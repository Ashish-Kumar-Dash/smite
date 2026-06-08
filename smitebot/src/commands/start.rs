//! Campaign launch orchestration.
//!
//! Builds the Docker image, prepares the Nyx sharedir, spawns parallel
//! `afl-fuzz` processes in the background, and persists campaign state so
//! that `stop` and `status` can manage the running campaign later.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;

use crate::config::CampaignConfig;
use crate::state::{CampaignState, RunnerState, Status};

/// Command handler for `smitebot start`.
pub struct StartCommand;

/// CLI arguments for `smitebot start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
    /// Skip the Docker image build step.
    #[arg(long)]
    skip_build: bool,
    /// Skip the Nyx sharedir setup step.
    #[arg(long)]
    skip_setup: bool,
}

impl StartCommand {
    /// Launches a fuzzing campaign from the given configuration.
    pub fn execute(args: &StartArgs) -> bool {
        let config = match CampaignConfig::load(&args.path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        let image = config.image_tag();

        if !args.skip_build {
            log::info!("building Docker image {image}");
            if !build_image(&config, &image) {
                return false;
            }
        }

        if !args.skip_setup {
            log::info!("setting up Nyx sharedir at {}", config.sharedir.display());
            if !setup_nyx(&config, &image) {
                return false;
            }
        }

        let campaign_id = generate_campaign_id(&config);
        let Some(runs_dir) = CampaignState::runs_dir() else {
            log::error!("unable to determine home directory");
            return false;
        };
        let state_dir = runs_dir.join(&campaign_id);

        let state_path = state_dir.join("state.json");
        let git_hash = smite_git_hash(&config.smite_dir);
        let image_digest = docker_image_id(&image);

        let mut state = CampaignState {
            id: campaign_id,
            status: Status::Starting,
            target: config.target,
            scenario: config.scenario.clone(),
            image: image.clone(),
            image_digest,
            sharedir: config.sharedir.clone(),
            smite_git_hash: git_hash,
            start_time: now_iso8601(),
            stop_time: None,
            runners: Vec::new(),
        };

        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        log::info!("starting {} runners", config.runners);

        let mut runners = Vec::new();
        for id in 0..config.runners {
            let name = runner_name(id);
            match spawn_runner(&config, id, &name) {
                Ok(pid) => {
                    log::info!("spawned {name} (pid {pid})");
                    runners.push(RunnerState { id, name, pid });
                }
                Err(e) => {
                    log::error!("failed to spawn {name}: {e}");
                    state.status = Status::Failed;
                    state.runners = runners;
                    let _ = state.save(&state_path);
                    return false;
                }
            }
        }

        state.runners = runners;

        log::info!("waiting for runners to initialize");
        let started = verify_startup(&config.output_dir, &state.runners);
        if !started {
            log::error!("not all runners started within the timeout");
            state.status = Status::Failed;
            let _ = state.save(&state_path);
            return false;
        }

        state.status = Status::Running;
        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        log::info!("campaign {} is running", state.id);
        log::info!("state saved to {}", state_path.display());
        true
    }
}

/// Builds the Docker image for the campaign using `docker build`.
fn build_image(config: &CampaignConfig, image: &str) -> bool {
    let dockerfile = config
        .smite_dir
        .join("workloads")
        .join(config.target.to_string())
        .join("Dockerfile");

    if !dockerfile.exists() {
        log::error!("Dockerfile not found: {}", dockerfile.display());
        return false;
    }

    let status = Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg(image)
        .arg("--build-arg")
        .arg(format!("SCENARIO={}", config.scenario))
        .arg("-f")
        .arg(&dockerfile)
        .arg(&config.smite_dir)
        .status();

    match status {
        Ok(s) if s.success() => {
            log::info!("built {image}");
            true
        }
        Ok(s) => {
            log::error!("docker build failed with {s}");
            false
        }
        Err(e) => {
            log::error!("failed to run docker build: {e}");
            false
        }
    }
}

/// Runs `scripts/setup-nyx.sh` to prepare the Nyx sharedir.
fn setup_nyx(config: &CampaignConfig, image: &str) -> bool {
    let script = config.smite_dir.join("scripts").join("setup-nyx.sh");
    if !script.exists() {
        log::error!("setup-nyx.sh not found: {}", script.display());
        return false;
    }

    let status = Command::new(&script)
        .arg(&config.sharedir)
        .arg(image)
        .arg(&config.aflpp_path)
        .status();

    match status {
        Ok(s) if s.success() => {
            log::info!("Nyx sharedir ready at {}", config.sharedir.display());
            true
        }
        Ok(s) => {
            log::error!("setup-nyx.sh failed with {s}");
            false
        }
        Err(e) => {
            log::error!("failed to run setup-nyx.sh: {e}");
            false
        }
    }
}

/// Spawns a single `afl-fuzz` process in its own process group and returns its PID.
///
/// The child is intentionally orphaned so the campaign outlives the `smitebot`
/// process. The `stop` command uses the persisted PID to terminate it later.
fn spawn_runner(config: &CampaignConfig, id: u16, name: &str) -> std::io::Result<u32> {
    let afl_fuzz = config.aflpp_path.join("afl-fuzz");

    let mut cmd = Command::new(&afl_fuzz);
    cmd.arg("-X");
    cmd.arg("-i").arg(&config.seed_dir);
    cmd.arg("-o").arg(&config.output_dir);

    if id == 0 {
        cmd.arg("-M").arg(name);
    } else {
        cmd.arg("-S").arg(name);
    }

    for flag in &config.afl_flags {
        cmd.arg(flag);
    }

    cmd.arg("--").arg(&config.sharedir);

    // Apply user specified AFL++ environment variables.
    for (key, val) in &config.afl_env {
        cmd.env(key, val);
    }

    // Auto inject IR mutator env vars for IR scenarios.
    if config.scenario.starts_with("ir") {
        let mutator_lib = config
            .smite_dir
            .join("target")
            .join("release")
            .join("libsmite_ir_mutator.so");
        cmd.env("AFL_CUSTOM_MUTATOR_LIBRARY", &mutator_lib);
        cmd.env("AFL_CUSTOM_MUTATOR_ONLY", "1");
        cmd.env("AFL_FRAMESHIFT_DISABLE", "1");
        cmd.env("AFL_DISABLE_TRIM", "1");
    }

    // Place each runner in its own process group so `stop` can killpg the whole
    // subtree without affecting other runners.
    cmd.process_group(0);

    let child = cmd.spawn()?;
    let pid = child.id();

    // Intentionally drop the Child handle. The afl-fuzz process continues
    // running as an orphan, managed later via its PID in state.json.
    drop(child);

    Ok(pid)
}

/// Returns the AFL++ runner name for the given index.
fn runner_name(id: u16) -> String {
    if id == 0 {
        "main".to_string()
    } else {
        format!("runner{id:03}")
    }
}

/// Polls for `fuzzer_stats` files to confirm all runners have started.
///
/// AFL++ creates `<output_dir>/<runner_name>/fuzzer_stats` once fuzzing begins.
fn verify_startup(output_dir: &Path, runners: &[RunnerState]) -> bool {
    let timeout = Duration::from_mins(5);
    let poll_interval = Duration::from_secs(5);
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let all_started = runners
            .iter()
            .all(|r| output_dir.join(&r.name).join("fuzzer_stats").exists());

        if all_started {
            return true;
        }

        thread::sleep(poll_interval);
    }

    // Log which runners failed to start.
    for runner in runners {
        let stats = output_dir.join(&runner.name).join("fuzzer_stats");
        if !stats.exists() {
            log::error!(
                "runner {} (pid {}) did not produce fuzzer_stats",
                runner.name,
                runner.pid
            );
        }
    }

    false
}

/// Generates a campaign ID from the target, scenario, and current time.
fn generate_campaign_id(config: &CampaignConfig) -> String {
    let timestamp = now_compact();
    format!("{}-{}-{timestamp}", config.target, config.scenario)
}

/// Returns the smite repository git hash, or `None` if not a git repo.
fn smite_git_hash(smite_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(smite_dir)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the Docker image ID hash for a locally built image.
fn docker_image_id(image: &str) -> Option<String> {
    let output = Command::new("docker")
        .arg("inspect")
        .arg("--format={{.Id}}")
        .arg(image)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the current time as an ISO 8601 string.
fn now_iso8601() -> String {
    let output = Command::new("date").arg("--iso-8601=seconds").output().ok();

    match output {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

/// Returns a compact timestamp for campaign ID generation.
fn now_compact() -> String {
    let output = Command::new("date").arg("+%Y%m%dT%H%M%S").output().ok();

    match output {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn runner_name_main_for_zero() {
        assert_eq!(runner_name(0), "main");
    }

    #[test]
    fn runner_name_padded_for_secondary() {
        assert_eq!(runner_name(1), "runner001");
        assert_eq!(runner_name(12), "runner012");
        assert_eq!(runner_name(100), "runner100");
    }

    #[test]
    fn generate_campaign_id_contains_target_and_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "/home/user/AFLplusplus"
smite_dir = "."
runners = 8
seed_dir = "/tmp/seeds"
output_dir = "/tmp/out"
sharedir = "/tmp/nyx"
"#,
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let id = generate_campaign_id(&config);

        assert!(
            id.starts_with("lnd-encrypted_bytes-"),
            "id should start with target-scenario: {id}"
        );
    }

    #[test]
    fn verify_startup_detects_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        let runners = vec![
            RunnerState {
                id: 0,
                name: "main".to_string(),
                pid: 100,
            },
            RunnerState {
                id: 1,
                name: "runner001".to_string(),
                pid: 101,
            },
        ];

        for runner in &runners {
            let runner_dir = dir.path().join(&runner.name);
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(runner_dir.join("fuzzer_stats"), "start_time: 0\n").unwrap();
        }

        assert!(verify_startup(dir.path(), &runners));
    }
}
