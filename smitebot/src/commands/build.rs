//! Docker image builds for Smite workloads.
//! The command keeps Docker's output visible so rebuild failures are easy to debug.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use clap::Args;

use crate::config::{CampaignConfig, Target};

/// Command handler for `smitebot build`.
pub struct BuildCommand;

/// CLI arguments for `smitebot build`.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Campaign configuration file. When provided, `target`, `scenario`, and
    /// `smite_dir` are read from the config instead of requiring CLI flags.
    config: Option<PathBuf>,
    /// Target implementation to build.
    #[arg(long)]
    target: Option<Target>,
    /// Scenario binary selected by the workload Dockerfile.
    #[arg(long)]
    scenario: Option<String>,
    /// Build the coverage-instrumented Docker image.
    #[arg(long)]
    coverage: bool,
    /// Override the Docker image tag.
    #[arg(long)]
    image: Option<String>,
    /// Path to smite repository root.
    #[arg(long, default_value = ".")]
    smite_dir: PathBuf,
    /// Pass --no-cache to docker build.
    #[arg(long)]
    no_cache: bool,
}

/// Fully resolved Docker build inputs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuildInputs {
    /// Docker image tag to produce.
    pub(crate) image: String,
    /// Workload Dockerfile selected from `--target` and `--coverage`.
    pub(crate) dockerfile: PathBuf,
    /// Smite repository root used as the Docker build context.
    pub(crate) smite_dir: PathBuf,
    /// Scenario passed to Docker as `--build-arg SCENARIO=...`.
    pub(crate) scenario: String,
    /// Whether Docker should rebuild without using its layer cache.
    pub(crate) no_cache: bool,
}

impl BuildInputs {
    /// Resolves Docker build inputs from a campaign configuration.
    pub(crate) fn from_config(config: &CampaignConfig, image: &str) -> Self {
        Self {
            image: image.to_string(),
            dockerfile: config
                .smite_dir
                .join("workloads")
                .join(config.target.to_string())
                .join("Dockerfile"),
            smite_dir: config.smite_dir.clone(),
            scenario: config.scenario.clone(),
            no_cache: false,
        }
    }

    /// Resolves Docker build inputs from CLI arguments.
    fn from_resolved(target: Target, scenario: &str, smite_dir: &Path, args: &BuildArgs) -> Self {
        let dockerfile_name = if args.coverage {
            "Dockerfile.coverage"
        } else {
            "Dockerfile"
        };

        Self {
            image: args
                .image
                .clone()
                .unwrap_or_else(|| default_workload_image_tag(target, scenario, args.coverage)),
            dockerfile: smite_dir
                .join("workloads")
                .join(target.to_string())
                .join(dockerfile_name),
            smite_dir: smite_dir.to_path_buf(),
            scenario: scenario.to_string(),
            no_cache: args.no_cache,
        }
    }
}

impl BuildCommand {
    /// Builds the requested Smite Docker image and returns whether Docker succeeded.
    pub fn execute(args: &BuildArgs) -> bool {
        let config = args.config.as_ref().map(|p| CampaignConfig::load(p));
        if let Some(Err(e)) = &config {
            log::error!("{e}");
            return false;
        }
        let config = config.map(|r| r.unwrap());

        let target = match (&args.target, &config) {
            (Some(t), _) => *t,
            (None, Some(c)) => c.target,
            (None, None) => {
                log::error!("--target is required (or provide a campaign config file)");
                return false;
            }
        };
        let scenario = match (&args.scenario, &config) {
            (Some(s), _) => s.clone(),
            (None, Some(c)) => c.scenario.clone(),
            (None, None) => {
                log::error!("--scenario is required (or provide a campaign config file)");
                return false;
            }
        };
        let smite_dir = match &config {
            Some(c) => c.smite_dir.clone(),
            None => args.smite_dir.clone(),
        };

        let inputs = BuildInputs::from_resolved(target, &scenario, &smite_dir, args);
        log::info!(
            "building {} with {}",
            inputs.image,
            inputs.dockerfile.display()
        );
        run_build(&inputs)
    }
}

/// Checks that the Dockerfile exists, runs `docker build`, and reports success.
///
/// Shared by `smitebot build` and `smitebot start`.
pub(crate) fn run_build(inputs: &BuildInputs) -> bool {
    if !inputs.dockerfile.exists() {
        log::error!("Dockerfile not found: {}", inputs.dockerfile.display());
        return false;
    }

    let status = match run_docker_build(inputs) {
        Ok(status) => status,
        Err(e) => {
            log::error!("failed to run docker build: {e}");
            return false;
        }
    };

    if !status.success() {
        log::error!("docker build failed with {status}");
        return false;
    }

    log::info!("built {}", inputs.image);
    true
}

/// Returns the default image tag used by Smite's manual Docker build flow.
fn default_workload_image_tag(target: Target, scenario: &str, coverage: bool) -> String {
    let suffix = if coverage { "-coverage" } else { "" };
    format!("smite-{target}-{scenario}{suffix}")
}

/// Runs `docker build`, streaming stdout/stderr directly to the terminal.
fn run_docker_build(inputs: &BuildInputs) -> std::io::Result<ExitStatus> {
    let mut command = Command::new("docker");
    command.arg("build");
    if inputs.no_cache {
        command.arg("--no-cache");
    }
    command
        .arg("-t")
        .arg(&inputs.image)
        .arg("--build-arg")
        .arg(format!("SCENARIO={}", inputs.scenario))
        .arg("-f")
        .arg(&inputs.dockerfile)
        .arg(&inputs.smite_dir);

    command.status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_build_args(target: Target, scenario: &str) -> BuildArgs {
        BuildArgs {
            config: None,
            target: Some(target),
            scenario: Some(scenario.to_string()),
            coverage: false,
            image: None,
            smite_dir: PathBuf::from("/repo/smite"),
            no_cache: false,
        }
    }

    fn resolved_inputs(args: &BuildArgs) -> BuildInputs {
        BuildInputs::from_resolved(
            args.target.unwrap(),
            args.scenario.as_deref().unwrap(),
            &args.smite_dir,
            args,
        )
    }

    #[test]
    fn default_workload_image_tag_matches_smite_convention() {
        assert_eq!(
            default_workload_image_tag(Target::Lnd, "encrypted_bytes", false),
            "smite-lnd-encrypted_bytes"
        );
        assert_eq!(
            default_workload_image_tag(Target::Cln, "noise", true),
            "smite-cln-noise-coverage"
        );
    }

    #[test]
    fn build_inputs_use_normal_dockerfile_by_default() {
        let args = sample_build_args(Target::Ldk, "init");
        let inputs = resolved_inputs(&args);

        assert_eq!(inputs.image, "smite-ldk-init");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/ldk/Dockerfile")
        );
        assert_eq!(inputs.smite_dir, Path::new("/repo/smite"));
        assert_eq!(inputs.scenario, "init");
        assert!(!inputs.no_cache);
    }

    #[test]
    fn build_inputs_select_expected_dockerfile_for_each_target() {
        let cases = [
            (Target::Lnd, "/repo/smite/workloads/lnd/Dockerfile"),
            (Target::Cln, "/repo/smite/workloads/cln/Dockerfile"),
            (Target::Ldk, "/repo/smite/workloads/ldk/Dockerfile"),
            (Target::Eclair, "/repo/smite/workloads/eclair/Dockerfile"),
        ];

        for (target, expected_dockerfile) in cases {
            let args = sample_build_args(target, "noise");
            let inputs = resolved_inputs(&args);

            assert_eq!(inputs.dockerfile, Path::new(expected_dockerfile));
        }
    }

    #[test]
    fn build_inputs_support_coverage_and_custom_image() {
        let mut args = sample_build_args(Target::Eclair, "encrypted_bytes");
        args.coverage = true;
        args.image = Some("local/eclair-eb:debug".to_string());
        args.no_cache = true;

        let inputs = resolved_inputs(&args);

        assert_eq!(inputs.image, "local/eclair-eb:debug");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/eclair/Dockerfile.coverage")
        );
        assert!(inputs.no_cache);
    }

    #[test]
    fn build_inputs_use_default_coverage_image_when_not_overridden() {
        let mut args = sample_build_args(Target::Cln, "noise");
        args.coverage = true;

        let inputs = resolved_inputs(&args);

        assert_eq!(inputs.image, "smite-cln-noise-coverage");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/cln/Dockerfile.coverage")
        );
    }

    #[test]
    fn build_inputs_preserve_custom_smite_dir() {
        let mut args = sample_build_args(Target::Lnd, "encrypted_bytes");
        args.smite_dir = PathBuf::from("/tmp/local-smite");

        let inputs = resolved_inputs(&args);

        assert_eq!(inputs.smite_dir, Path::new("/tmp/local-smite"));
        assert_eq!(
            inputs.dockerfile,
            Path::new("/tmp/local-smite/workloads/lnd/Dockerfile")
        );
    }
}
