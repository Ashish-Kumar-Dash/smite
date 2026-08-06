//! Corpus management: merge runner queues and minimize with `afl-cmin`.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Subcommand};

use crate::state::CampaignState;
use crate::utils::{find_in_path, is_executable};

/// Command handler for `smitebot corpus`.
pub struct CorpusCommand;

/// CLI arguments for `smitebot corpus`.
#[derive(Debug, Args)]
pub struct CorpusArgs {
    /// Corpus subcommand to run.
    #[command(subcommand)]
    pub command: CorpusSubcommand,
}

/// Subcommands for corpus management.
#[derive(Debug, Subcommand)]
pub enum CorpusSubcommand {
    /// Collect and deduplicate inputs from campaign runner queues.
    Merge(MergeArgs),
    /// Remove corpus inputs that don't add new coverage using `afl-cmin`.
    Minimize(MinimizeArgs),
}

/// CLI arguments for `smitebot corpus merge`.
#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Campaign IDs whose runner queues to merge (directories under `~/.smitebot/runs`).
    #[arg(required = true)]
    campaign_ids: Vec<String>,
    /// Output directory for the merged corpus.
    #[arg(short = 'o', long)]
    output: PathBuf,
}

/// CLI arguments for `smitebot corpus minimize`.
#[derive(Debug, Args)]
pub struct MinimizeArgs {
    /// Campaign ID whose sharedir and `aflpp_path` to use.
    campaign_id: String,
    /// Input directory or glob pattern passed to `afl-cmin -i`
    /// (default: `<output_dir>/*/queue/`).
    #[arg(short = 'i', long)]
    input: Option<String>,
    /// Output directory (default: `~/.smitebot/runs/<id>/corpus-min/`).
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
    /// Path to the AFL++ source tree, overriding the value stored in state.json.
    #[arg(long)]
    aflpp_path: Option<PathBuf>,
}

impl CorpusCommand {
    /// Dispatches to the requested corpus subcommand.
    pub fn execute(args: &CorpusArgs) -> bool {
        match &args.command {
            CorpusSubcommand::Merge(a) => execute_merge(a),
            CorpusSubcommand::Minimize(a) => execute_minimize(a),
        }
    }
}

/// Loads the campaign state for `campaign_id`, logging a not-found hint on error.
fn load_campaign(runs_dir: &Path, campaign_id: &str) -> Option<CampaignState> {
    let state_path = runs_dir.join(campaign_id).join("state.json");
    match CampaignState::load(&state_path) {
        Ok(state) => Some(state),
        Err(e) => {
            log::error!("{e}");
            log::error!(
                "campaign '{campaign_id}' not found; list campaigns with: ls {}",
                runs_dir.display()
            );
            None
        }
    }
}

/// Loads every campaign's state, then merges their runner queues into `output`.
///
/// All states are loaded before any file is written, so a bad campaign ID fails
/// before the output directory is touched rather than leaving a partial merge.
fn execute_merge(args: &MergeArgs) -> bool {
    let Some(runs_dir) = CampaignState::runs_dir() else {
        log::error!("unable to determine home directory");
        return false;
    };

    let mut states = Vec::with_capacity(args.campaign_ids.len());
    for campaign_id in &args.campaign_ids {
        let Some(state) = load_campaign(&runs_dir, campaign_id) else {
            return false;
        };
        states.push(state);
    }

    if output_dir_occupied(&args.output) {
        return false;
    }

    if let Err(e) = fs::create_dir_all(&args.output) {
        log::error!(
            "failed to create output directory {}: {e}",
            args.output.display()
        );
        return false;
    }

    let Some((total_in, total_out)) = merge_states(&states, &args.output) else {
        log::error!(
            "merge failed partway; partial results may remain in {} — remove it before retrying",
            args.output.display()
        );
        return false;
    };

    log::info!(
        "merged {total_in} files across {} campaign(s) → {total_out} unique files written to {}",
        args.campaign_ids.len(),
        args.output.display()
    );
    true
}

/// Copies unique queue files from every runner of every state into `output`.
///
/// Deduplicates by a hash of the file contents rather than the contents
/// themselves, so a large corpus only costs 8 bytes per unique entry in memory.
/// A 64-bit hash collision (silently dropping a distinct input) has probability
/// ~n²/2⁶⁵, negligible for realistic corpus sizes. Returns `(files_read,
/// files_written)`, or `None` if any read/write failed (logged at the failure
/// site).
fn merge_states(states: &[CampaignState], output: &Path) -> Option<(usize, usize)> {
    let mut seen: HashSet<u64> = HashSet::new();
    let mut total_in = 0usize;
    let mut total_out = 0usize;

    for state in states {
        for runner in &state.runners {
            let queue_dir = state.output_dir.join(runner.name()).join("queue");
            if !queue_dir.exists() {
                log::warn!("queue directory missing, skipping: {}", queue_dir.display());
                continue;
            }

            let entries = match fs::read_dir(&queue_dir) {
                Ok(e) => e,
                Err(e) => {
                    log::error!("failed to read {}: {e}", queue_dir.display());
                    return None;
                }
            };

            for entry in entries {
                let path = match entry {
                    Ok(e) => e.path(),
                    Err(e) => {
                        log::error!("failed to read an entry in {}: {e}", queue_dir.display());
                        return None;
                    }
                };
                if !path.is_file() {
                    continue;
                }
                let contents = match fs::read(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("failed to read {}: {e}", path.display());
                        return None;
                    }
                };
                total_in += 1;
                if seen.insert(content_hash(&contents)) {
                    let dest = output.join(format!("{total_out:06}"));
                    // `contents` is already in hand from the dedup read, so write
                    // it out directly rather than re-reading via fs::copy.
                    if let Err(e) = fs::write(&dest, &contents) {
                        log::error!("failed to write {}: {e}", dest.display());
                        return None;
                    }
                    total_out += 1;
                }
            }
        }
    }

    Some((total_in, total_out))
}

/// Returns a 64-bit hash of `bytes` for content-based deduplication.
fn content_hash(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

/// Runs `afl-cmin -X` against the campaign's corpus to remove inputs that
/// don't contribute new coverage.
fn execute_minimize(args: &MinimizeArgs) -> bool {
    let Some(runs_dir) = CampaignState::runs_dir() else {
        log::error!("unable to determine home directory");
        return false;
    };

    let Some(state) = load_campaign(&runs_dir, &args.campaign_id) else {
        return false;
    };

    // The --aflpp-path flag overrides the path recorded at campaign start, for when
    // the AFL++ checkout has since moved.
    let aflpp = args.aflpp_path.as_deref().or(state.aflpp_path.as_deref());
    let Some(afl_cmin) = find_afl_cmin(aflpp) else {
        log::error!("afl-cmin not found; pass --aflpp-path <path> or add AFL++ to PATH");
        return false;
    };

    // Default: pass the output_dir glob so afl-cmin collects all runner queues
    // in one pass, matching morehouse's manual workflow:
    // afl-cmin -i "output_dir/*/queue/" -o minimized/ -X sharedir
    let input = args
        .input
        .clone()
        .unwrap_or_else(|| format!("{}/*/queue/", state.output_dir.display()));

    let output = args
        .output
        .clone()
        .unwrap_or_else(|| runs_dir.join(&args.campaign_id).join("corpus-min"));

    // Fail before booting Nyx if the output already holds a corpus. afl-cmin
    // guards this too, but it first deletes any `id:*` files in the directory.
    if output_dir_occupied(&output) {
        return false;
    }

    log::info!("running afl-cmin on {input}");
    log::info!("output: {}", output.display());

    let mut cmd = Command::new(&afl_cmin);
    cmd.arg("-i")
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .arg("-X")
        .arg(&state.sharedir);

    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            log::error!("failed to run {}: {e}", afl_cmin.display());
            return false;
        }
    };

    if !status.success() {
        log::error!("afl-cmin failed with {status}");
        return false;
    }

    log::info!("minimized corpus written to {}", output.display());
    true
}

/// Reports (with an error log) whether `output` already contains files.
///
/// Both subcommands refuse a populated output directory so an existing corpus is
/// never mixed into or overwritten. A missing directory counts as unoccupied (it
/// will be created); any other `read_dir` error is treated as occupied so we
/// never write over an unknown state.
fn output_dir_occupied(output: &Path) -> bool {
    match output.read_dir() {
        Ok(mut entries) => {
            if entries.next().is_some() {
                log::error!(
                    "output directory {} already contains files; choose a new directory or remove it first",
                    output.display()
                );
                true
            } else {
                false
            }
        }
        // A missing directory is the common, expected case — it will be created.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        // Any other error (e.g. a permission problem, or a file where a directory
        // was expected) leaves occupancy unknown; refuse rather than risk writing
        // over something.
        Err(e) => {
            log::error!("cannot inspect output directory {}: {e}", output.display());
            true
        }
    }
}

/// Locates an executable `afl-cmin`: checks `aflpp_path` first, falls back to
/// searching `$PATH`.
fn find_afl_cmin(aflpp_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = aflpp_path {
        let candidate = path.join("afl-cmin");
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    find_in_path("afl-cmin")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::config::Target;
    use crate::state::{RunnerState, Status};

    /// Builds a stopped campaign state whose runners read from `output_dir`.
    fn sample_state(output_dir: PathBuf, runners: u16) -> CampaignState {
        CampaignState {
            id: "lnd-enc-1000".to_string(),
            status: Status::Stopped,
            target: Target::Lnd,
            scenario: "encrypted_bytes".to_string(),
            image: "smite-lnd-encrypted_bytes".to_string(),
            image_digest: "sha256:abc".to_string(),
            output_dir,
            sharedir: PathBuf::from("/tmp/smite-nyx"),
            smite_git_hash: "deadbeef".to_string(),
            start_time: 1_000_000,
            stop_time: Some(1_001_000),
            tmux_session: "lnd-enc-1000".to_string(),
            runners: (0..runners)
                .map(|id| RunnerState { id, pid: None })
                .collect(),
            aflpp_path: None,
        }
    }

    /// Writes `files` (name, contents) into `output_dir/<runner>/queue/`.
    fn write_queue(output_dir: &Path, runner: u16, files: &[(&str, &str)]) {
        let queue = output_dir.join(runner.to_string()).join("queue");
        fs::create_dir_all(&queue).unwrap();
        for (name, contents) in files {
            fs::write(queue.join(name), contents).unwrap();
        }
    }

    /// Returns the contents of every file directly in `dir`, sorted.
    fn dir_contents_sorted(dir: &Path) -> Vec<String> {
        let mut contents: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        contents.sort();
        contents
    }

    #[test]
    fn merge_states_deduplicates_by_content_across_runners() {
        let dir = tempdir().unwrap();
        let output_dir = dir.path().join("out");
        // Runner 1's "id:9" duplicates runner 0's "aaa" under a different name,
        // so dedup must key on content, not filename. Four inputs, three distinct.
        write_queue(&output_dir, 0, &[("id:0", "aaa"), ("id:1", "bbb")]);
        write_queue(&output_dir, 1, &[("id:9", "aaa"), ("id:1", "ccc")]);
        let out = dir.path().join("corpus");
        fs::create_dir_all(&out).unwrap();

        let (total_in, total_out) = merge_states(&[sample_state(output_dir, 2)], &out).unwrap();

        assert_eq!(total_in, 4);
        assert_eq!(total_out, 3);
        assert_eq!(dir_contents_sorted(&out), ["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn merge_states_skips_runner_without_queue_dir() {
        let dir = tempdir().unwrap();
        let output_dir = dir.path().join("out");
        // Only runner 0 has a queue; runner 1's directory is absent.
        write_queue(&output_dir, 0, &[("id:0", "x")]);
        let out = dir.path().join("corpus");
        fs::create_dir_all(&out).unwrap();

        let (total_in, total_out) = merge_states(&[sample_state(output_dir, 2)], &out).unwrap();

        assert_eq!(total_in, 1);
        assert_eq!(total_out, 1);
        assert_eq!(dir_contents_sorted(&out), ["x"]);
    }

    #[test]
    fn merge_states_deduplicates_across_campaigns() {
        let dir = tempdir().unwrap();
        let out_a = dir.path().join("a");
        let out_b = dir.path().join("b");
        // "shared" appears in both campaigns under different names, so it must
        // dedup on content across the state boundary.
        write_queue(&out_a, 0, &[("id:2", "shared")]);
        write_queue(&out_b, 0, &[("id:0", "shared"), ("id:1", "unique")]);
        let out = dir.path().join("corpus");
        fs::create_dir_all(&out).unwrap();

        let states = [sample_state(out_a, 1), sample_state(out_b, 1)];
        let (total_in, total_out) = merge_states(&states, &out).unwrap();

        assert_eq!(total_in, 3);
        assert_eq!(total_out, 2);
        assert_eq!(dir_contents_sorted(&out), ["shared", "unique"]);
    }

    #[test]
    fn output_dir_occupied_detects_existing_files() {
        let dir = tempdir().unwrap();
        // Absent directory is not occupied.
        assert!(!output_dir_occupied(&dir.path().join("missing")));

        // Empty directory is not occupied.
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(!output_dir_occupied(&empty));

        // A directory holding a corpus file is occupied.
        fs::write(empty.join("000000"), b"x").unwrap();
        assert!(output_dir_occupied(&empty));
    }

    #[test]
    fn find_afl_cmin_prefers_executable_in_aflpp_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let cmin = dir.path().join("afl-cmin");
        fs::write(&cmin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&cmin, fs::Permissions::from_mode(0o755)).unwrap();

        let result = find_afl_cmin(Some(dir.path()));
        assert_eq!(result, Some(cmin));
    }

    #[test]
    fn find_afl_cmin_ignores_non_executable_candidate() {
        let dir = tempdir().unwrap();
        // A non-executable file at aflpp_path is not a runnable afl-cmin, so the
        // aflpp_path branch is skipped (the result then comes from $PATH, if any).
        fs::write(dir.path().join("afl-cmin"), "not executable").unwrap();

        assert_ne!(
            find_afl_cmin(Some(dir.path())),
            Some(dir.path().join("afl-cmin"))
        );
    }
}
