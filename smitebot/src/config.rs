//! Campaign configuration file parsing and validation.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::Deserialize;

/// A parsed and validated smitebot campaign configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignConfig {
    /// Workload target implementation to fuzz.
    pub target: Target,
    /// Scenario binary selected by the workload Dockerfile.
    pub scenario: String,
    /// Path to AFL++ source tree.
    pub aflpp_path: PathBuf,
    /// Path to the smite repository root.
    pub smite_dir: PathBuf,
    /// Number of parallel AFL++ instances to launch.
    pub runners: u16,
    /// Directory containing seed inputs for the fuzzing corpus.
    pub seed_dir: PathBuf,
    /// AFL++ output directory for findings and stats.
    pub output_dir: PathBuf,
    /// Nyx shared directory created by `setup-nyx.sh`.
    pub sharedir: PathBuf,
    /// Docker image tag override; derived from target and scenario when absent.
    pub image: Option<String>,
    /// Extra environment variables passed to AFL++ instances.
    #[serde(default)]
    pub afl_env: HashMap<String, String>,
    /// Extra CLI flags appended to the `afl-fuzz` command.
    #[serde(default)]
    pub afl_flags: Vec<String>,
}

/// Lightning Network implementation to target.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    /// Lightning Network Daemon.
    Lnd,
    /// Core Lightning.
    Cln,
    /// LDK Node.
    Ldk,
    /// Eclair.
    Eclair,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lnd => write!(f, "lnd"),
            Self::Cln => write!(f, "cln"),
            Self::Ldk => write!(f, "ldk"),
            Self::Eclair => write!(f, "eclair"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("runners must be at least 1")]
    InvalidRunners,
    #[error("scenario must not be empty")]
    EmptyScenario,
    #[error("image must not be empty when specified")]
    EmptyImage,
}

impl CampaignConfig {
    /// Loads and validates a campaign configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Returns the Docker image tag, using the Smite convention as the default.
    #[must_use]
    pub fn image_tag(&self) -> String {
        self.image
            .clone()
            .unwrap_or_else(|| format!("smite-{}-{}", self.target, self.scenario))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.runners == 0 {
            return Err(ConfigError::InvalidRunners);
        }
        if self.scenario.is_empty() {
            return Err(ConfigError::EmptyScenario);
        }
        if self.image.as_ref().is_some_and(String::is_empty) {
            return Err(ConfigError::EmptyImage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("campaign.toml");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    const VALID_CONFIG: &str = r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "/home/user/AFLplusplus"
smite_dir = "."
runners = 8
seed_dir = "/tmp/smite-seeds"
output_dir = "/tmp/smite-out"
sharedir = "/tmp/smite-nyx"
"#;

    #[test]
    fn load_parses_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), VALID_CONFIG);

        let config = CampaignConfig::load(&path).unwrap();

        assert_eq!(config.target, Target::Lnd);
        assert_eq!(config.scenario, "encrypted_bytes");
        assert_eq!(config.aflpp_path, PathBuf::from("/home/user/AFLplusplus"));
        assert_eq!(config.smite_dir, PathBuf::from("."));
        assert_eq!(config.runners, 8);
        assert_eq!(config.seed_dir, PathBuf::from("/tmp/smite-seeds"));
        assert_eq!(config.output_dir, PathBuf::from("/tmp/smite-out"));
        assert_eq!(config.sharedir, PathBuf::from("/tmp/smite-nyx"));
        assert!(config.image.is_none());
    }

    #[test]
    fn load_accepts_optional_image_override() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!("{VALID_CONFIG}image = \"custom:tag\"\n");
        let path = write_config(dir.path(), &content);

        let config = CampaignConfig::load(&path).unwrap();

        assert_eq!(config.image.as_deref(), Some("custom:tag"));
    }

    #[test]
    fn load_rejects_missing_required_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "target = \"lnd\"\nscenario = \"noise\"\n");

        let err = CampaignConfig::load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_rejects_invalid_target() {
        let dir = tempfile::tempdir().unwrap();
        let content = VALID_CONFIG.replace("\"lnd\"", "\"btcd\"");
        let path = write_config(dir.path(), &content);

        let err = CampaignConfig::load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_rejects_zero_runners() {
        let dir = tempfile::tempdir().unwrap();
        let content = VALID_CONFIG.replace("runners = 8", "runners = 0");
        let path = write_config(dir.path(), &content);

        let err = CampaignConfig::load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRunners));
    }

    #[test]
    fn load_rejects_empty_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let content = VALID_CONFIG.replace(r#"scenario = "encrypted_bytes""#, r#"scenario = """#);
        let path = write_config(dir.path(), &content);

        let err = CampaignConfig::load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyScenario));
    }

    #[test]
    fn load_reports_missing_file() {
        let err = CampaignConfig::load(Path::new("/no/such/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    #[test]
    fn image_tag_derives_default_from_target_and_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), VALID_CONFIG);

        let config = CampaignConfig::load(&path).unwrap();

        assert_eq!(config.image_tag(), "smite-lnd-encrypted_bytes");
    }

    #[test]
    fn image_tag_uses_override_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!("{VALID_CONFIG}image = \"my-image:latest\"\n");
        let path = write_config(dir.path(), &content);

        let config = CampaignConfig::load(&path).unwrap();

        assert_eq!(config.image_tag(), "my-image:latest");
    }

    #[test]
    fn target_display_matches_config_values() {
        assert_eq!(Target::Lnd.to_string(), "lnd");
        assert_eq!(Target::Cln.to_string(), "cln");
        assert_eq!(Target::Ldk.to_string(), "ldk");
        assert_eq!(Target::Eclair.to_string(), "eclair");
    }

    #[test]
    fn load_accepts_all_targets() {
        for target in ["lnd", "cln", "ldk", "eclair"] {
            let dir = tempfile::tempdir().unwrap();
            let content = VALID_CONFIG.replace("\"lnd\"", &format!("\"{target}\""));
            let path = write_config(dir.path(), &content);

            let config = CampaignConfig::load(&path).unwrap();
            assert_eq!(config.target.to_string(), target);
        }
    }

    #[test]
    fn load_rejects_empty_image() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!("{VALID_CONFIG}image = \"\"\n");
        let path = write_config(dir.path(), &content);

        let err = CampaignConfig::load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyImage));
    }

    #[test]
    fn load_defaults_afl_env_and_flags_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), VALID_CONFIG);

        let config = CampaignConfig::load(&path).unwrap();

        assert!(config.afl_env.is_empty());
        assert!(config.afl_flags.is_empty());
    }

    #[test]
    fn load_parses_afl_env_and_flags() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!(
            "{VALID_CONFIG}\nafl_flags = [\"-t\", \"1000+\"]\n\n[afl_env]\nAFL_KEEP_TIMEOUTS = \"1\"\n"
        );
        let path = write_config(dir.path(), &content);

        let config = CampaignConfig::load(&path).unwrap();

        assert_eq!(config.afl_env.get("AFL_KEEP_TIMEOUTS").unwrap(), "1");
        assert_eq!(config.afl_flags, vec!["-t", "1000+"]);
    }

    #[test]
    fn load_rejects_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!("{VALID_CONFIG}extra_field = true\n");
        let path = write_config(dir.path(), &content);

        let err = CampaignConfig::load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn config_error_messages_include_file_path() {
        let err = CampaignConfig::load(Path::new("/tmp/bad.toml")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/tmp/bad.toml"),
            "error should include path: {msg}"
        );
    }
}
