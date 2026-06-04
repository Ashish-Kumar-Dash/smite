//! Campaign configuration validation.

use std::path::PathBuf;

use clap::Args;

use crate::config::CampaignConfig;

/// Command handler for `smitebot config`.
pub struct ConfigCommand;

/// CLI arguments for `smitebot config`.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
}

impl ConfigCommand {
    /// Validates a campaign configuration file and reports the result.
    pub fn execute(args: &ConfigArgs) -> bool {
        match CampaignConfig::load(&args.path) {
            Ok(config) => {
                log::info!("target:     {}", config.target);
                log::info!("scenario:   {}", config.scenario);
                log::info!("aflpp_path: {}", config.aflpp_path.display());
                log::info!("smite_dir:  {}", config.smite_dir.display());
                log::info!("runners:    {}", config.runners);
                log::info!("seed_dir:   {}", config.seed_dir.display());
                log::info!("output_dir: {}", config.output_dir.display());
                log::info!("sharedir:   {}", config.sharedir.display());
                log::info!("image:      {}", config.image_tag());
                true
            }
            Err(e) => {
                log::error!("{e}");
                false
            }
        }
    }
}
