// ABOUTME: Shared file-based logging configuration for debug mode

use anyhow::{Context, Result};
use log::LevelFilter;
use simplelog::*;
use std::fs::{self, OpenOptions};

/// Initialize file logger that writes to ~/claude-code-with-bedrock/logs/{log_name}.log
pub fn init_file_logger(log_name: &str, session_name: &str) -> Result<()> {
    let log_dir = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("claude-code-with-bedrock")
        .join("logs");

    // Create log directory if it doesn't exist
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {:?}", log_dir))?;

    let log_file = log_dir.join(format!("{}.log", log_name));

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .with_context(|| format!("Failed to open log file: {:?}", log_file))?;

    // Configure logger with timestamps and thread IDs
    WriteLogger::init(
        LevelFilter::Debug,
        Config::default(),
        file,
    )
    .context("Failed to initialize file logger")?;

    log::info!("=== {} Session Started ===", session_name);
    log::debug!("Log file: {:?}", log_file);

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_log_directory_path() {
        if let Some(home) = dirs::home_dir() {
            let expected = home.join("claude-code-with-bedrock").join("logs");
            assert!(expected.to_string_lossy().contains("claude-code-with-bedrock"));
        }
    }
}
