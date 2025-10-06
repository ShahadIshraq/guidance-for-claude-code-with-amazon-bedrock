// ABOUTME: Token retrieval via credential-process subprocess

use anyhow::{Context, Result};
use log::{info, warn};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

pub fn get_token_via_credential_process() -> Result<Option<String>> {
    info!("Getting token via credential-process...");

    // Path to credential process
    let credential_process = if cfg!(windows) {
        dirs::home_dir()
            .context("Failed to get home directory")?
            .join("claude-code-with-bedrock")
            .join("credential-process.exe")
    } else {
        dirs::home_dir()
            .context("Failed to get home directory")?
            .join("claude-code-with-bedrock")
            .join("credential-process")
    };

    // Check if credential process exists
    if !credential_process.exists() {
        warn!("Credential process not found at {:?}", credential_process);
        return Ok(None);
    }

    // Run credential process with --get-monitoring-token flag and 5-minute timeout
    let mut child = Command::new(&credential_process)
        .arg("--get-monitoring-token")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn credential process")?;

    // Wait for up to 5 minutes (300 seconds) - matches Python timeout
    let timeout = Duration::from_secs(300);
    match child.wait_timeout(timeout)? {
        Some(status) => {
            if status.success() {
                let output = child.wait_with_output()?;
                let token = String::from_utf8(output.stdout)
                    .context("Invalid UTF-8 in credential process output")?
                    .trim()
                    .to_string();

                if !token.is_empty() {
                    info!("Successfully retrieved token via credential-process");
                    Ok(Some(token))
                } else {
                    warn!("Credential process returned empty output");
                    Ok(None)
                }
            } else {
                warn!("Could not get token via credential-process");
                Ok(None)
            }
        }
        None => {
            // Process timed out
            child.kill()?;
            warn!("Credential process timed out");
            Ok(None)
        }
    }
}
