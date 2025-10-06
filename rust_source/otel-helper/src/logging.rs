// ABOUTME: File-based logging configuration for debug mode

use anyhow::Result;

/// Initialize file logger that writes to ~/claude-code-with-bedrock/logs/otel-helper.log
pub fn init_file_logger() -> Result<()> {
    shared::init_file_logger("otel-helper", "OTEL Helper")
}
