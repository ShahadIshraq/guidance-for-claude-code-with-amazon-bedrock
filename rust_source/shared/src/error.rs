// ABOUTME: Common error types for credential-provider and otel-helper

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SharedError {
    #[error("JWT decode error: {0}")]
    JwtDecode(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, SharedError>;
