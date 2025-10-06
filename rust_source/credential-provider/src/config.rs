// ABOUTME: Configuration loading and provider detection

use anyhow::{Context, Result};
use log::debug;
use serde_json::Value;
use shared::ProfileConfig;
use std::collections::HashMap;

use crate::aws::AwsFederation;
use crate::concurrency::PortLock;
use crate::oidc::OidcProvider;
use crate::storage::CredentialStorage;

pub struct MultiProviderAuth {
    pub profile: String,
    pub config: ProfileConfig,
    pub provider_type: String,
    pub redirect_port: u16,
    pub redirect_uri: String,
    pub storage: CredentialStorage,
}

impl MultiProviderAuth {
    pub fn new(profile: &str) -> Result<Self> {
        let mut config = load_config(profile)?;

        // Auto-detect federation type
        detect_federation_type(&mut config);

        let provider_type = determine_provider_type(&config);
        let redirect_port = std::env::var("REDIRECT_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8400);
        let redirect_uri = format!("http://localhost:{}/callback", redirect_port);

        let storage = CredentialStorage::new(
            profile,
            &config.credential_storage,
        )?;

        Ok(Self {
            profile: profile.to_string(),
            config,
            provider_type,
            redirect_port,
            redirect_uri,
            storage,
        })
    }

    pub async fn run(&self) -> Result<Option<Value>> {
        // Check cache first
        if let Some(cached) = self.storage.get_cached_credentials()? {
            debug!("Using cached credentials");
            return Ok(Some(cached));
        }

        // Try to acquire port lock
        match PortLock::try_acquire(self.redirect_port)? {
            Some(_lock) => {
                debug!("Port lock acquired, proceeding with authentication");

                // Check cache again (another process might have just finished)
                if let Some(cached) = self.storage.get_cached_credentials()? {
                    return Ok(Some(cached));
                }

                // Authenticate with Okta
                debug!(
                    "Authenticating with Okta for profile '{}'...",
                    self.profile
                );

                let oidc = OidcProvider::new(
                    self.config.provider_domain.clone(),
                    self.config.client_id.clone(),
                    self.provider_type.clone(),
                    self.redirect_uri.clone(),
                );

                let (id_token, token_claims) = oidc.authenticate_oidc().await?;

                // Get AWS credentials
                debug!("Exchanging token for AWS credentials...");
                let aws_federation = AwsFederation::new(self.config.aws_region.clone());

                let max_session_duration = self.config.max_session_duration.unwrap_or_else(|| {
                    if self.config.federation_type.as_deref() == Some("direct") {
                        43200 // 12 hours for direct STS
                    } else {
                        28800 // 8 hours for Cognito
                    }
                });

                let credentials = aws_federation
                    .get_aws_credentials(
                        &id_token,
                        &token_claims,
                        &self.config.federation_type,
                        &self.config.provider_domain,
                        &self.provider_type,
                        &self.config.identity_pool_id,
                        &self.config.federated_role_arn,
                        &self.config.role_arn,
                        max_session_duration,
                        &self.config.cognito_user_pool_id,
                    )
                    .await?;

                // Cache credentials
                self.storage.save_credentials(&credentials)?;

                // Save monitoring token (non-blocking, failures don't affect AWS auth)
                if let Err(e) = self.storage.save_monitoring_token(&id_token, &Value::Object(
                    token_claims.into_iter().collect()
                )) {
                    debug!("Warning: Could not save monitoring token: {}", e);
                }

                Ok(Some(credentials))
            }
            None => {
                // Port in use, another auth is in progress
                debug!("Another authentication is in progress, waiting...");

                // Wait for the other process to complete
                let storage_ref = &self.storage;
                PortLock::wait_for_release(
                    self.redirect_port,
                    60, // 60 second timeout
                    || storage_ref.get_cached_credentials(),
                )
            }
        }
    }

    pub fn clear_cached_credentials(&self) -> Result<Vec<String>> {
        self.storage.clear_credentials()
    }

    pub fn get_monitoring_token(&self) -> Result<Option<String>> {
        self.storage.get_monitoring_token()
    }

    pub async fn authenticate_for_monitoring(&self) -> Result<Option<String>> {
        // Try to acquire port lock
        match PortLock::try_acquire(self.redirect_port)? {
            Some(_lock) => {
                debug!("Port available, proceeding with monitoring authentication");

                // Authenticate with Okta for monitoring token
                debug!("Authenticating with Okta for monitoring token...");

                let oidc = OidcProvider::new(
                    self.config.provider_domain.clone(),
                    self.config.client_id.clone(),
                    self.provider_type.clone(),
                    self.redirect_uri.clone(),
                );

                let (id_token, token_claims) = oidc.authenticate_oidc().await?;

                // Get AWS credentials (we need them but won't output them)
                debug!("Exchanging token for AWS credentials...");
                let aws_federation = AwsFederation::new(self.config.aws_region.clone());

                let max_session_duration = self.config.max_session_duration.unwrap_or_else(|| {
                    if self.config.federation_type.as_deref() == Some("direct") {
                        43200
                    } else {
                        28800
                    }
                });

                let credentials = aws_federation
                    .get_aws_credentials(
                        &id_token,
                        &token_claims,
                        &self.config.federation_type,
                        &self.config.provider_domain,
                        &self.provider_type,
                        &self.config.identity_pool_id,
                        &self.config.federated_role_arn,
                        &self.config.role_arn,
                        max_session_duration,
                        &self.config.cognito_user_pool_id,
                    )
                    .await?;

                // Cache credentials for future use
                self.storage.save_credentials(&credentials)?;

                // Save monitoring token
                self.storage.save_monitoring_token(&id_token, &Value::Object(
                    token_claims.into_iter().collect()
                ))?;

                // Return just the monitoring token
                Ok(Some(id_token))
            }
            None => {
                // Port in use, another auth is in progress
                debug!("Another authentication is in progress, waiting...");

                // Wait for the other process to complete
                let storage_ref = &self.storage;
                let _ = PortLock::wait_for_release(
                    self.redirect_port,
                    60,
                    || storage_ref.get_cached_credentials(),
                )?;

                // After waiting, check if we now have a monitoring token
                let token = self.get_monitoring_token()?;
                if token.is_some() {
                    Ok(token)
                } else {
                    debug!("Authentication timeout or failed in another process");
                    Ok(None)
                }
            }
        }
    }
}

fn load_config(profile: &str) -> Result<ProfileConfig> {
    let config_path = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("claude-code-with-bedrock")
        .join("config.json");

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {:?}", config_path))?;

    let file_config: Value = serde_json::from_str(&content)?;

    // Handle new config format with profiles
    let mut profile_config = if let Some(profiles) = file_config.get("profiles") {
        let profiles: HashMap<String, ProfileConfig> = serde_json::from_value(profiles.clone())?;
        profiles
            .get(profile)
            .cloned()
            .with_context(|| format!("Profile '{}' not found in configuration", profile))?
    } else {
        // Old format for backward compatibility
        let profiles: HashMap<String, ProfileConfig> = serde_json::from_value(file_config)?;
        profiles
            .get(profile)
            .cloned()
            .with_context(|| format!("Profile '{}' not found in configuration", profile))?
    };

    // Backward compatibility field mapping
    // Handle identity_pool_name as alias for identity_pool_id
    if profile_config.identity_pool_id.is_none() && profile_config.identity_pool_name.is_some() {
        profile_config.identity_pool_id = profile_config.identity_pool_name.clone();
    }

    Ok(profile_config)
}

fn detect_federation_type(config: &mut ProfileConfig) {
    // Explicit federation type takes precedence
    if config.federation_type.is_some() {
        return;
    }

    // Auto-detect based on available configuration
    if config.federated_role_arn.is_some() {
        config.federation_type = Some("direct".to_string());
        debug!("Detected Direct STS federation mode (federated_role_arn found)");
    } else if config.identity_pool_id.is_some() || config.identity_pool_name.is_some() {
        config.federation_type = Some("cognito".to_string());
        debug!("Detected Cognito Identity Pool federation mode");
    } else {
        // Default to cognito for backward compatibility
        config.federation_type = Some("cognito".to_string());
        debug!("Defaulting to Cognito Identity Pool federation mode");
    }
}

fn determine_provider_type(_config: &ProfileConfig) -> String {
    // Always use Okta
    "okta".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_provider_type() {
        let config = ProfileConfig {
            provider_domain: "dev.okta.com".to_string(),
            client_id: "test".to_string(),
            identity_pool_id: None,
            identity_pool_name: None,
            federated_role_arn: None,
            role_arn: None,
            aws_region: "us-east-1".to_string(),
            provider_type: "auto".to_string(),
            credential_storage: "session".to_string(),
            federation_type: None,
            max_session_duration: None,
            cognito_user_pool_id: None,
        };

        // Always returns "okta" in simplified version
        assert_eq!(determine_provider_type(&config), "okta");
    }

    #[test]
    fn test_detect_federation_type() {
        let mut config = ProfileConfig {
            provider_domain: "dev.okta.com".to_string(),
            client_id: "test".to_string(),
            identity_pool_id: None,
            identity_pool_name: None,
            federated_role_arn: Some("arn:aws:iam::123456789012:role/MyRole".to_string()),
            role_arn: None,
            aws_region: "us-east-1".to_string(),
            provider_type: "auto".to_string(),
            credential_storage: "session".to_string(),
            federation_type: None,
            max_session_duration: None,
            cognito_user_pool_id: None,
        };

        detect_federation_type(&mut config);
        assert_eq!(config.federation_type, Some("direct".to_string()));

        config.federation_type = None;
        config.federated_role_arn = None;
        config.identity_pool_id = Some("us-east-1:12345678-1234-1234-1234-123456789012".to_string());
        detect_federation_type(&mut config);
        assert_eq!(config.federation_type, Some("cognito".to_string()));
    }
}
