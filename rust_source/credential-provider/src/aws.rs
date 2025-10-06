// ABOUTME: AWS credential exchange via Direct STS or Cognito Identity Pool

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_cognitoidentity::config::Credentials as CognitoCredentials;
use aws_sdk_cognitoidentity::Client as CognitoIdentityClient;
use aws_sdk_sts::types::Tag;
use aws_sdk_sts::Client as StsClient;
use log::debug;
use serde_json::{json, Value};
use std::collections::HashMap;

pub struct AwsFederation {
    aws_region: String,
}

impl AwsFederation {
    pub fn new(aws_region: String) -> Self {
        Self { aws_region }
    }

    /// Exchange OIDC token for AWS credentials
    pub async fn get_aws_credentials(
        &self,
        id_token: &str,
        token_claims: &HashMap<String, Value>,
        federation_type: &Option<String>,
        provider_domain: &str,
        provider_type: &str,
        identity_pool_id: &Option<String>,
        federated_role_arn: &Option<String>,
        role_arn: &Option<String>,
        max_session_duration: i32,
        cognito_user_pool_id: &Option<String>,
    ) -> Result<Value> {
        debug!("Entering get_aws_credentials method");

        let fed_type = federation_type.as_deref().unwrap_or("cognito");
        debug!("Using federation type: {}", fed_type);

        if fed_type == "direct" {
            self.get_aws_credentials_direct(
                id_token,
                token_claims,
                federated_role_arn
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("federated_role_arn is required for direct STS federation"))?,
                max_session_duration,
            )
            .await
        } else {
            self.get_aws_credentials_cognito(
                id_token,
                token_claims,
                provider_domain,
                provider_type,
                identity_pool_id
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("identity_pool_id is required for Cognito federation"))?,
                role_arn,
                cognito_user_pool_id,
            )
            .await
        }
    }

    /// Direct STS federation without Cognito Identity Pool - provides 12 hour sessions
    async fn get_aws_credentials_direct(
        &self,
        id_token: &str,
        token_claims: &HashMap<String, Value>,
        federated_role_arn: &str,
        max_session_duration: i32,
    ) -> Result<Value> {
        debug!("Using Direct STS federation (AssumeRoleWithWebIdentity)");

        // Create STS client
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(self.aws_region.clone()))
            .load()
            .await;
        let sts_client = StsClient::new(&config);

        // Prepare session tags from token claims
        let mut session_tags = Vec::new();

        let tag_mappings = [
            ("email", "UserEmail"),
            ("sub", "UserId"),
            ("preferred_username", "UserName"),
            ("name", "UserName"), // Fallback
        ];

        for (claim_key, tag_key) in &tag_mappings {
            if let Some(value) = token_claims.get(*claim_key) {
                if let Some(str_value) = value.as_str() {
                    // Session tag values have a 256 character limit
                    let tag_value = if str_value.len() > 256 {
                        &str_value[..256]
                    } else {
                        str_value
                    };
                    session_tags.push(
                        Tag::builder()
                            .key(tag_key.to_string())
                            .value(tag_value.to_string())
                            .build()
                            .context("Failed to build session tag")?,
                    );
                }
            }
        }

        // Generate session name from user identifier
        let session_name = if let Some(sub) = token_claims.get("sub").and_then(|v| v.as_str()) {
            format!("claude-code-{}", &sub[..sub.len().min(32)])
        } else if let Some(email) = token_claims.get("email").and_then(|v| v.as_str()) {
            let username = email.split('@').next().unwrap_or("user");
            format!("claude-code-{}", &username[..username.len().min(32)])
        } else {
            "claude-code".to_string()
        };

        debug!("Assuming role: {}", federated_role_arn);
        debug!("Session name: {}", session_name);
        debug!("Session tags: {:?}", session_tags);

        // Call AssumeRoleWithWebIdentity
        let response = sts_client
            .assume_role_with_web_identity()
            .role_arn(federated_role_arn)
            .role_session_name(session_name)
            .web_identity_token(id_token)
            .duration_seconds(max_session_duration)
            .send()
            .await
            .map_err(|e| {
                let error_str = e.to_string();
                if is_credential_error(&error_str) {
                    anyhow::anyhow!(
                        "Authentication failed - cached credentials were invalid and have been cleared.\n\
                        Please try again to re-authenticate.\n\
                        Original error: {}",
                        error_str
                    )
                } else {
                    anyhow::anyhow!("Failed to get AWS credentials via Direct STS: {}", error_str)
                }
            })?;

        let creds = response
            .credentials()
            .ok_or_else(|| anyhow::anyhow!("No credentials in response"))?;

        // Format for AWS CLI
        let expiration = creds.expiration().fmt(aws_sdk_sts::primitives::DateTimeFormat::DateTimeWithOffset)
            .map_err(|e| anyhow::anyhow!("Failed to format expiration: {}", e))?;

        let formatted_creds = json!({
            "Version": 1,
            "AccessKeyId": creds.access_key_id(),
            "SecretAccessKey": creds.secret_access_key(),
            "SessionToken": creds.session_token(),
            "Expiration": expiration,
        });

        debug!(
            "Successfully obtained credentials via Direct STS, expires: {}",
            formatted_creds["Expiration"]
        );

        Ok(formatted_creds)
    }

    /// Exchange OIDC token for AWS credentials via Cognito Identity Pool
    async fn get_aws_credentials_cognito(
        &self,
        id_token: &str,
        token_claims: &HashMap<String, Value>,
        provider_domain: &str,
        provider_type: &str,
        identity_pool_id: &str,
        role_arn: &Option<String>,
        cognito_user_pool_id: &Option<String>,
    ) -> Result<Value> {
        debug!("Using Cognito Identity Pool federation");

        // Create Cognito Identity client without credentials
        debug!("Creating Cognito Identity client...");
        let cognito_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(self.aws_region.clone()))
            .credentials_provider(CognitoCredentials::new(
                "UNSIGNED",
                "UNSIGNED",
                None,
                None,
                "unsigned"
            ))
            .load()
            .await;
        let cognito_client = CognitoIdentityClient::new(&cognito_config);
        debug!("Cognito client created");

        debug!("Creating STS client...");
        let sts_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(self.aws_region.clone()))
            .load()
            .await;
        let _sts_client = StsClient::new(&sts_config);
        debug!("STS client created");

        debug!("Provider type: {}", provider_type);
        debug!("AWS Region: {}", self.aws_region);
        debug!("Identity Pool ID: {}", identity_pool_id);

        // Determine the correct login key based on provider type
        let login_key = if provider_type == "cognito" {
            // For Cognito User Pool, extract from token issuer to ensure case matches
            if let Some(issuer) = token_claims.get("iss").and_then(|v| v.as_str()) {
                debug!("Using issuer from token as login key");
                issuer.replace("https://", "")
            } else {
                // Fallback: construct from config
                let user_pool_id = cognito_user_pool_id
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("cognito_user_pool_id is required for Cognito User Pool authentication"))?;
                let key = format!("cognito-idp.{}.amazonaws.com/{}", self.aws_region, user_pool_id);
                debug!("Cognito User Pool ID from config: {}", user_pool_id);
                key
            }
        } else {
            // For external OIDC providers, use the provider domain
            provider_domain.to_string()
        };

        debug!("Login key: {}", login_key);
        debug!("Token claims: {:?}", token_claims.keys().collect::<Vec<_>>());
        if let Some(issuer) = token_claims.get("iss") {
            debug!("Token issuer: {}", issuer);
        }

        // Log all claims being passed for principal tags
        if log::log_enabled!(log::Level::Debug) {
            debug!("\n=== Claims being sent to Cognito Identity ===");
            debug!("Provider: {}", login_key);
            debug!("Claims that could be mapped to principal tags:");
            for (key, value) in token_claims {
                debug!("  {}: {}", key, value);
            }
        }

        // Get Cognito identity
        debug!("Calling GetId with identity pool: {}", identity_pool_id);
        let mut logins = HashMap::new();
        logins.insert(login_key.clone(), id_token.to_string());

        let identity_response = cognito_client
            .get_id()
            .identity_pool_id(identity_pool_id)
            .set_logins(Some(logins.clone()))
            .send()
            .await
            .map_err(|e| {
                let error_str = e.to_string();
                if is_credential_error(&error_str) {
                    anyhow::anyhow!(
                        "Authentication failed - cached credentials were invalid and have been cleared.\n\
                        Please try again to re-authenticate.\n\
                        Original error: {}",
                        error_str
                    )
                } else {
                    anyhow::anyhow!("Failed to get AWS credentials: {}", error_str)
                }
            })?;

        let identity_id = identity_response
            .identity_id()
            .ok_or_else(|| anyhow::anyhow!("No identity ID in response"))?;
        debug!("Got Cognito Identity ID: {}", identity_id);

        let role_arn_opt = role_arn.clone();
        debug!(
            "Configured role ARN: {}",
            role_arn_opt.as_deref().unwrap_or("None (using default pool role)")
        );

        // Get credentials for identity
        let credentials_response = cognito_client
            .get_credentials_for_identity()
            .identity_id(identity_id)
            .set_logins(Some(logins))
            .send()
            .await?;

        let creds = credentials_response
            .credentials()
            .ok_or_else(|| anyhow::anyhow!("No credentials in response"))?;

        let expiration = creds.expiration()
            .ok_or_else(|| anyhow::anyhow!("No expiration"))?
            .fmt(aws_sdk_cognitoidentity::primitives::DateTimeFormat::DateTimeWithOffset)
            .map_err(|e| anyhow::anyhow!("Failed to format expiration: {}", e))?;

        // Format for AWS CLI
        let formatted_creds = json!({
            "Version": 1,
            "AccessKeyId": creds.access_key_id().ok_or_else(|| anyhow::anyhow!("No access key"))?,
            "SecretAccessKey": creds.secret_key().ok_or_else(|| anyhow::anyhow!("No secret key"))?,
            "SessionToken": creds.session_token().ok_or_else(|| anyhow::anyhow!("No session token"))?,
            "Expiration": expiration,
        });

        Ok(formatted_creds)
    }
}

fn is_credential_error(error_str: &str) -> bool {
    let error_patterns = [
        "InvalidParameterException",
        "NotAuthorizedException",
        "ValidationError",
        "Invalid AccessKeyId",
        "ExpiredToken",
        "Invalid JWT",
        "Token is not from a supported provider",
    ];

    error_patterns.iter().any(|pattern| error_str.contains(pattern))
}
