// ABOUTME: Shared configuration types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub provider_domain: String,
    pub client_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_pool_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_pool_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub federated_role_arn: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,

    #[serde(default = "default_aws_region")]
    pub aws_region: String,

    #[serde(default = "default_provider_type")]
    pub provider_type: String,

    #[serde(default = "default_credential_storage")]
    pub credential_storage: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_session_duration: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cognito_user_pool_id: Option<String>,
}

fn default_aws_region() -> String {
    "us-east-1".to_string()
}

fn default_provider_type() -> String {
    "auto".to_string()
}

fn default_credential_storage() -> String {
    "session".to_string()
}
