// ABOUTME: Credential storage via keyring or session files

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::debug;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct CredentialStorage {
    profile: String,
    storage_type: StorageType,
}

enum StorageType {
    Keyring,
    Session { session_dir: PathBuf },
}

impl CredentialStorage {
    pub fn new(profile: &str, credential_storage: &str) -> Result<Self> {
        let storage_type = if credential_storage == "keyring" {
            StorageType::Keyring
        } else {
            let session_dir = dirs::home_dir()
                .context("Failed to get home directory")?
                .join(".claude-code-session");
            std::fs::create_dir_all(&session_dir)?;
            StorageType::Session { session_dir }
        };

        Ok(Self {
            profile: profile.to_string(),
            storage_type,
        })
    }

    pub fn get_cached_credentials(&self) -> Result<Option<Value>> {
        match &self.storage_type {
            StorageType::Keyring => self.get_from_keyring(),
            StorageType::Session { session_dir } => self.get_from_session_file(session_dir),
        }
    }

    pub fn save_credentials(&self, credentials: &Value) -> Result<()> {
        match &self.storage_type {
            StorageType::Keyring => self.save_to_keyring(credentials),
            StorageType::Session { session_dir } => self.save_to_session_file(session_dir, credentials),
        }
    }

    pub fn clear_credentials(&self) -> Result<Vec<String>> {
        let mut cleared = Vec::new();

        // Clear from keyring
        match &self.storage_type {
            StorageType::Keyring => {
                if self.clear_keyring()? {
                    if cfg!(target_os = "windows") {
                        cleared.push("keyring credentials (Windows)".to_string());
                    } else {
                        cleared.push("keyring credentials".to_string());
                    }
                }
                // Clear monitoring token from keyring
                if self.clear_monitoring_keyring()? {
                    cleared.push("keyring monitoring token".to_string());
                }
            }
            StorageType::Session { session_dir } => {
                if self.clear_session_file(session_dir)? {
                    cleared.push("session file".to_string());
                }
                if self.clear_monitoring_session(session_dir)? {
                    cleared.push("monitoring token file".to_string());
                }
            }
        }

        Ok(cleared)
    }

    pub fn get_monitoring_token(&self) -> Result<Option<String>> {
        // Check environment first
        if let Ok(token) = std::env::var("CLAUDE_CODE_MONITORING_TOKEN") {
            return Ok(Some(token));
        }

        match &self.storage_type {
            StorageType::Keyring => self.get_monitoring_from_keyring(),
            StorageType::Session { session_dir } => self.get_monitoring_from_session(session_dir),
        }
    }

    pub fn save_monitoring_token(&self, id_token: &str, token_claims: &Value) -> Result<()> {
        let token_data = json!({
            "token": id_token,
            "expires": token_claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0),
            "email": token_claims.get("email").and_then(|v| v.as_str()).unwrap_or(""),
            "profile": self.profile,
        });

        match &self.storage_type {
            StorageType::Keyring => self.save_monitoring_to_keyring(&token_data),
            StorageType::Session { session_dir } => self.save_monitoring_to_session(session_dir, &token_data),
        }?;

        // Also export to environment for this session
        std::env::set_var("CLAUDE_CODE_MONITORING_TOKEN", id_token);
        debug!("Saved monitoring token for {}", token_claims.get("email").and_then(|v| v.as_str()).unwrap_or("user"));

        Ok(())
    }

    fn get_from_keyring(&self) -> Result<Option<Value>> {
        use keyring::Entry;

        // On Windows, credentials are split into multiple entries
        if cfg!(target_os = "windows") {
            return self.get_from_keyring_windows();
        }

        let entry = Entry::new("claude-code-with-bedrock", &format!("{}-credentials", self.profile))?;

        match entry.get_password() {
            Ok(creds_json) => {
                let creds: Value = serde_json::from_str(&creds_json)?;

                // Check for dummy/cleared credentials
                if creds.get("AccessKeyId").and_then(|v| v.as_str()) == Some("EXPIRED") {
                    debug!("Found cleared dummy credentials, need re-authentication");
                    return Ok(None);
                }

                // Validate expiration
                if self.is_expired(&creds)? {
                    return Ok(None);
                }

                Ok(Some(creds))
            }
            Err(_) => Ok(None),
        }
    }

    fn get_from_keyring_windows(&self) -> Result<Option<Value>> {
        use keyring::Entry;

        let keys_entry = Entry::new("claude-code-with-bedrock", &format!("{}-keys", self.profile))?;
        let token1_entry = Entry::new("claude-code-with-bedrock", &format!("{}-token1", self.profile))?;
        let token2_entry = Entry::new("claude-code-with-bedrock", &format!("{}-token2", self.profile))?;
        let meta_entry = Entry::new("claude-code-with-bedrock", &format!("{}-meta", self.profile))?;

        match (
            keys_entry.get_password(),
            token1_entry.get_password(),
            token2_entry.get_password(),
            meta_entry.get_password(),
        ) {
            (Ok(keys_json), Ok(token1), Ok(token2), Ok(meta_json)) => {
                let keys: Value = serde_json::from_str(&keys_json)?;
                let meta: Value = serde_json::from_str(&meta_json)?;

                let creds = json!({
                    "Version": meta["Version"],
                    "AccessKeyId": keys["AccessKeyId"],
                    "SecretAccessKey": keys["SecretAccessKey"],
                    "SessionToken": format!("{}{}", token1, token2),
                    "Expiration": meta["Expiration"],
                });

                // Check for dummy/cleared credentials
                if creds.get("AccessKeyId").and_then(|v| v.as_str()) == Some("EXPIRED") {
                    debug!("Found cleared dummy credentials, need re-authentication");
                    return Ok(None);
                }

                // Validate expiration
                if self.is_expired(&creds)? {
                    return Ok(None);
                }

                Ok(Some(creds))
            }
            _ => Ok(None),
        }
    }

    fn get_from_session_file(&self, session_dir: &PathBuf) -> Result<Option<Value>> {
        let session_file = session_dir.join(format!("{}-session.json", self.profile));

        if !session_file.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&session_file)?;
        let creds: Value = serde_json::from_str(&content)?;

        // Check for dummy/cleared credentials
        if creds.get("AccessKeyId").and_then(|v| v.as_str()) == Some("EXPIRED") {
            debug!("Found cleared dummy credentials in session file, need re-authentication");
            return Ok(None);
        }

        // Validate expiration
        if self.is_expired(&creds)? {
            return Ok(None);
        }

        Ok(Some(creds))
    }

    fn save_to_keyring(&self, credentials: &Value) -> Result<()> {
        use keyring::Entry;

        // On Windows, split credentials into multiple entries
        if cfg!(target_os = "windows") {
            return self.save_to_keyring_windows(credentials);
        }

        let entry = Entry::new("claude-code-with-bedrock", &format!("{}-credentials", self.profile))?;
        let creds_json = serde_json::to_string(credentials)?;
        entry.set_password(&creds_json)?;

        Ok(())
    }

    fn save_to_keyring_windows(&self, credentials: &Value) -> Result<()> {
        use keyring::Entry;

        let session_token = credentials["SessionToken"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No SessionToken in credentials"))?;
        let mid = session_token.len() / 2;

        // Store as 4 separate entries
        let keys_entry = Entry::new("claude-code-with-bedrock", &format!("{}-keys", self.profile))?;
        keys_entry.set_password(&serde_json::to_string(&json!({
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretAccessKey"],
        }))?)?;

        let token1_entry = Entry::new("claude-code-with-bedrock", &format!("{}-token1", self.profile))?;
        token1_entry.set_password(&session_token[..mid])?;

        let token2_entry = Entry::new("claude-code-with-bedrock", &format!("{}-token2", self.profile))?;
        token2_entry.set_password(&session_token[mid..])?;

        let meta_entry = Entry::new("claude-code-with-bedrock", &format!("{}-meta", self.profile))?;
        meta_entry.set_password(&serde_json::to_string(&json!({
            "Version": credentials["Version"],
            "Expiration": credentials["Expiration"],
        }))?)?;

        Ok(())
    }

    fn save_to_session_file(&self, session_dir: &PathBuf, credentials: &Value) -> Result<()> {
        let session_file = session_dir.join(format!("{}-session.json", self.profile));
        let content = serde_json::to_string_pretty(credentials)?;
        std::fs::write(&session_file, content)?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&session_file)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&session_file, perms)?;
        }

        Ok(())
    }

    fn clear_keyring(&self) -> Result<bool> {
        use keyring::Entry;

        if cfg!(target_os = "windows") {
            return self.clear_keyring_windows();
        }

        let entry = Entry::new("claude-code-with-bedrock", &format!("{}-credentials", self.profile))?;

        match entry.get_password() {
            Ok(_) => {
                // Replace with expired dummy credential
                let expired = json!({
                    "Version": 1,
                    "AccessKeyId": "EXPIRED",
                    "SecretAccessKey": "EXPIRED",
                    "SessionToken": "EXPIRED",
                    "Expiration": "2000-01-01T00:00:00Z"
                });
                entry.set_password(&serde_json::to_string(&expired)?)?;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn clear_keyring_windows(&self) -> Result<bool> {
        use keyring::Entry;

        let entries = [
            format!("{}-keys", self.profile),
            format!("{}-token1", self.profile),
            format!("{}-token2", self.profile),
            format!("{}-meta", self.profile),
        ];

        let mut any_cleared = false;

        for entry_name in &entries {
            let entry = Entry::new("claude-code-with-bedrock", entry_name)?;
            if entry.get_password().is_ok() {
                // Replace with expired dummy data
                let expired_data = if entry_name.contains("keys") {
                    serde_json::to_string(&json!({"AccessKeyId": "EXPIRED", "SecretAccessKey": "EXPIRED"}))?
                } else if entry_name.contains("token") {
                    "EXPIRED".to_string()
                } else if entry_name.contains("meta") {
                    serde_json::to_string(&json!({"Version": 1, "Expiration": "2000-01-01T00:00:00Z"}))?
                } else {
                    "EXPIRED".to_string()
                };
                entry.set_password(&expired_data)?;
                any_cleared = true;
            }
        }

        Ok(any_cleared)
    }

    fn clear_session_file(&self, session_dir: &PathBuf) -> Result<bool> {
        let session_file = session_dir.join(format!("{}-session.json", self.profile));

        if session_file.exists() {
            std::fs::remove_file(&session_file)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn clear_monitoring_keyring(&self) -> Result<bool> {
        use keyring::Entry;

        let entry = Entry::new("claude-code-with-bedrock", &format!("{}-monitoring", self.profile))?;

        match entry.get_password() {
            Ok(_) => {
                // Replace with expired dummy token
                let expired = json!({
                    "token": "EXPIRED",
                    "expires": 0,
                    "email": "",
                    "profile": self.profile,
                });
                entry.set_password(&serde_json::to_string(&expired)?)?;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn clear_monitoring_session(&self, session_dir: &PathBuf) -> Result<bool> {
        let monitoring_file = session_dir.join(format!("{}-monitoring.json", self.profile));

        if monitoring_file.exists() {
            std::fs::remove_file(&monitoring_file)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_monitoring_from_keyring(&self) -> Result<Option<String>> {
        use keyring::Entry;

        let entry = Entry::new("claude-code-with-bedrock", &format!("{}-monitoring", self.profile))?;

        match entry.get_password() {
            Ok(token_json) => {
                let token_data: Value = serde_json::from_str(&token_json)?;

                // Check for dummy/cleared token
                if token_data.get("token").and_then(|v| v.as_str()) == Some("EXPIRED") {
                    return Ok(None);
                }

                // Check expiration
                if let Some(exp) = token_data.get("expires").and_then(|v| v.as_i64()) {
                    let now = Utc::now().timestamp();
                    // Return token if it expires in more than 10 minutes
                    if exp - now > 600 {
                        let token = token_data["token"].as_str().unwrap().to_string();
                        // Set in environment for this session
                        std::env::set_var("CLAUDE_CODE_MONITORING_TOKEN", &token);
                        return Ok(Some(token));
                    }
                }

                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    fn get_monitoring_from_session(&self, session_dir: &PathBuf) -> Result<Option<String>> {
        let token_file = session_dir.join(format!("{}-monitoring.json", self.profile));

        if !token_file.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&token_file)?;
        let token_data: Value = serde_json::from_str(&content)?;

        // Check expiration
        if let Some(exp) = token_data.get("expires").and_then(|v| v.as_i64()) {
            let now = Utc::now().timestamp();
            // Return token if it expires in more than 10 minutes
            if exp - now > 600 {
                let token = token_data["token"].as_str().unwrap().to_string();
                // Set in environment for this session
                std::env::set_var("CLAUDE_CODE_MONITORING_TOKEN", &token);
                return Ok(Some(token));
            }
        }

        Ok(None)
    }

    fn save_monitoring_to_keyring(&self, token_data: &Value) -> Result<()> {
        use keyring::Entry;

        let entry = Entry::new("claude-code-with-bedrock", &format!("{}-monitoring", self.profile))?;
        entry.set_password(&serde_json::to_string(token_data)?)?;

        Ok(())
    }

    fn save_monitoring_to_session(&self, session_dir: &PathBuf, token_data: &Value) -> Result<()> {
        let token_file = session_dir.join(format!("{}-monitoring.json", self.profile));
        let content = serde_json::to_string_pretty(token_data)?;
        std::fs::write(&token_file, content)?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&token_file)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&token_file, perms)?;
        }

        Ok(())
    }

    fn is_expired(&self, creds: &Value) -> Result<bool> {
        if let Some(exp_str) = creds.get("Expiration").and_then(|v| v.as_str()) {
            let exp_time: DateTime<Utc> = DateTime::parse_from_rfc3339(exp_str)
                .context("Failed to parse expiration time")?
                .into();
            let now = Utc::now();

            // Use credentials if they expire in more than 30 seconds
            Ok((exp_time - now).num_seconds() <= 30)
        } else {
            Ok(true) // No expiration means expired
        }
    }
}
