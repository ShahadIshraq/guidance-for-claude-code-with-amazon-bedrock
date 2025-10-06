// ABOUTME: User attribute extraction from JWT claims
// ABOUTME: Privacy-preserving user ID hashing

use anyhow::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use shared::get_string_claim;

#[derive(Debug)]
pub struct UserInfo {
    pub email: String,
    pub user_id: String,
    pub username: String,
    pub organization_id: String,
    pub department: String,
    pub team: String,
    pub cost_center: String,
    pub manager: String,
    pub location: String,
    pub role: String,
    pub account_uuid: String,
    pub issuer: String,
    pub subject: String,
}

pub fn extract_user_info(payload: &Value) -> Result<UserInfo> {
    // Extract basic user info
    let email = get_string_claim(payload, "email")
        .or_else(|| get_string_claim(payload, "preferred_username"))
        .or_else(|| get_string_claim(payload, "mail"))
        .unwrap_or_else(|| "unknown@example.com".to_string());

    // For Cognito, use the sub as user_id and hash it for privacy
    let user_id = if let Some(sub) = get_string_claim(payload, "sub")
        .or_else(|| get_string_claim(payload, "user_id"))
    {
        hash_user_id(&sub)
    } else {
        "".to_string()
    };

    // Extract username - for Cognito it's in cognito:username
    let username = get_string_claim(payload, "cognito:username")
        .or_else(|| get_string_claim(payload, "preferred_username"))
        .unwrap_or_else(|| email.split('@').next().unwrap_or("unknown").to_string());

    // Extract organization - always use "okta" for Okta-based auth
    let org_id = "okta".to_string();

    // Extract team/department information - these fields vary by IdP
    let department = get_string_claim(payload, "department")
        .or_else(|| get_string_claim(payload, "dept"))
        .or_else(|| get_string_claim(payload, "division"))
        .unwrap_or_else(|| "unspecified".to_string());

    let team = get_string_claim(payload, "team")
        .or_else(|| get_string_claim(payload, "team_id"))
        .or_else(|| get_string_claim(payload, "group"))
        .unwrap_or_else(|| "default-team".to_string());

    let cost_center = get_string_claim(payload, "cost_center")
        .or_else(|| get_string_claim(payload, "costCenter"))
        .or_else(|| get_string_claim(payload, "cost_code"))
        .unwrap_or_else(|| "general".to_string());

    let manager = get_string_claim(payload, "manager")
        .or_else(|| get_string_claim(payload, "manager_email"))
        .unwrap_or_else(|| "unassigned".to_string());

    let location = get_string_claim(payload, "location")
        .or_else(|| get_string_claim(payload, "office_location"))
        .or_else(|| get_string_claim(payload, "office"))
        .unwrap_or_else(|| "remote".to_string());

    let role = get_string_claim(payload, "role")
        .or_else(|| get_string_claim(payload, "job_title"))
        .or_else(|| get_string_claim(payload, "title"))
        .unwrap_or_else(|| "user".to_string());

    let account_uuid = get_string_claim(payload, "aud").unwrap_or_default();
    let issuer = get_string_claim(payload, "iss").unwrap_or_default();
    let subject = get_string_claim(payload, "sub").unwrap_or_default();

    Ok(UserInfo {
        email,
        user_id,
        username,
        organization_id: org_id,
        department,
        team,
        cost_center,
        manager,
        location,
        role,
        account_uuid,
        issuer,
        subject,
    })
}

fn hash_user_id(user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    let result = hasher.finalize();
    let hash = hex::encode(result);

    // Format as UUID-like string (first 32 chars)
    format!(
        "{}-{}-{}-{}-{}",
        &hash[0..8],
        &hash[8..12],
        &hash[12..16],
        &hash[16..20],
        &hash[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hash_user_id_consistency() {
        let user_id = "test-user-123";
        let hash1 = hash_user_id(user_id);
        let hash2 = hash_user_id(user_id);

        assert_eq!(hash1, hash2);
        assert!(hash1.contains('-'));
        assert_eq!(hash1.len(), 36); // UUID format
    }

    #[test]
    fn test_extract_user_info() {
        let payload = json!({
            "sub": "user123",
            "email": "test@example.com",
            "department": "Engineering",
            "team": "Platform"
        });

        let info = extract_user_info(&payload).unwrap();
        assert_eq!(info.email, "test@example.com");
        assert_eq!(info.department, "Engineering");
        assert_eq!(info.team, "Platform");
        assert!(!info.user_id.is_empty());
    }
}
