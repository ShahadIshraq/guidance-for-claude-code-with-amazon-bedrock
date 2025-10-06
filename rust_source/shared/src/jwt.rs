// ABOUTME: Common JWT parsing utilities without signature verification

use crate::error::{Result, SharedError};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;

/// Decode JWT payload without signature verification
pub fn decode_jwt_payload(token: &str) -> Result<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SharedError::JwtDecode(
            "Invalid JWT format: expected 3 parts".to_string(),
        ));
    }

    // Get the payload part (second segment)
    let mut payload_b64 = parts[1].to_string();

    // Add padding if needed (matches Python logic)
    let padding_needed = payload_b64.len() % 4;
    if padding_needed > 0 {
        payload_b64.push_str(&"=".repeat(4 - padding_needed));
    }

    // Replace URL-safe characters (matches Python logic)
    payload_b64 = payload_b64.replace("-", "+").replace("_", "/");

    // Decode base64
    let payload_bytes = general_purpose::STANDARD
        .decode(&payload_b64)
        .map_err(|e| SharedError::JwtDecode(format!("Base64 decode failed: {}", e)))?;

    // Parse JSON
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SharedError::JwtDecode(format!("JSON parse failed: {}", e)))?;

    Ok(payload)
}

/// Extract a string claim from JWT payload
pub fn get_string_claim(payload: &Value, key: &str) -> Option<String> {
    payload.get(key)?.as_str().map(|s| s.to_string())
}

/// Extract an integer claim from JWT payload
pub fn get_i64_claim(payload: &Value, key: &str) -> Option<i64> {
    payload.get(key)?.as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt_payload() {
        // Sample JWT (header.payload.signature)
        // Payload: {"sub":"1234567890","name":"Test User","iat":1516239022}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let payload = decode_jwt_payload(token).unwrap();
        assert_eq!(get_string_claim(&payload, "sub"), Some("1234567890".to_string()));
        assert_eq!(get_string_claim(&payload, "name"), Some("Test User".to_string()));
        assert_eq!(get_i64_claim(&payload, "iat"), Some(1516239022));
    }

    #[test]
    fn test_invalid_jwt() {
        assert!(decode_jwt_payload("invalid").is_err());
        assert!(decode_jwt_payload("part1.part2").is_err());
    }
}
