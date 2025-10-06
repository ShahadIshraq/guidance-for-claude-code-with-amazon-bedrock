// ABOUTME: HTTP header formatting for OTEL collector

use crate::attributes::UserInfo;
use std::collections::HashMap;

pub fn format_as_headers_dict(attributes: &UserInfo) -> HashMap<String, String> {
    let mut headers = HashMap::new();

    // Map attributes to HTTP headers expected by OTEL collector
    // Note: Headers must be lowercase to match OTEL collector configuration
    headers.insert("x-user-email".to_string(), attributes.email.clone());
    headers.insert("x-user-id".to_string(), attributes.user_id.clone());
    headers.insert("x-user-name".to_string(), attributes.username.clone());
    headers.insert("x-department".to_string(), attributes.department.clone());
    headers.insert("x-team-id".to_string(), attributes.team.clone());
    headers.insert("x-cost-center".to_string(), attributes.cost_center.clone());
    headers.insert("x-organization".to_string(), attributes.organization_id.clone());
    headers.insert("x-location".to_string(), attributes.location.clone());
    headers.insert("x-role".to_string(), attributes.role.clone());
    headers.insert("x-manager".to_string(), attributes.manager.clone());

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_as_headers_dict() {
        let user_info = UserInfo {
            email: "test@example.com".to_string(),
            user_id: "12345".to_string(),
            username: "testuser".to_string(),
            organization_id: "okta".to_string(),
            department: "Engineering".to_string(),
            team: "Platform".to_string(),
            cost_center: "CC001".to_string(),
            manager: "manager@example.com".to_string(),
            location: "remote".to_string(),
            role: "engineer".to_string(),
            account_uuid: "".to_string(),
            issuer: "".to_string(),
            subject: "".to_string(),
        };

        let headers = format_as_headers_dict(&user_info);

        assert_eq!(headers.get("x-user-email"), Some(&"test@example.com".to_string()));
        assert_eq!(headers.get("x-user-id"), Some(&"12345".to_string()));
        assert_eq!(headers.get("x-department"), Some(&"Engineering".to_string()));
    }
}
