// ABOUTME: OTEL helper script that extracts user attributes from JWT tokens
// ABOUTME: Outputs HTTP headers for OpenTelemetry collector to enable user attribution

use anyhow::Result;
use clap::Parser;
use log::{debug, error};
use std::collections::HashMap;

mod jwt;
mod attributes;
mod headers;
mod token;
mod logging;

use attributes::extract_user_info;
use headers::format_as_headers_dict;
use jwt::decode_jwt_payload;
use token::get_token_via_credential_process;

#[derive(Parser, Debug)]
#[command(name = "otel-helper")]
#[command(about = "Generate OTEL headers from authentication token")]
struct Args {
    /// Run in test mode with verbose output
    #[arg(long)]
    test: bool,

    /// Show verbose output
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    // Initialize logger based on mode
    if args.verbose {
        // Verbose mode: write to file
        if let Err(e) = logging::init_file_logger() {
            eprintln!("Warning: Failed to initialize file logger: {}", e);
            eprintln!("Continuing without file logging...");
        } else if !args.test {
            // Only show message in non-test mode (test mode has its own output)
            eprintln!("Debug logging enabled. Logs will be written to ~/claude-code-with-bedrock/logs/otel-helper.log");
        }
    } else if args.test {
        // Test mode: write to stderr only
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else if std::env::var("DEBUG_MODE").is_ok() {
        // Fallback to stderr logging if env var is set (for backward compatibility)
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    let result = run(args);

    match result {
        Ok(exit_code) => {
            if log::log_enabled!(log::Level::Debug) {
                debug!("=== OTEL Helper Session Ended (exit code: {}) ===", exit_code);
            }
            std::process::exit(exit_code)
        },
        Err(e) => {
            error!("Error processing token: {}", e);
            if log::log_enabled!(log::Level::Debug) {
                debug!("=== OTEL Helper Session Ended (error) ===");
            }
            std::process::exit(1);
        }
    }
}

fn run(args: Args) -> Result<i32> {
    // Try to get token from environment first
    let token = if let Ok(env_token) = std::env::var("CLAUDE_CODE_MONITORING_TOKEN") {
        debug!("Using token from environment variable CLAUDE_CODE_MONITORING_TOKEN");
        env_token
    } else {
        // Use credential-process to get token
        match get_token_via_credential_process()? {
            Some(t) => t,
            None => {
                debug!("Could not obtain authentication token");
                return Ok(1);
            }
        }
    };

    // Decode token and extract user info
    let payload = decode_jwt_payload(&token)?;
    let user_info = extract_user_info(&payload)?;

    // Generate headers dictionary
    let headers_dict = format_as_headers_dict(&user_info);

    // In test mode, print detailed output
    if args.test {
        print_test_output(&headers_dict, &user_info);
    } else {
        // Normal mode: Output as JSON
        println!("{}", serde_json::to_string(&headers_dict)?);
    }

    Ok(0)
}

fn print_test_output(headers: &HashMap<String, String>, user_info: &attributes::UserInfo) {
    println!("===== TEST MODE OUTPUT =====\n");
    println!("Generated HTTP Headers:");
    for (header_name, header_value) in headers {
        let display_name = header_name
            .replace("x-", "X-")
            .replace("-id", "-ID");
        println!("  {}: {}", display_name, header_value);
    }

    println!("\n===== Extracted Attributes =====\n");
    // Print non-technical fields first (matching Python order)
    for (key, value) in &[
        ("email", user_info.email.as_str()),
        ("user.id", {
            let truncated = &user_info.user_id[..30.min(user_info.user_id.len())];
            &format!("{}...", truncated)
        }),
        ("username", user_info.username.as_str()),
        ("organization.id", user_info.organization_id.as_str()),
        ("department", user_info.department.as_str()),
        ("team", user_info.team.as_str()),
        ("cost.center", user_info.cost_center.as_str()),
        ("manager", user_info.manager.as_str()),
        ("location", user_info.location.as_str()),
        ("role", user_info.role.as_str()),
    ] {
        let display_value = if value.len() > 30 {
            format!("{}...", &value[..30])
        } else {
            value.to_string()
        };
        println!("  {}: {}", key.replace('_', "."), display_value);
    }

    // Print full attributes (matching Python format)
    println!();
    println!("  user.email: {}", user_info.email);
    println!("  user.id: {}...", &user_info.user_id[..30.min(user_info.user_id.len())]);
    println!("  user.name: {}", user_info.username);
    println!("  organization.id: {}", user_info.organization_id);
    println!("  service.name: claude-code");
    println!("  user.account_uuid: {}", user_info.account_uuid);
    println!("  oidc.issuer: {}...", &user_info.issuer[..30.min(user_info.issuer.len())]);
    println!("  oidc.subject: {}...", &user_info.subject[..30.min(user_info.subject.len())]);
    println!("  department: {}", user_info.department);
    println!("  team.id: {}", user_info.team);
    println!("  cost_center: {}", user_info.cost_center);
    println!("  manager: {}", user_info.manager);
    println!("  location: {}", user_info.location);
    println!("  role: {}", user_info.role);

    println!("\n========================");
}
