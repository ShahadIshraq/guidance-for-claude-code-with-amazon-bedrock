// ABOUTME: AWS Credential Provider for OIDC authentication and Cognito Identity Pool federation
// ABOUTME: Supports multiple OIDC providers including Okta and Azure AD for Bedrock access

use anyhow::Result;
use clap::Parser;
use log::debug;

mod config;
mod oidc;
mod storage;
mod aws;
mod concurrency;
mod logging;

use config::MultiProviderAuth;

const VERSION: &str = "1.0.0";

#[derive(Parser, Debug)]
#[command(name = "credential-provider")]
#[command(about = "AWS credential provider for OIDC + Cognito Identity Pool", version = VERSION)]
struct Args {
    /// Configuration profile to use
    #[arg(short, long, default_value = "ClaudeCode")]
    profile: String,

    /// Get cached monitoring token instead of AWS credentials
    #[arg(long)]
    get_monitoring_token: bool,

    /// Clear cached credentials and force re-authentication
    #[arg(long)]
    clear_cache: bool,

    /// Enable verbose debug logging to file
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logger if verbose flag is set
    if args.verbose {
        if let Err(e) = logging::init_file_logger() {
            eprintln!("Warning: Failed to initialize file logger: {}", e);
            eprintln!("Continuing without file logging...");
        } else {
            eprintln!("Debug logging enabled. Logs will be written to ~/claude-code-with-bedrock/logs/credential-provider.log");
        }
    } else if std::env::var("COGNITO_AUTH_DEBUG").is_ok() {
        // Fallback to stderr logging if env var is set (for backward compatibility)
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    let result = run(args).await;

    match result {
        Ok(exit_code) => {
            if log::log_enabled!(log::Level::Debug) {
                debug!("=== Credential Provider Session Ended (exit code: {}) ===", exit_code);
            }
            std::process::exit(exit_code)
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            if log::log_enabled!(log::Level::Debug) {
                log::error!("Fatal error: {}", e);
                debug!("=== Credential Provider Session Ended (error) ===");
            }
            std::process::exit(1);
        }
    }
}

async fn run(args: Args) -> Result<i32> {
    let auth = MultiProviderAuth::new(&args.profile)?;

    // Handle cache clearing request
    if args.clear_cache {
        let cleared = auth.clear_cached_credentials()?;
        if !cleared.is_empty() {
            eprintln!("Cleared cached credentials for profile '{}':", args.profile);
            for item in cleared {
                eprintln!("  • {}", item);
            }
        } else {
            eprintln!("No cached credentials found for profile '{}'", args.profile);
        }
        return Ok(0);
    }

    // Handle monitoring token request
    if args.get_monitoring_token {
        match auth.get_monitoring_token()? {
            Some(token) => {
                println!("{}", token);
                Ok(0)
            }
            None => {
                debug!("No valid monitoring token found, triggering authentication...");
                match auth.authenticate_for_monitoring().await? {
                    Some(token) => {
                        println!("{}", token);
                        Ok(0)
                    }
                    None => Ok(1),
                }
            }
        }
    } else {
        // Normal AWS credential flow
        match auth.run().await? {
            Some(credentials) => {
                println!("{}", serde_json::to_string(&credentials)?);
                Ok(0)
            }
            None => Ok(1),
        }
    }
}
