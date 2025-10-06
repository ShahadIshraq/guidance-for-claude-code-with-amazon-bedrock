// ABOUTME: PKCE flow OAuth2 implementation
// ABOUTME: OAuth callback server and token exchange

use anyhow::{Context, Result};
use axum::{
    extract::Query,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use log::debug;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

// Okta OIDC configuration constants
const PROVIDER_NAME: &str = "Okta";
const AUTHORIZE_ENDPOINT: &str = "/oauth2/v1/authorize";
const TOKEN_ENDPOINT: &str = "/oauth2/v1/token";
const SCOPES: &str = "openid profile email";
const RESPONSE_TYPE: &str = "code";

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug)]
struct AuthResult {
    code: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    #[allow(dead_code)]
    access_token: Option<String>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
}

pub struct OidcProvider {
    provider_domain: String,
    client_id: String,
    redirect_uri: String,
}

impl OidcProvider {
    pub fn new(
        provider_domain: String,
        client_id: String,
        _provider_type: String,
        redirect_uri: String,
    ) -> Self {
        Self {
            provider_domain,
            client_id,
            redirect_uri,
        }
    }

    /// Create a TcpListener with SO_REUSEADDR enabled
    fn create_reusable_listener(port: u16) -> Result<TcpListener> {
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .parse()
            .context("Failed to parse address")?;

        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("Failed to create socket")?;

        socket
            .set_reuse_address(true)
            .context("Failed to set SO_REUSEADDR")?;

        socket
            .bind(&addr.into())
            .context("Failed to bind OIDC socket")?;

        socket.listen(128).context("Failed to listen on OIDC socket")?;

        // Convert to tokio TcpListener
        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;
        Ok(TcpListener::from_std(std_listener)?)
    }

    /// Perform OIDC authentication with PKCE
    pub async fn authenticate_oidc(&self) -> Result<(String, HashMap<String, serde_json::Value>)> {
        let state = generate_random_string(16);
        let nonce = generate_random_string(16);

        // Generate PKCE parameters
        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier);

        // Build authorization URL
        let auth_url = self.build_auth_url(&state, &nonce, &code_challenge)?;

        // Setup callback server
        let auth_result = Arc::new(Mutex::new(AuthResult {
            code: None,
            error: None,
        }));

        let callback_result = auth_result.clone();
        let expected_state = state.clone();

        let app = Router::new().route(
            "/callback",
            get(move |query: Query<CallbackQuery>| {
                handle_callback(query, expected_state.clone(), callback_result.clone())
            }),
        );

        // Extract port from redirect_uri
        let redirect_url = Url::parse(&self.redirect_uri)?;
        let port = redirect_url.port().unwrap_or(8400);

        let listener = Self::create_reusable_listener(port)?;

        // Start server in background
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("Server failed to start");
        });

        // Open browser
        debug!("Opening browser for {} authentication...", PROVIDER_NAME);
        debug!("If browser doesn't open, visit: {}", auth_url);

        if let Err(e) = webbrowser::open(&auth_url) {
            debug!("Failed to open browser: {}", e);
        }

        // Wait for callback with timeout
        let timeout_duration = Duration::from_secs(300); // 5 minutes
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout_duration {
                server_handle.abort();
                anyhow::bail!("Authentication timeout - no authorization code received");
            }

            let result = auth_result.lock().unwrap();
            if result.error.is_some() {
                let error = result.error.clone().unwrap();
                drop(result);
                server_handle.abort();
                anyhow::bail!("Authentication error: {}", error);
            }

            if result.code.is_some() {
                let code = result.code.clone().unwrap();
                drop(result);
                server_handle.abort();

                // Exchange code for tokens
                let tokens = self.exchange_code_for_tokens(&code, &code_verifier).await?;

                // Decode ID token
                let claims = decode_id_token(&tokens.id_token)?;

                // Validate nonce
                if let Some(token_nonce) = claims.get("nonce").and_then(|v| v.as_str()) {
                    if token_nonce != nonce {
                        anyhow::bail!("Invalid nonce in ID token");
                    }
                }

                // Enhanced debug logging
                if log::log_enabled!(log::Level::Debug) {
                    debug!("\n=== ID Token Claims ===");
                    debug!("{}", serde_json::to_string_pretty(&claims)?);

                    debug!("\n=== Key Claims for Mapping ===");
                    let important_claims = [
                        "sub", "email", "name", "preferred_username", "groups",
                        "cognito:groups", "custom:department", "custom:role",
                    ];
                    for claim in &important_claims {
                        if let Some(value) = claims.get(*claim) {
                            debug!("{}: {}", claim, value);
                        }
                    }
                }

                return Ok((tokens.id_token, claims));
            }

            drop(result);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn build_auth_url(&self, state: &str, nonce: &str, code_challenge: &str) -> Result<String> {
        let base_url = if self.provider_domain.starts_with("http://") || self.provider_domain.starts_with("https://") {
            self.provider_domain.clone()
        } else {
            format!("https://{}", self.provider_domain)
        };

        let params = vec![
            ("client_id", self.client_id.as_str()),
            ("response_type", RESPONSE_TYPE),
            ("scope", SCOPES),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge_method", "S256"),
            ("code_challenge", code_challenge),
        ];

        let query_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!("{}{}?{}", base_url, AUTHORIZE_ENDPOINT, query_string))
    }

    async fn exchange_code_for_tokens(&self, code: &str, code_verifier: &str) -> Result<TokenResponse> {
        let base_url = if self.provider_domain.starts_with("http://") || self.provider_domain.starts_with("https://") {
            self.provider_domain.clone()
        } else {
            format!("https://{}", self.provider_domain)
        };

        let token_url = format!("{}{}", base_url, TOKEN_ENDPOINT);

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("code_verifier", code_verifier),
        ];

        let client = reqwest::Client::new();
        let response = client
            .post(&token_url)
            .form(&params)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("Failed to send token request")?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Token exchange failed: {}", error_text);
        }

        let tokens: TokenResponse = response.json().await?;
        Ok(tokens)
    }
}

async fn handle_callback(
    Query(query): Query<CallbackQuery>,
    expected_state: String,
    result: Arc<Mutex<AuthResult>>,
) -> impl IntoResponse {
    debug!("Received callback request");

    let mut auth_result = result.lock().unwrap();

    if query.error.is_some() {
        let description = query.error_description.unwrap_or_else(|| "Unknown error".to_string());
        auth_result.error = Some(description.clone());
        drop(auth_result);

        return Html(format!(
            r#"
            <html>
            <head><title>Authentication</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>Authentication failed</h1>
                <p>Return to your terminal to continue.</p>
            </body>
            </html>
            "#
        ));
    }

    if query.state.as_ref() == Some(&expected_state) && query.code.is_some() {
        auth_result.code = query.code;
        drop(auth_result);

        Html(
            r#"
            <html>
            <head><title>Authentication</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>Authentication successful! You can close this window.</h1>
                <p>Return to your terminal to continue.</p>
            </body>
            </html>
            "#.to_string()
        )
    } else {
        auth_result.error = Some("Invalid state or missing code".to_string());
        drop(auth_result);

        Html(
            r#"
            <html>
            <head><title>Authentication</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>Invalid response</h1>
                <p>Return to your terminal to continue.</p>
            </body>
            </html>
            "#.to_string()
        )
    }
}

fn generate_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..length * 3 / 4).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)[..length].to_string()
}

fn generate_code_verifier() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

fn decode_id_token(token: &str) -> Result<HashMap<String, serde_json::Value>> {
    use jsonwebtoken::{decode, DecodingKey, Validation};

    // Decode without verification (we're just extracting claims)
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false; // Disable audience validation

    let token_data = decode::<HashMap<String, serde_json::Value>>(
        token,
        &DecodingKey::from_secret(&[]),
        &validation,
    )?;

    Ok(token_data.claims)
}
