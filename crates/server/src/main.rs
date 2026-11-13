use common::JwtManager;
use server::auth_service::{create_auth_router, AppState, GoogleOAuthService, FacebookOAuthService};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-development-jwt-secret-key-32-bytes".to_string());
    let jwt_manager = JwtManager::new(jwt_secret.as_bytes(), 86400);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build reqwest client");

    let google_client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let google_client_secret = std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
    let google_auth = Arc::new(GoogleOAuthService::new(
        http_client.clone(),
        google_client_id,
        google_client_secret,
    ));

    let facebook_app_id = std::env::var("FACEBOOK_APP_ID").unwrap_or_default();
    let facebook_app_secret = std::env::var("FACEBOOK_APP_SECRET").unwrap_or_default();
    let facebook_auth = Arc::new(FacebookOAuthService::new(
        http_client.clone(),
        facebook_app_id,
        facebook_app_secret,
    ));

    let state = AppState {
        http_client,
        jwt_manager: Arc::new(jwt_manager),
        google_auth,
        facebook_auth,
    };

    let app = create_auth_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Server listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}
