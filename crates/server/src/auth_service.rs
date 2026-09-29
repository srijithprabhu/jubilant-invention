use std::net::ToSocketAddrs;
use std::sync::Arc;
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, State},
    http::{request::Parts, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
    Json, Router,
};
use common::{
    AuthClaims, AuthError, AuthProvider, AuthResponse, JwtManager, OAuthExchangePayload, User,
};

#[async_trait]
pub trait OAuthProviderService: Send + Sync {
    async fn exchange_code(&self, code: &str, redirect_uri: Option<&str>) -> Result<User, AuthError>;
}

pub struct GoogleOAuthService {
    pub client_id: String,
    pub client_secret: String,
}

#[async_trait]
impl OAuthProviderService for GoogleOAuthService {
    async fn exchange_code(&self, _code: &str, _redirect_uri: Option<&str>) -> Result<User, AuthError> {
        // TODO (User implementation):
        // Exchange authorization code with Google OAuth2 token endpoint and retrieve user profile.
        todo!("Implement Google OAuth2 code exchange")
    }
}

pub struct FacebookOAuthService {
    pub app_id: String,
    pub app_secret: String,
}

#[async_trait]
impl OAuthProviderService for FacebookOAuthService {
    async fn exchange_code(&self, _code: &str, _redirect_uri: Option<&str>) -> Result<User, AuthError> {
        // TODO (User implementation):
        // Exchange authorization code with Facebook Graph API and retrieve user profile.
        todo!("Implement Facebook OAuth2 code exchange")
    }
}

#[derive(Clone)]
pub struct MockOAuthService {
    pub provider: AuthProvider,
    pub mock_users: std::collections::HashMap<String, User>,
}

impl MockOAuthService {
    pub fn new(provider: AuthProvider) -> Self {
        Self {
            provider,
            mock_users: std::collections::HashMap::new(),
        }
    }

    pub fn with_user(mut self, code: &str, user: User) -> Self {
        self.mock_users.insert(code.to_string(), user);
        self
    }
}

#[async_trait]
impl OAuthProviderService for MockOAuthService {
    async fn exchange_code(&self, code: &str, _redirect_uri: Option<&str>) -> Result<User, AuthError> {
        self.mock_users
            .get(code)
            .cloned()
            .ok_or_else(|| AuthError::ProviderError(format!("Invalid auth code: {}", code)))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub jwt_manager: JwtManager,
    pub google_auth: Arc<dyn OAuthProviderService>,
    pub facebook_auth: Arc<dyn OAuthProviderService>,
}

pub struct AuthUser(pub AuthClaims);

pub struct ApiError(pub StatusCode, pub String);

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|val| val.to_str().ok())
            .ok_or_else(|| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "Missing authorization header".to_string(),
                )
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "Invalid authorization scheme".to_string(),
                )
            })?;

        let app_state = AppState::from_ref(state);
        let claims = app_state
            .jwt_manager
            .verify_token(token)
            .map_err(|err| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid token: {err}"),
                )
            })?;

        Ok(AuthUser(claims))
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.0,
            Json(serde_json::json!({ "error": self.1 })),
        )
            .into_response()
    }
}

async fn exchange_and_issue_token(
    provider: &dyn OAuthProviderService,
    jwt_manager: &JwtManager,
    payload: OAuthExchangePayload,
) -> Result<Json<AuthResponse>, ApiError> {
    let user = provider
        .exchange_code(&payload.code, payload.redirect_uri.as_deref())
        .await
        .map_err(|err| {
            ApiError(
                StatusCode::BAD_REQUEST,
                err.to_string(),
            )
        })?;

    let session_token = jwt_manager
        .generate_token(&user)
        .map_err(|err| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            )
        })?;

    Ok(Json(AuthResponse { session_token, user }))
}

pub async fn handle_google_login(
    State(state): State<AppState>,
    Json(payload): Json<OAuthExchangePayload>,
) -> Result<Json<AuthResponse>, ApiError> {
    exchange_and_issue_token(state.google_auth.as_ref(), &state.jwt_manager, payload).await
}

pub async fn handle_facebook_login(
    State(state): State<AppState>,
    Json(payload): Json<OAuthExchangePayload>,
) -> Result<Json<AuthResponse>, ApiError> {
    exchange_and_issue_token(state.facebook_auth.as_ref(), &state.jwt_manager, payload).await
}

pub async fn handle_me(auth_user: AuthUser) -> Json<AuthClaims> {
    Json(auth_user.0)
}

pub fn create_auth_router(state: AppState) -> Router {
    Router::new()
        .route("/api/auth/google", post(handle_google_login))
        .route("/api/auth/facebook", post(handle_facebook_login))
        .route("/api/me", get(handle_me))
        .with_state(state)
}
