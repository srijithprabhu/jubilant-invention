use std::sync::Arc;
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, State},
    http::{request::Parts, StatusCode},
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

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 1. Extract `Authorization` header from `parts.headers`.
        //    If missing -> return 401 Unauthorized with json error `{"error": "Missing authorization header"}`.
        // 2. Validate format: must start with "Bearer ".
        //    If invalid format -> return 401 Unauthorized with json error `{"error": "Invalid authorization scheme"}`.
        // 3. Extract token slice and retrieve AppState using `AppState::from_ref(state)`.
        // 4. Verify token via `app_state.jwt_manager.verify_token(token)`.
        // 5. If valid -> return `Ok(AuthUser(claims))`.
        //    If expired/invalid -> return 401 Unauthorized with corresponding error message.
        let auth_header = parts.headers.get("Authorization");
        if auth_header.is_none() {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Missing authorization header"}))));
        }
        let auth_header = auth_header.unwrap().to_str().unwrap();
        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid authorization scheme"}))));
        }
        let token = &auth_header["Bearer ".len()..];
        let app_state = AppState::from_ref(state);
        let valid = app_state.jwt_manager.verify_token(token);
        match valid {
            Ok(claims) => Ok(AuthUser(claims)),
            Err(err) => Err(
                (StatusCode::UNAUTHORIZED,
                 Json(serde_json::json!({"error": format!("Invalid token: {}", err)})))
            )
        }
    }
}

pub async fn handle_google_login(
    State(state): State<AppState>,
    Json(payload): Json<OAuthExchangePayload>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // TODO (User implementation):
    // 1. Exchange code via `state.google_auth.exchange_code(&payload.code, payload.redirect_uri.as_deref()).await`.
    // 2. On error -> return 400 Bad Request or 401 with JSON error description.
    // 3. On success -> generate session token via `state.jwt_manager.generate_token(&user)`.
    // 4. Return `Json(AuthResponse { session_token, user })`.
    let user = state
        .google_auth
        .exchange_code(&payload.code, payload.redirect_uri.as_deref())
        .await
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
        })?;

    let session_token = state
        .jwt_manager
        .generate_token(&user)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
        })?;

    Ok(Json(AuthResponse {
        session_token,
        user,
    }))
}

pub async fn handle_facebook_login(
    State(state): State<AppState>,
    Json(payload): Json<OAuthExchangePayload>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // TODO (User implementation):
    // 1. Exchange code via `state.facebook_auth.exchange_code(&payload.code, payload.redirect_uri.as_deref()).await`.
    // 2. On error -> return 400 Bad Request or 401 with JSON error description.
    // 3. On success -> generate session token via `state.jwt_manager.generate_token(&user)`.
    // 4. Return `Json(AuthResponse { session_token, user })`.
    let user = state
        .facebook_auth
        .exchange_code(&payload.code, payload.redirect_uri.as_deref())
        .await
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
        })?;

    let session_token = state
        .jwt_manager
        .generate_token(&user)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
        })?;

    Ok(Json(AuthResponse {
        session_token,
        user,
    }))
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
