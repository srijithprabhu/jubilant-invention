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
    pub client: reqwest::Client,
    pub client_id: String,
    pub client_secret: String,
}

impl GoogleOAuthService {
    pub fn new(
        client: reqwest::Client,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            client,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

#[derive(serde::Deserialize)]
struct GoogleOAuthTokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: String,
    picture: Option<String>,
}

#[async_trait]
impl OAuthProviderService for GoogleOAuthService {
    async fn exchange_code(&self, code: &str, redirect_uri: Option<&str>) -> Result<User, AuthError> {
        // TODO (User implementation):
        // Exchange authorization code with Google OAuth2 token endpoint and retrieve user profile.
        const GRANT_TYPE: &str = "authorization_code";
        const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
        let params = [
            ("code", code),
            ("grant_type", GRANT_TYPE),
            ("redirect_uri", redirect_uri.unwrap_or("")),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        let token_response: GoogleOAuthTokenResponse = self.client.post(TOKEN_ENDPOINT)
            .form(&params)
            .send()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?
            .error_for_status()
            .map_err(|err| AuthError::ProviderError(format!("Google token exchange failed: {err}")))?
            .json()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?;
        const USER_INFO: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
        let user_info: GoogleUserInfo = self.client.get(USER_INFO)
            .bearer_auth(token_response.access_token)
            .send()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?
            .error_for_status()
            .map_err(|err| AuthError::ProviderError(format!("Google userinfo request failed: {err}")))?
            .json()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?;

        let user = User {
            id: format!("google-{}", user_info.sub), // or a generated UUID
            email: user_info.email,
            name: user_info.name,
            avatar_url: user_info.picture,
            provider: AuthProvider::Google,
            provider_user_id: user_info.sub,
        };
        Ok(user)
    }
}

pub struct FacebookOAuthService {
    pub client: reqwest::Client,
    pub app_id: String,
    pub app_secret: String,
}

impl FacebookOAuthService {
    pub fn new(
        client: reqwest::Client,
        app_id: impl Into<String>,
        app_secret: impl Into<String>,
    ) -> Self {
        Self {
            client,
            app_id: app_id.into(),
            app_secret: app_secret.into(),
        }
    }
}

#[derive(serde::Deserialize)]
struct FacebookAccessTokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct FacebookPictureData {
    url: String,
}

#[derive(serde::Deserialize)]
struct FacebookPicture {
    data: FacebookPictureData,
}

#[derive(serde::Deserialize)]
struct FacebookUserProfile {
    id: String,
    name: String,
    email: Option<String>,
    picture: Option<FacebookPicture>,
}

#[async_trait]
impl OAuthProviderService for FacebookOAuthService {
    async fn exchange_code(&self, code: &str, redirect_uri: Option<&str>) -> Result<User, AuthError> {
        // Exchange authorization code with Facebook Graph API and retrieve user profile.
        const TOKEN_ENDPOINT: &str = "https://graph.facebook.com/v19.0/oauth/access_token";
        let params = [
            ("code", code),
            ("redirect_uri", redirect_uri.unwrap_or("")),
            ("client_id", &self.app_id),
            ("client_secret", &self.app_secret),
        ];
        let response: FacebookAccessTokenResponse = self.client.post(TOKEN_ENDPOINT)
            .form(&params)
            .send()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?
            .error_for_status()
            .map_err(|err| AuthError::ProviderError(format!("Facebook token exchange failed: {err}")))?
            .json()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?;
        let access_token = response.access_token;
        const USER_ENDPOINT: &str = "https://graph.facebook.com/v19.0/me?fields=id,name,email,picture";
        let user_response: FacebookUserProfile = self.client.get(USER_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?
            .error_for_status()
            .map_err(|err| AuthError::ProviderError(format!("Facebook user profile retrieval failed: {err}")))?
            .json()
            .await
            .map_err(|err| AuthError::ProviderError(err.to_string()))?;
        let avatar_url = user_response.picture.map(|p| p.data.url);
        let user = User {
            id: format!("facebook-{}", user_response.id),
            name: user_response.name,
            email: user_response.email.unwrap_or_default(),
            avatar_url,
            provider: AuthProvider::Facebook,
            provider_user_id: user_response.id,
        };
        Ok(user)
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
    pub http_client: reqwest::Client,
    pub jwt_manager: Arc<JwtManager>,
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
