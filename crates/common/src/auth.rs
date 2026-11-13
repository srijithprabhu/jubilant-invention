use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use jsonwebtoken::errors::ErrorKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthProvider {
    Google,
    Facebook,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub provider: AuthProvider,
    pub provider_user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub provider: AuthProvider,
    pub exp: usize,
    pub iat: usize,
}

impl AuthClaims {
    pub fn from_user(user: &User, duration_secs: u64) -> Self {
        let iat = chrono::Utc::now().timestamp() as usize;
        let exp = iat + duration_secs as usize;
        Self {
            sub: user.id.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            provider: user.provider,
            iat,
            exp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthExchangePayload {
    pub code: String,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub session_token: String,
    pub user: User,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("Invalid token format or claims: {0}")]
    InvalidToken(String),
    #[error("Token has expired")]
    ExpiredToken,
    #[error("Invalid token signature")]
    SignatureInvalid,
    #[error("Missing bearer token")]
    MissingToken,
    #[error("OAuth provider error: {0}")]
    ProviderError(String),
    #[error("Internal auth error: {0}")]
    Internal(String),
}

#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    pub duration_secs: u64,
}

impl JwtManager {
    pub fn new(secret: impl AsRef<[u8]>, duration_secs: u64) -> Self {
        let secret_bytes = secret.as_ref();
        Self {
            encoding_key: EncodingKey::from_secret(secret_bytes),
            decoding_key: DecodingKey::from_secret(secret_bytes),
            duration_secs,
        }
    }

    pub fn generate_token(&self, user: &User) -> Result<String, AuthError> {
        let auth_claims = AuthClaims::from_user(user, self.duration_secs);
        jsonwebtoken::encode(&Header::default(), &auth_claims, &self.encoding_key)
            .map_err(|err| AuthError::Internal(format!("Error encoding token: {err}")))
    }

    pub fn verify_token(&self, token: &str) -> Result<AuthClaims, AuthError> {
        let mut validation = Validation::default();
        validation.leeway = 0;

        jsonwebtoken::decode::<AuthClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                ErrorKind::InvalidSignature => AuthError::SignatureInvalid,
                _ => AuthError::InvalidToken(err.to_string()),
            })
    }
}
