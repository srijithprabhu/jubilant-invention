use std::error;
use std::ops::Add;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionToken {
    pub token: String,
    pub expires_at: i64,
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
    pub secret: Vec<u8>,
    pub duration_secs: u64,
}

impl JwtManager {
    pub fn new(secret: impl Into<Vec<u8>>, duration_secs: u64) -> Self {
        Self {
            secret: secret.into(),
            duration_secs,
        }
    }

    /// Generates a signed JWT for the specified User identity with `duration_secs` validity.
    pub fn generate_token(&self, _user: &User) -> Result<String, AuthError> {
        // TODO (User implementation):
        // 1. Calculate current unix timestamp and expiration timestamp using `chrono::Utc::now()`.
        // 2. Construct `AuthClaims` with `sub` = user.id, `email`, `name`, `provider`, `iat`, and `exp`.
        // 3. Encode the claims using `jsonwebtoken::encode` with `Header::default()` and `EncodingKey::from_secret(&self.secret)`.
        // 4. Map jsonwebtoken errors to `AuthError`.
        let iat = chrono::Utc::now();
        let exp = iat.add(chrono::Duration::seconds(self.duration_secs as i64));
        let auth_claims = AuthClaims {
            sub: _user.id.clone(),
            email: _user.email.clone(),
            name: _user.name.clone(),
            provider: _user.provider.clone(),
            iat: iat.timestamp() as usize,
            exp: exp.timestamp() as usize,
        };
        let token = jsonwebtoken::encode(
            &Header::default(),
            &auth_claims,
            &EncodingKey::from_secret(&self.secret)).unwrap();
        Ok(token)
    }

    /// Verifies and decodes a signed JWT, returning the decoded `AuthClaims`.
    pub fn verify_token(&self, _token: &str) -> Result<AuthClaims, AuthError> {
        // TODO (User implementation):
        // 1. Build a `Validation::default()`.
        // 2. Decode the token using `jsonwebtoken::decode::<AuthClaims>` with `DecodingKey::from_secret(&self.secret)`.
        // 3. Handle `jsonwebtoken::errors::ErrorKind::ExpiredSignature` -> `AuthError::ExpiredToken`.
        // 4. Handle `ErrorKind::InvalidSignature` -> `AuthError::SignatureInvalid`.
        // 5. Handle other errors -> `AuthError::InvalidToken`.
        let mut validation = Validation::default();
        validation.leeway = 0;
        let message = jsonwebtoken::decode::<AuthClaims>(
            _token,
            &DecodingKey::from_secret(&self.secret),
            &validation);
        match message {
            Ok(claims) => Ok(claims.claims),
            Err(err) => {
                Err(match err.kind() {
                    ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                    ErrorKind::InvalidSignature => AuthError::SignatureInvalid,
                    _ => AuthError::InvalidToken(_token.to_string())
                })
            }
        }
    }
}
