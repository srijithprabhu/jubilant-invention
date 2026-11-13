use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use common::{AuthProvider, AuthResponse, JwtManager, OAuthExchangePayload, User};
use http_body_util::BodyExt;
use server::auth_service::{create_auth_router, AppState, MockOAuthService};
use std::sync::Arc;
use tower::ServiceExt;

fn setup_test_app() -> (axum::Router, JwtManager, User, User) {
    let jwt_manager = JwtManager::new(b"test-secret-key-32-bytes-long!!!", 3600);

    let google_user = User {
        id: "user-google-101".to_string(),
        email: "google.user@example.com".to_string(),
        name: "Google Alice".to_string(),
        avatar_url: Some("https://lh3.googleusercontent.com/avatar.jpg".to_string()),
        provider: AuthProvider::Google,
        provider_user_id: "google-oauth2|101".to_string(),
    };

    let facebook_user = User {
        id: "user-facebook-202".to_string(),
        email: "fb.user@example.com".to_string(),
        name: "Facebook Bob".to_string(),
        avatar_url: None,
        provider: AuthProvider::Facebook,
        provider_user_id: "facebook|202".to_string(),
    };

    let google_mock = Arc::new(
        MockOAuthService::new(AuthProvider::Google)
            .with_user("valid-google-auth-code", google_user.clone()),
    );

    let fb_mock = Arc::new(
        MockOAuthService::new(AuthProvider::Facebook)
            .with_user("valid-facebook-auth-code", facebook_user.clone()),
    );

    let state = AppState {
        http_client: reqwest::Client::new(),
        jwt_manager: Arc::new(jwt_manager.clone()),
        google_auth: google_mock,
        facebook_auth: fb_mock,
    };

    let app = create_auth_router(state);
    (app, jwt_manager, google_user, facebook_user)
}

#[tokio::test]
async fn test_google_login_success() {
    let (app, _, expected_user, _) = setup_test_app();

    let payload = OAuthExchangePayload {
        code: "valid-google-auth-code".to_string(),
        redirect_uri: Some("http://localhost:3000/auth/callback".to_string()),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/google")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let auth_res: AuthResponse = serde_json::from_slice(&body_bytes).expect("Valid AuthResponse JSON");

    assert!(!auth_res.session_token.is_empty());
    assert_eq!(auth_res.user, expected_user);
}

#[tokio::test]
async fn test_google_login_invalid_code() {
    let (app, _, _, _) = setup_test_app();

    let payload = OAuthExchangePayload {
        code: "invalid-bogus-code".to_string(),
        redirect_uri: None,
    };

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/google")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert!(
        response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNAUTHORIZED,
        "Invalid auth code should yield 400 or 401, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_facebook_login_success() {
    let (app, _, _, expected_user) = setup_test_app();

    let payload = OAuthExchangePayload {
        code: "valid-facebook-auth-code".to_string(),
        redirect_uri: Some("http://localhost:3000/auth/callback".to_string()),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/facebook")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let auth_res: AuthResponse = serde_json::from_slice(&body_bytes).expect("Valid AuthResponse JSON");

    assert!(!auth_res.session_token.is_empty());
    assert_eq!(auth_res.user, expected_user);
}

#[tokio::test]
async fn test_protected_me_endpoint_with_valid_bearer_token() {
    let (app, jwt_manager, user, _) = setup_test_app();

    // Use jwt_manager to create a valid token
    let token = jwt_manager.generate_token(&user).unwrap();

    let request = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let claims: common::AuthClaims = serde_json::from_slice(&body_bytes).expect("Valid AuthClaims JSON");

    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.email, user.email);
    assert_eq!(claims.provider, AuthProvider::Google);
}

#[tokio::test]
async fn test_protected_me_endpoint_missing_token() {
    let (app, _, _, _) = setup_test_app();

    let request = Request::builder()
        .method("GET")
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_me_endpoint_invalid_token() {
    let (app, _, _, _) = setup_test_app();

    let request = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header(header::AUTHORIZATION, "Bearer totally-invalid-token-string")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
