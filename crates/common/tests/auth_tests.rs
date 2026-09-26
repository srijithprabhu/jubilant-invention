use common::{AuthError, AuthProvider, JwtManager, User};

fn sample_user(id: &str, provider: AuthProvider) -> User {
    User {
        id: id.to_string(),
        email: format!("{}@example.com", id),
        name: format!("User {}", id),
        avatar_url: Some(format!("https://example.com/avatars/{}.png", id)),
        provider,
        provider_user_id: format!("provider-uid-{}", id),
    }
}

#[test]
fn test_jwt_generation_and_valid_verification() {
    let jwt_manager = JwtManager::new(b"super-secret-test-key-32-bytes-long!", 3600);
    let user = sample_user("user-42", AuthProvider::Google);

    let token = jwt_manager
        .generate_token(&user)
        .expect("JWT generation should succeed for valid user");

    assert!(!token.is_empty(), "Generated token should not be empty");
    assert_eq!(
        token.split('.').count(),
        3,
        "JWT should have 3 segments (header.payload.signature)"
    );

    let claims = jwt_manager
        .verify_token(&token)
        .expect("Valid JWT should decode successfully");

    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.email, user.email);
    assert_eq!(claims.name, user.name);
    assert_eq!(claims.provider, AuthProvider::Google);
    assert!(claims.exp > claims.iat);
}

#[test]
fn test_jwt_tampered_signature_rejection() {
    let jwt_manager_a = JwtManager::new(b"secret-key-alpha-32-bytes-long!!", 3600);
    let jwt_manager_b = JwtManager::new(b"secret-key-beta--32-bytes-long!!", 3600);
    let user = sample_user("user-99", AuthProvider::Facebook);

    let token = jwt_manager_a
        .generate_token(&user)
        .expect("Token generation should succeed");

    // Verifying with different secret key must fail with SignatureInvalid
    let result = jwt_manager_b.verify_token(&token);
    assert!(
        matches!(result, Err(AuthError::SignatureInvalid)),
        "Verification with wrong secret must return SignatureInvalid, got: {:?}",
        result
    );
}

#[test]
fn test_jwt_tampered_payload_rejection() {
    let jwt_manager = JwtManager::new(b"secret-key-gamma-32-bytes-long!", 3600);
    let user = sample_user("user-tamper", AuthProvider::Google);

    let token = jwt_manager
        .generate_token(&user)
        .expect("Token generation should succeed");

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Tamper with payload segment
    let tampered_payload = "eyJzdWIiOiJoYWNrZXIiLCJlbWFpbCI6ImhhY2tAZXZpbC5jb20ifQ";
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let result = jwt_manager.verify_token(&tampered_token);
    assert!(
        result.is_err(),
        "Tampered token must be rejected"
    );
}

#[test]
fn test_jwt_expiration_rejection() {
    // 0 seconds validity ensures immediate expiration
    let jwt_manager = JwtManager::new(b"secret-key-delta-32-bytes-long!", 0);
    let user = sample_user("user-expired", AuthProvider::Google);

    let token = jwt_manager
        .generate_token(&user)
        .expect("Token generation should succeed");

    // Sleep to ensure the Unix timestamp (which has 1-second granularity) elapses past exp
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let result = jwt_manager.verify_token(&token);
    assert!(
        matches!(result, Err(AuthError::ExpiredToken)),
        "Expired token must return ExpiredToken error, got: {:?}",
        result
    );
}

#[test]
fn test_jwt_malformed_string_rejection() {
    let jwt_manager = JwtManager::new(b"secret-key-epsilon-32-bytes-long", 3600);

    assert!(matches!(
        jwt_manager.verify_token("not-a-valid-jwt"),
        Err(AuthError::InvalidToken(_))
    ));
    assert!(matches!(
        jwt_manager.verify_token(""),
        Err(AuthError::InvalidToken(_))
    ));
    assert!(matches!(
        jwt_manager.verify_token("a.b"),
        Err(AuthError::InvalidToken(_))
    ));
}
