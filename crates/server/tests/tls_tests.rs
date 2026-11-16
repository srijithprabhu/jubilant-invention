use server::tls::{extract_certificate_digest, generate_self_signed_identity, load_identity_from_pem_files};

#[test]
fn test_generate_self_signed_identity() {
    let result = generate_self_signed_identity(&["localhost", "127.0.0.1"]);
    assert!(result.is_ok(), "Failed to generate self-signed identity: {:?}", result.err());

    let info = result.unwrap();
    assert_eq!(info.digest.as_ref().len(), 32, "SHA-256 digest must be 32 bytes");
    assert!(!info.digest_base64.is_empty(), "Base64 digest string should not be empty");

    let extracted = extract_certificate_digest(&info.identity);
    assert!(extracted.is_some(), "Should extract certificate digest from identity");
    assert_eq!(extracted.unwrap(), info.digest, "Extracted digest must match computed digest");
}

#[test]
fn test_tls_identity_digest_bytes() {
    let info = generate_self_signed_identity(&["localhost"]).unwrap();
    let bytes = info.digest_bytes();
    assert_eq!(bytes.len(), 32);
    assert_eq!(&bytes, info.digest.as_ref());
}

#[tokio::test]
async fn test_load_identity_from_pem_files() {
    // Test loading identity from invalid/non-existent files
    let result = load_identity_from_pem_files("non_existent_cert.pem", "non_existent_key.pem").await;
    assert!(result.is_err(), "Loading from non-existent files should return an error");
}
