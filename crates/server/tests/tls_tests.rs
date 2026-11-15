use server::tls::{extract_certificate_digest, generate_self_signed_identity};

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
