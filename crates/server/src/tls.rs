use std::error::Error;
use wtransport::tls::{Identity, Sha256Digest};

/// Contains TLS identity details along with its computed SHA-256 certificate digest
/// for WebTransport browser client configuration (`serverCertificateHashes`).
pub struct TlsIdentityInfo {
    pub identity: Identity,
    pub digest: Sha256Digest,
    pub digest_base64: String,
}

/// Generates a self-signed TLS identity for WebTransport testing / local development.
///
/// # Arguments
/// * `san` - Subject Alternative Names (e.g., `&["localhost", "127.0.0.1"]`)
///
/// # Returns
/// `TlsIdentityInfo` containing the `Identity`, `Sha256Digest`, and base64 digest string.
pub fn generate_self_signed_identity<I, S>(san: I) -> Result<TlsIdentityInfo, Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let _ = san;
    todo!("Generate self-signed TLS identity and compute its SHA-256 digest")
}

/// Extracts the SHA-256 digest from an existing `Identity`'s leaf certificate.
pub fn extract_certificate_digest(identity: &Identity) -> Option<Sha256Digest> {
    let _ = identity;
    todo!("Extract the leaf certificate SHA-256 digest from the identity")
}
