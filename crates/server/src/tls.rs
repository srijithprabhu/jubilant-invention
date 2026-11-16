use std::error::Error;
use std::path::Path;
use base64::Engine;
use wtransport::tls::{Identity, Sha256Digest};

/// Contains TLS identity details along with its computed SHA-256 certificate digest
/// for WebTransport browser client configuration (`serverCertificateHashes`).
pub struct TlsIdentityInfo {
    pub identity: Identity,
    pub digest: Sha256Digest,
    pub digest_base64: String,
}

impl TlsIdentityInfo {
    /// Returns the raw 32-byte SHA-256 certificate digest.
    pub fn digest_bytes(&self) -> [u8; 32] {
        *self.digest.as_ref()
    }

    pub fn digest_hex(&self) -> String { self.digest.fmt(wtransport::tls::Sha256DigestFmt::DottedHex) }
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
    let identity = Identity::self_signed(san)?;
    create_tls_identity_info(identity)
}

/// Loads a TLS identity from PEM-encoded certificate and private key files.
///
/// # Arguments
/// * `cert_path` - Path to the certificate chain PEM file
/// * `key_path` - Path to the private key PEM file
pub async fn load_identity_from_pem_files<P, Q>(
    cert_path: P,
    key_path: Q,
) -> Result<TlsIdentityInfo, Box<dyn Error + Send + Sync>>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let identity = Identity::load_pemfiles(cert_path, key_path).await?;
    create_tls_identity_info(identity)
}


fn create_tls_identity_info(identity: Identity) -> Result<TlsIdentityInfo, Box<dyn Error + Send + Sync>> {
    let digest = extract_certificate_digest(&identity)
        .ok_or("TLS identity contains an empty certificate chain")?;
    let digest_base64 = base64::prelude::BASE64_STANDARD.encode(digest.as_ref());
    Ok(TlsIdentityInfo {
        identity,
        digest,
        digest_base64,
    })
}

/// Extracts the SHA-256 digest from an existing `Identity`'s leaf certificate.
pub fn extract_certificate_digest(identity: &Identity) -> Option<Sha256Digest> {
    identity.certificate_chain().as_slice().first().map(|cert| cert.hash())
}
