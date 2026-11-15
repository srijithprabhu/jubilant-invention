use std::error::Error;
use wtransport::tls::{Identity, Sha256Digest, Sha256DigestFmt};

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
    let identity = Identity::self_signed(san)?;
    let digest = identity.certificate_chain().as_slice()[0].hash();
    let digest_base64 = digest.fmt(Sha256DigestFmt::DottedHex);
    Ok(TlsIdentityInfo {
        identity,
        digest,
        digest_base64,
    })
}

/// Extracts the SHA-256 digest from an existing `Identity`'s leaf certificate.
pub fn extract_certificate_digest(identity: &Identity) -> Option<Sha256Digest> {
    Some(identity.certificate_chain().as_slice()[0].hash())
}
