//! Protocol errors.

/// Result returned by protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// An invalid or unauthentic Hole Punchky protocol object.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// JSON could not be encoded or decoded.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A key or signature was not valid.
    #[error("invalid {0}")]
    InvalidEncoding(&'static str),
    /// A cryptographic signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// An object uses an unsupported protocol version.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    /// A signed object is not yet valid.
    #[error("object is not yet valid")]
    NotYetValid,
    /// A signed object has expired.
    #[error("object has expired")]
    Expired,
    /// A delegation lasts longer than policy permits.
    #[error("device certificate lifetime is too long")]
    CertificateLifetime,
    /// A required capability was not delegated.
    #[error("device lacks capability {0}")]
    MissingCapability(String),
    /// The claimed root identity does not match the expected identity.
    #[error("identity mismatch")]
    IdentityMismatch,
    /// The claimed device identifier does not match the connection.
    #[error("device mismatch")]
    DeviceMismatch,
    /// The signed message has an invalid time window.
    #[error("invalid message time window")]
    InvalidTimeWindow,
    /// HPKE encryption or decryption failed.
    #[error("HPKE operation failed")]
    Hpke,
}
