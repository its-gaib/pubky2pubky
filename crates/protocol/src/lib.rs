//! Cryptographic identity, discovery, and wire types for pubky2pubky protocol v1.

mod error;
mod signing;
mod v1;

pub use error::{ProtocolError, Result};
pub use signing::now_seconds;
pub use v1::{
    V1_CURRENTNESS_PATH_PREFIX, V1_DEVICE_RECORD_PATH_PREFIX, V1_IROH_ALPN, V1_IROH_ALPN_TEXT,
    V1_MAX_ACK_BYTES, V1_MAX_CURRENTNESS_LIFETIME_SECONDS, V1_MAX_CURRENTNESS_PROOF_BYTES,
    V1_MAX_DEVICE_CERTIFICATE_LIFETIME_SECONDS, V1_MAX_DEVICE_RECORD_BYTES,
    V1_MAX_GRANT_CAPABILITIES, V1_MAX_GRANT_JWS_BYTES, V1_MAX_GRANT_LIFETIME_SECONDS,
    V1_MAX_HANDSHAKE_LIFETIME_SECONDS, V1_MAX_HELLO_BYTES, V1_MAX_LOCATOR_LIFETIME_SECONDS,
    V1_MAX_RELAY_URLS, V1_PROTOCOL_VERSION, V1_REQUIRED_STORAGE_SCOPE, V1AckClaims,
    V1CurrentnessClaims, V1CurrentnessRole, V1DeviceCertificate, V1DeviceCertificateClaims,
    V1DeviceCredential, V1DeviceCredentialDraft, V1DeviceRecord, V1GrantAuthorization,
    V1HelloClaims, V1LocatorClaims, V1SignedAck, V1SignedCurrentnessProof, V1SignedHello,
    V1SignedLocator, v1_currentness_path, v1_device_record_path, v1_random_challenge,
};

/// Maximum accepted clock difference for freshly signed messages.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 120;

/// Longest device delegation accepted by the protocol library.
pub const MAX_CERTIFICATE_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
