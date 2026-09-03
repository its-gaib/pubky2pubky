//! Cryptographic identity, discovery, and wire types for Hole Punchky.
//!
//! The rendezvous server can authenticate and route these messages, but it cannot
//! read iroh endpoint addresses. Pubky root keys delegate bounded device signing,
//! HPKE encryption, and dedicated iroh endpoint keys.

mod crypto;
mod descriptor;
mod error;
mod identity;
mod message;
mod v3;

pub use crypto::{
    EncryptedSignal, IrohEndpointAddress, MAX_IROH_DIRECT_ADDRESSES, MAX_IROH_RELAY_URLS,
    SignalHeader, SignalKind, SignalPayload,
};
pub use descriptor::{
    DESCRIPTOR_PATH, RendezvousDescriptor, RendezvousDescriptorClaims, RendezvousEndpoint,
};
pub use error::{ProtocolError, Result};
pub use identity::{
    Authenticated, DeviceCertificate, DeviceCertificateClaims, DeviceCredential, SignedPayload,
    now_seconds,
};
pub use message::{Accept, ClientFrame, ErrorCode, Knock, Registration, Reject, ServerFrame};
pub use v3::{
    V3_DEVICE_CAPABILITIES, V3_DIRECTORY_PATH, V3_IROH_ALPN, V3_IROH_ALPN_TEXT,
    V3_LOCATOR_PATH_PREFIX, V3_MAX_CERTIFICATES, V3_MAX_DIRECTORY_LIFETIME_SECONDS,
    V3_MAX_HANDSHAKE_LIFETIME_SECONDS, V3_MAX_LOCATOR_LIFETIME_SECONDS, V3_MAX_RELAY_URLS,
    V3_PROTOCOL_VERSION, V3AckClaims, V3DeviceCertificate, V3DeviceCertificateClaims,
    V3DeviceCredential, V3DeviceDirectory, V3DeviceDirectoryClaims, V3HelloClaims, V3LocatorClaims,
    V3SignedAck, V3SignedHello, V3SignedLocator, v3_locator_path, v3_random_nonce,
};

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u16 = 2;

/// Data-plane transport identifier advertised by descriptors and rendezvous servers.
pub const IROH_TRANSPORT: &str = "iroh-quic-v1";

/// QUIC ALPN used by Hole Punchky peers.
pub const IROH_ALPN: &[u8] = b"hole-punchky/iroh/2";

/// Maximum accepted clock difference for freshly signed messages.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 120;

/// Longest device delegation accepted by the protocol library.
pub const MAX_CERTIFICATE_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
