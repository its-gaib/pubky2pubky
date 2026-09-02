//! Cryptographic identity, discovery, and wire types for Hole Punchky.
//!
//! The rendezvous server can authenticate and route these messages, but it cannot
//! read WebRTC descriptions or ICE candidates. Pubky root keys delegate a bounded
//! device signing key and a separate HPKE encryption key.

mod crypto;
mod descriptor;
mod error;
mod identity;
mod message;

pub use crypto::{EncryptedSignal, SignalHeader, SignalKind, SignalPayload};
pub use descriptor::{
    DESCRIPTOR_PATH, RendezvousDescriptor, RendezvousDescriptorClaims, RendezvousEndpoint,
};
pub use error::{ProtocolError, Result};
pub use identity::{
    Authenticated, DeviceCertificate, DeviceCertificateClaims, DeviceCredential, SignedPayload,
    now_seconds,
};
pub use message::{
    Accept, ClientFrame, ErrorCode, IceServer, Knock, Registration, Reject, ServerFrame,
    TurnCredentials, TurnRequest,
};

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted clock difference for freshly signed messages.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 120;

/// Longest device delegation accepted by the protocol library.
pub const MAX_CERTIFICATE_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
