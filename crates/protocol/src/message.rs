use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Authenticated, SignedPayload};

/// ICE server configuration supplied by the rendezvous service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    /// STUN or TURN URLs.
    pub urls: Vec<String>,
    /// Optional TURN username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional TURN credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

macro_rules! impl_signed_payload {
    ($type:ty, $domain:literal) => {
        impl SignedPayload for $type {
            const DOMAIN: &'static str = $domain;

            fn version(&self) -> u16 {
                self.version
            }
            fn identity(&self) -> &str {
                &self.identity
            }
            fn device_id(&self) -> &str {
                &self.device_id
            }
            fn issued_at(&self) -> u64 {
                self.issued_at
            }
            fn expires_at(&self) -> u64 {
                self.expires_at
            }
        }
    };
}

/// Authenticate one WebSocket connection as a delegated device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// Protocol version.
    pub version: u16,
    /// Pubky identity.
    pub identity: String,
    /// Delegated device id.
    pub device_id: String,
    /// Random base64url nonce, unique for this connection attempt.
    pub nonce: String,
    /// Beginning of message validity.
    pub issued_at: u64,
    /// End of message validity.
    pub expires_at: u64,
}
impl_signed_payload!(Registration, "hole-punchky/register/v1");

/// Ask an identity's online devices for permission to negotiate a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Knock {
    /// Protocol version.
    pub version: u16,
    /// Caller Pubky identity.
    pub identity: String,
    /// Caller device id.
    pub device_id: String,
    /// Caller-selected random session id.
    pub session_id: Uuid,
    /// Target Pubky identity.
    pub target_identity: String,
    /// Optional exact target device; otherwise every online device receives the knock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<String>,
    /// Application protocol requested over the data channel.
    pub application: String,
    /// Opaque, non-secret caller metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Beginning of message validity.
    pub issued_at: u64,
    /// End of message validity.
    pub expires_at: u64,
}
impl_signed_payload!(Knock, "hole-punchky/knock/v1");

/// Accept a pending knock and bind the session to this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accept {
    /// Protocol version.
    pub version: u16,
    /// Responder Pubky identity.
    pub identity: String,
    /// Responder device id.
    pub device_id: String,
    /// Accepted session id.
    pub session_id: Uuid,
    /// Initiator Pubky identity.
    pub target_identity: String,
    /// Beginning of message validity.
    pub issued_at: u64,
    /// End of message validity.
    pub expires_at: u64,
}
impl_signed_payload!(Accept, "hole-punchky/accept/v1");

/// Decline a pending knock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reject {
    /// Protocol version.
    pub version: u16,
    /// Responder Pubky identity.
    pub identity: String,
    /// Responder device id.
    pub device_id: String,
    /// Rejected session id.
    pub session_id: Uuid,
    /// Initiator Pubky identity.
    pub target_identity: String,
    /// Short machine-readable or user-facing reason.
    pub reason: String,
    /// Beginning of message validity.
    pub issued_at: u64,
    /// End of message validity.
    pub expires_at: u64,
}
impl_signed_payload!(Reject, "hole-punchky/reject/v1");

/// Ask for session-scoped, short-lived TURN REST credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnRequest {
    /// Protocol version.
    pub version: u16,
    /// Requesting Pubky identity.
    pub identity: String,
    /// Requesting device id.
    pub device_id: String,
    /// Accepted session requiring relay service.
    pub session_id: Uuid,
    /// Beginning of message validity.
    pub issued_at: u64,
    /// End of message validity.
    pub expires_at: u64,
}
impl_signed_payload!(TurnRequest, "hole-punchky/turn-request/v1");

/// A short-lived TURN credential following coturn's REST convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCredentials {
    /// Accepted rendezvous session these credentials were minted for.
    pub session_id: Uuid,
    /// TURN URLs usable with this credential.
    pub urls: Vec<String>,
    /// Time-qualified TURN username.
    pub username: String,
    /// HMAC-derived password.
    pub credential: String,
    /// Credential expiry in Unix seconds.
    pub expires_at: u64,
}

/// Stable machine-readable server errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Frame was malformed or violates protocol rules.
    BadRequest,
    /// Signature, delegation, or connection identity was invalid.
    Unauthorized,
    /// A requested identity has no matching online device.
    Unavailable,
    /// A session does not exist or already ended.
    SessionNotFound,
    /// A different responder already accepted the session.
    SessionClaimed,
    /// Per-identity or per-address allowance was exhausted.
    RateLimited,
    /// A message exceeds the configured bound.
    TooLarge,
    /// TURN fallback is not configured.
    TurnUnavailable,
    /// Unexpected internal failure.
    Internal,
}

/// Frames sent from a device to a rendezvous WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Authenticate the connection. This must be the first frame.
    Register(Authenticated<Registration>),
    /// Start a consent-first connection attempt.
    Knock(Authenticated<Knock>),
    /// Accept and bind a pending session.
    Accept(Authenticated<Accept>),
    /// Decline a pending session.
    Reject(Authenticated<Reject>),
    /// Forward opaque encrypted WebRTC signaling.
    Signal(crate::EncryptedSignal),
    /// Obtain a relay credential after consent.
    RequestTurnCredentials(Authenticated<TurnRequest>),
    /// Application heartbeat.
    Ping {
        /// Opaque value echoed by the server.
        nonce: String,
    },
}

/// Frames sent from a rendezvous service to a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ServerFrame {
    /// Registration succeeded.
    Registered {
        /// Server-assigned connection id.
        connection_id: Uuid,
        /// Public STUN servers safe to provide before session consent.
        ice_servers: Vec<IceServer>,
        /// Maximum negotiated-session lifetime.
        session_ttl_seconds: u64,
    },
    /// A caller requests a connection.
    Knock(Authenticated<Knock>),
    /// The target accepted the session.
    Accepted(Authenticated<Accept>),
    /// A target declined the session.
    Rejected(Authenticated<Reject>),
    /// An opaque encrypted WebRTC signal from the bound peer.
    Signal(crate::EncryptedSignal),
    /// Short-lived relay credentials.
    TurnCredentials(TurnCredentials),
    /// Application heartbeat response.
    Pong {
        /// Opaque value supplied by the client.
        nonce: String,
    },
    /// Recoverable or terminal protocol error.
    Error {
        /// Machine-readable category.
        code: ErrorCode,
        /// Human-readable safe detail.
        message: String,
        /// Related session when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<Uuid>,
    },
}
