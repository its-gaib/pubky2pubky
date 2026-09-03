use hole_punchky_protocol::{ErrorCode, ProtocolError};
use uuid::Uuid;

/// Result returned by client operations.
pub type Result<T> = std::result::Result<T, ClientError>;

/// A discovery, rendezvous, or iroh transport failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A signed or encrypted protocol object was invalid.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// The rendezvous URL violates transport policy.
    #[error("insecure or invalid rendezvous URL")]
    InvalidRendezvousUrl,
    /// An iroh relay URL violates transport policy.
    #[error("insecure or invalid iroh relay URL")]
    InvalidRelayUrl,
    /// The rendezvous connection failed.
    #[error("rendezvous connection failed: {0}")]
    Rendezvous(String),
    /// The rendezvous connection ended.
    #[error("rendezvous connection closed: {0}")]
    RendezvousClosed(String),
    /// The rendezvous service rejected an operation.
    #[error("rendezvous error {code:?}: {message}")]
    Server {
        /// Stable error category.
        code: ErrorCode,
        /// Safe server detail.
        message: String,
        /// Related session, when provided.
        session_id: Option<Uuid>,
    },
    /// The peer declined a knock.
    #[error("peer rejected connection: {0}")]
    Rejected(String),
    /// A bounded operation did not finish in time.
    #[error("timed out while {0}")]
    Timeout(&'static str),
    /// Pubky storage or discovery failed.
    #[error("Pubky discovery failed: {0}")]
    Discovery(String),
    /// Iroh endpoint, relay, QUIC, or stream operation failed.
    #[error("iroh transport failed: {0}")]
    Iroh(String),
    /// The authenticated peer stream was closed.
    #[error("peer stream closed")]
    ChannelClosed,
    /// The received peer identity/session did not match the requested one.
    #[error("unexpected peer or session")]
    UnexpectedPeer,
}
