use pubky2pubky_protocol::ProtocolError;

/// Result returned by client operations.
pub type Result<T> = std::result::Result<T, ClientError>;

/// A discovery, state, or iroh transport failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A signed or encrypted protocol object was invalid.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// An iroh relay URL violates transport policy.
    #[error("insecure or invalid iroh relay URL")]
    InvalidRelayUrl,
    /// A bounded operation did not finish in time.
    #[error("timed out while {0}")]
    Timeout(&'static str),
    /// Pubky storage or discovery failed.
    #[error("Pubky discovery failed: {0}")]
    Discovery(String),
    /// Persistent anti-rollback state could not be validated or updated.
    #[error("anti-rollback state failed: {0}")]
    State(String),
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
