//! Native Hole Punchky client: Pubky discovery, consent rendezvous, and iroh QUIC.

mod discovery;
mod error;
mod peer;
mod signaling;

pub use discovery::{
    DescriptorResolver, PubkyResolver, StaticResolver, publish_descriptor, resolve_rendezvous_url,
};
pub use error::{ClientError, Result};
pub use peer::{ConnectionPath, DialOptions, IrohRelayConfig, PathPolicy, Peer};
pub use signaling::{IncomingKnock, RendezvousClient, RendezvousClientConfig};
