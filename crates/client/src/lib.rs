//! Native Hole Punchky client: Pubky discovery, authenticated rendezvous, and WebRTC.

mod discovery;
mod error;
mod peer;
mod signaling;

pub use discovery::{
    DescriptorResolver, PubkyResolver, StaticResolver, publish_descriptor, resolve_rendezvous_url,
};
pub use error::{ClientError, Result};
pub use peer::{ConnectionPath, DialOptions, IcePolicy, Peer};
pub use signaling::{IncomingKnock, RendezvousClient, RendezvousClientConfig};
