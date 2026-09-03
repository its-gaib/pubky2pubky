//! Native Hole Punchky client: Pubky discovery, consent rendezvous, and iroh QUIC.

mod discovery;
mod error;
mod peer;
mod sequence;
mod signaling;
mod v3_discovery;
mod v3_peer;

pub use discovery::{
    DescriptorResolver, PubkyResolver, StaticResolver, publish_descriptor, resolve_rendezvous_url,
};
pub use error::{ClientError, Result};
pub use peer::{ConnectionPath, DialOptions, IrohRelayConfig, PathPolicy, Peer};
pub use sequence::{FileSequenceStore, MemorySequenceStore, PublisherSequenceStore, SequenceStore};
pub use signaling::{IncomingKnock, RendezvousClient, RendezvousClientConfig};
pub use v3_discovery::{
    PubkyV3Resolver, ResolvedV3Device, StaticV3Resolver, V3DeviceResolver, V3DiscoveryConfig,
    publish_v3_directory, publish_v3_locator,
};
pub use v3_peer::{IncomingV3, PublicContactDisclosure, V3Client, V3ClientConfig};
