//! Pubky discovery and authenticated iroh QUIC, including relay-only browser support for v3.

#[cfg(not(target_arch = "wasm32"))]
mod discovery;
mod error;
mod peer;
mod sequence;
#[cfg(not(target_arch = "wasm32"))]
mod signaling;
mod v3_discovery;
mod v3_peer;

#[cfg(not(target_arch = "wasm32"))]
pub use discovery::{
    DescriptorResolver, PubkyResolver, StaticResolver, publish_descriptor, resolve_rendezvous_url,
};
pub use error::{ClientError, Result};
pub use peer::{ConnectionPath, DialOptions, IrohRelayConfig, PathPolicy, Peer};
#[cfg(not(target_arch = "wasm32"))]
pub use sequence::FileSequenceStore;
pub use sequence::{MemorySequenceStore, PublisherSequenceStore, SequenceStore};
#[cfg(not(target_arch = "wasm32"))]
pub use signaling::{IncomingKnock, RendezvousClient, RendezvousClientConfig};
pub use v3_discovery::{
    PubkyV3Resolver, ResolvedV3Device, StaticV3Resolver, V3DeviceResolver, V3DiscoveryConfig,
    publish_v3_directory, publish_v3_locator,
};
pub use v3_peer::{IncomingV3, PublicContactDisclosure, V3Client, V3ClientConfig};
