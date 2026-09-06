//! Pubky discovery and authenticated iroh QUIC, including relay-only browser support for v4.

#[cfg(not(target_arch = "wasm32"))]
mod discovery;
mod error;
mod peer;
mod sequence;
#[cfg(not(target_arch = "wasm32"))]
mod signaling;
mod v3_discovery;
mod v3_peer;
mod v4_discovery;
mod v4_peer;

#[cfg(not(target_arch = "wasm32"))]
pub use discovery::{
    DescriptorResolver, PubkyResolver, StaticResolver, publish_descriptor, resolve_rendezvous_url,
};
pub use error::{ClientError, Result};
pub use peer::{ConnectionPath, DialOptions, IrohRelayConfig, PathPolicy, Peer};
#[cfg(not(target_arch = "wasm32"))]
pub use sequence::FileSequenceStore;
pub use sequence::{
    AuthenticatedSequenceObservation, MemorySequenceStore, PublisherSequenceStore, SequenceStore,
};
#[cfg(not(target_arch = "wasm32"))]
pub use signaling::{IncomingKnock, RendezvousClient, RendezvousClientConfig};
pub use v3_discovery::{
    PubkyV3Resolver, ResolvedV3Device, StaticV3Resolver, V3DeviceResolver, V3DiscoveryConfig,
    publish_v3_directory, publish_v3_locator,
};
pub use v3_peer::{IncomingV3, PublicContactDisclosure, V3Client, V3ClientConfig};
pub use v4_discovery::{
    PubkyV4Resolver, ResolvedV4Device, StaticV4Resolver, V4_MAX_DEVICES, V4DeviceResolver,
    V4DiscoveryConfig, delete_v4_currentness_proof, delete_v4_device_record,
    publish_v4_currentness_proof, publish_v4_device_record,
};
pub use v4_peer::{IncomingV4, V4Client, V4ClientConfig};
