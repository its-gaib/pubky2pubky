//! Pubky discovery and authenticated iroh QUIC for pubky2pubky protocol v1.

mod error;
mod peer;
mod sequence;
mod v1_discovery;
mod v1_peer;

pub use error::{ClientError, Result};
pub use peer::{ConnectionPath, IrohRelayConfig, PathPolicy, Peer, PublicContactDisclosure};
#[cfg(not(target_arch = "wasm32"))]
pub use sequence::FileSequenceStore;
pub use sequence::{
    AuthenticatedSequenceObservation, MemorySequenceStore, PublisherSequenceStore, SequenceStore,
};
pub use v1_discovery::{
    PubkyV1Resolver, ResolvedV1Device, StaticV1Resolver, V1_MAX_DEVICES, V1DeviceResolver,
    V1DiscoveryConfig, delete_v1_currentness_proof, delete_v1_device_record,
    publish_v1_currentness_proof, publish_v1_device_record,
};
pub use v1_peer::{IncomingV1, V1Client, V1ClientConfig};
