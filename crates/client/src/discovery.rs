use std::{collections::HashMap, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use hole_punchky_protocol::{DESCRIPTOR_PATH, RendezvousDescriptor, now_seconds};
use pubky::{Pubky, PubkySession};
use tokio::sync::RwLock;
use url::Url;

use crate::{ClientError, Result};

/// Resolve a root-signed Hole Punchky descriptor for a Pubky identity.
#[async_trait]
pub trait DescriptorResolver: Send + Sync {
    /// Fetch and validate the current descriptor.
    async fn resolve(&self, identity: &str) -> Result<RendezvousDescriptor>;
}

/// Descriptor resolver backed by Pubky public storage.
#[derive(Clone)]
pub struct PubkyResolver {
    pubky: Pubky,
    allow_insecure_local: bool,
}

impl PubkyResolver {
    /// Use the supplied Pubky facade (mainnet or a configured testnet).
    #[must_use]
    pub const fn new(pubky: Pubky) -> Self {
        Self {
            pubky,
            allow_insecure_local: false,
        }
    }

    /// Permit `ws://localhost` descriptors for an explicitly local development network.
    #[must_use]
    pub const fn allow_insecure_local(mut self, allow: bool) -> Self {
        self.allow_insecure_local = allow;
        self
    }
}

#[async_trait]
impl DescriptorResolver for PubkyResolver {
    async fn resolve(&self, identity: &str) -> Result<RendezvousDescriptor> {
        let address = format!("pubky://{identity}{DESCRIPTOR_PATH}");
        let descriptor: RendezvousDescriptor = self
            .pubky
            .public_storage()
            .get_json(address)
            .await
            .map_err(|error| ClientError::Discovery(error.to_string()))?;
        descriptor.verify(identity, now_seconds(), self.allow_insecure_local)?;
        Ok(descriptor)
    }
}

/// In-memory resolver for tests, private deployments, and offline descriptor injection.
#[derive(Clone, Default)]
pub struct StaticResolver {
    descriptors: Arc<RwLock<HashMap<String, RendezvousDescriptor>>>,
    allow_insecure_local: bool,
}

impl StaticResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new(allow_insecure_local: bool) -> Self {
        Self {
            descriptors: Arc::default(),
            allow_insecure_local,
        }
    }

    /// Add or replace an identity's descriptor.
    pub async fn insert(&self, descriptor: RendezvousDescriptor) {
        self.descriptors
            .write()
            .await
            .insert(descriptor.claims.identity.clone(), descriptor);
    }
}

#[async_trait]
impl DescriptorResolver for StaticResolver {
    async fn resolve(&self, identity: &str) -> Result<RendezvousDescriptor> {
        let descriptor = self
            .descriptors
            .read()
            .await
            .get(identity)
            .cloned()
            .ok_or_else(|| ClientError::Discovery("descriptor not found".to_owned()))?;
        descriptor.verify(identity, now_seconds(), self.allow_insecure_local)?;
        Ok(descriptor)
    }
}

/// Publish an already root-signed descriptor into the signed-in user's public storage.
///
/// # Errors
///
/// Returns an error when the descriptor is invalid or the homeserver write fails.
pub async fn publish_descriptor(
    session: &PubkySession,
    descriptor: &RendezvousDescriptor,
) -> Result<()> {
    let local_only = descriptor.claims.endpoints.iter().all(|endpoint| {
        endpoint.signaling_url.scheme() == "wss"
            || endpoint.signaling_url.host_str().is_some_and(|host| {
                host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            })
    });
    descriptor.verify(&descriptor.claims.identity, now_seconds(), local_only)?;
    session
        .storage()
        .put_json(DESCRIPTOR_PATH, descriptor)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

/// Resolve and select the highest-priority rendezvous URL for an identity.
///
/// # Errors
///
/// Returns an error when discovery/verification fails or the descriptor has no endpoint.
pub async fn resolve_rendezvous_url(
    resolver: &dyn DescriptorResolver,
    identity: &str,
) -> Result<Url> {
    let descriptor = resolver.resolve(identity).await?;
    descriptor
        .ordered_endpoints()
        .first()
        .map(|endpoint| endpoint.signaling_url.clone())
        .ok_or_else(|| ClientError::Discovery("descriptor has no endpoints".to_owned()))
}
