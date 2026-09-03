use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use hole_punchky_protocol::{
    V3_DIRECTORY_PATH, V3DeviceCertificate, V3DeviceDirectory, V3SignedLocator, now_seconds,
    v3_locator_path,
};
use pubky::{Pubky, PubkySession, PublicKey};
use tokio::sync::RwLock;

use crate::{ClientError, MemorySequenceStore, Result, SequenceStore};

const MAX_DEVICES: usize = 8;
const ABSOLUTE_MAX_RECORD_BYTES: usize = 1024 * 1024;

/// One root-certified v3 device and its independently device-signed, fresh iroh locator.
#[derive(Debug, Clone)]
pub struct ResolvedV3Device {
    /// Root-signed device certificate from the identity's directory.
    pub certificate: V3DeviceCertificate,
    /// Device-signed endpoint id and relay hints.
    pub locator: V3SignedLocator,
}

/// Resolve all currently valid native-v3 devices for one canonical Pubky identity.
#[async_trait]
pub trait V3DeviceResolver: Send + Sync {
    /// Return valid devices in deterministic order, skipping malformed sibling locator files.
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>>;
}

/// Strict resource and timeout bounds for homeserver discovery.
#[derive(Debug, Clone)]
pub struct V3DiscoveryConfig {
    /// Time allowed to receive response headers for any one homeserver request.
    pub connect_timeout: Duration,
    /// Time allowed for the directory and every referenced locator combined.
    pub overall_timeout: Duration,
    /// Maximum bytes read for the root-signed directory, regardless of `Content-Length`.
    pub directory_max_bytes: usize,
    /// Maximum bytes read for any one locator, regardless of `Content-Length`.
    pub locator_max_bytes: usize,
    /// Permit protocol records containing plain-HTTP loopback relay origins.
    pub allow_insecure_loopback_relay: bool,
}

impl Default for V3DiscoveryConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            overall_timeout: Duration::from_secs(30),
            directory_max_bytes: 64 * 1024,
            locator_max_bytes: 32 * 1024,
            allow_insecure_loopback_relay: false,
        }
    }
}

impl V3DiscoveryConfig {
    fn validate(&self) -> Result<()> {
        if self.connect_timeout.is_zero()
            || self.overall_timeout.is_zero()
            || self.connect_timeout > self.overall_timeout
            || self.directory_max_bytes == 0
            || self.locator_max_bytes == 0
            || self.directory_max_bytes > ABSOLUTE_MAX_RECORD_BYTES
            || self.locator_max_bytes > ABSOLUTE_MAX_RECORD_BYTES
        {
            return Err(ClientError::Discovery(
                "invalid v3 discovery resource bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

/// V3 resolver backed by Pubky PKARR resolution and public homeserver storage.
#[derive(Clone)]
pub struct PubkyV3Resolver {
    pubky: Pubky,
    sequences: Arc<dyn SequenceStore>,
    config: V3DiscoveryConfig,
}

impl PubkyV3Resolver {
    /// Create a resolver with an explicit anti-rollback store and default network bounds.
    #[must_use]
    pub fn new(pubky: Pubky, sequences: Arc<dyn SequenceStore>) -> Self {
        Self {
            pubky,
            sequences,
            config: V3DiscoveryConfig::default(),
        }
    }

    /// Override discovery resource bounds and local-development relay policy.
    #[must_use]
    pub fn with_config(mut self, config: V3DiscoveryConfig) -> Self {
        self.config = config;
        self
    }

    async fn resolve_inner(&self, identity: &str) -> Result<Vec<ResolvedV3Device>> {
        let directory_address = addressed(identity, V3_DIRECTORY_PATH)?;
        let directory_bytes = self
            .fetch_bounded(directory_address, self.config.directory_max_bytes)
            .await?;
        let directory: V3DeviceDirectory = serde_json::from_slice(&directory_bytes)
            .map_err(|_| ClientError::Discovery("malformed v3 device directory".to_owned()))?;
        let now = now_seconds();
        directory.verify(identity, now, None)?;
        self.sequences
            .record(identity, "directory", directory.claims.generation)
            .await?;

        let mut resolved = Vec::with_capacity(directory.claims.devices.len().min(MAX_DEVICES));
        for certificate in directory.claims.devices.iter().take(MAX_DEVICES) {
            let Ok(path) = v3_locator_path(&certificate.claims.control_signing_key) else {
                continue;
            };
            let Ok(address) = addressed(identity, &path) else {
                continue;
            };
            let Ok(bytes) = self
                .fetch_bounded(address, self.config.locator_max_bytes)
                .await
            else {
                continue;
            };
            let Ok(locator) = serde_json::from_slice::<V3SignedLocator>(&bytes) else {
                continue;
            };
            if locator
                .verify(
                    certificate,
                    identity,
                    now_seconds(),
                    self.config.allow_insecure_loopback_relay,
                    None,
                )
                .is_err()
            {
                continue;
            }
            let scope = format!("locator:{}", certificate.claims.control_signing_key);
            if self
                .sequences
                .record(identity, &scope, locator.claims.sequence)
                .await
                .is_err()
            {
                continue;
            }
            resolved.push(ResolvedV3Device {
                certificate: certificate.clone(),
                locator,
            });
        }
        resolved.sort_by(|left, right| {
            left.certificate
                .claims
                .device_id
                .cmp(&right.certificate.claims.device_id)
                .then_with(|| {
                    left.certificate
                        .claims
                        .control_signing_key
                        .cmp(&right.certificate.claims.control_signing_key)
                })
        });
        if resolved.is_empty() && !directory.claims.devices.is_empty() {
            return Err(ClientError::Discovery(
                "no valid v3 device locators were found".to_owned(),
            ));
        }
        Ok(resolved)
    }

    async fn fetch_bounded(&self, address: String, max_bytes: usize) -> Result<Vec<u8>> {
        let mut response = tokio::time::timeout(
            self.config.connect_timeout,
            self.pubky.public_storage().get(address),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting to Pubky public storage"))?
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
        reject_oversized_declared_length(response.content_length(), max_bytes)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| ClientError::Discovery(error.to_string()))?
        {
            if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
                return Err(ClientError::Discovery(
                    "Pubky discovery record exceeds byte limit".to_owned(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn reject_oversized_declared_length(declared: Option<u64>, max: usize) -> Result<()> {
    let max = u64::try_from(max)
        .map_err(|_| ClientError::Discovery("invalid discovery byte limit".to_owned()))?;
    if declared.is_some_and(|length| length > max) {
        return Err(ClientError::Discovery(
            "Pubky discovery record declares an oversized body".to_owned(),
        ));
    }
    Ok(())
}

#[async_trait]
impl V3DeviceResolver for PubkyV3Resolver {
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>> {
        self.config.validate()?;
        let identity = canonical_identity(identity)?;
        tokio::time::timeout(self.config.overall_timeout, self.resolve_inner(&identity))
            .await
            .map_err(|_| ClientError::Timeout("resolving v3 Pubky devices"))?
    }
}

/// In-memory v3 resolver for deterministic tests and offline injection.
#[derive(Clone)]
pub struct StaticV3Resolver {
    records: Arc<RwLock<Vec<ResolvedV3Device>>>,
    sequences: Arc<dyn SequenceStore>,
    allow_insecure_loopback_relay: bool,
}

impl Default for StaticV3Resolver {
    fn default() -> Self {
        Self::new(false)
    }
}

impl StaticV3Resolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new(allow_insecure_loopback_relay: bool) -> Self {
        Self {
            records: Arc::default(),
            sequences: Arc::new(MemorySequenceStore::default()),
            allow_insecure_loopback_relay,
        }
    }

    /// Replace all injected records. Verification occurs on every resolution.
    pub async fn replace(&self, records: Vec<ResolvedV3Device>) {
        *self.records.write().await = records;
    }

    /// Add an injected certificate/locator pair.
    pub async fn insert(&self, certificate: V3DeviceCertificate, locator: V3SignedLocator) {
        self.records.write().await.push(ResolvedV3Device {
            certificate,
            locator,
        });
    }
}

#[async_trait]
impl V3DeviceResolver for StaticV3Resolver {
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>> {
        let identity = canonical_identity(identity)?;
        let records = self.records.read().await.clone();
        let mut resolved = Vec::new();
        for record in records.into_iter().take(MAX_DEVICES) {
            if record
                .locator
                .verify(
                    &record.certificate,
                    &identity,
                    now_seconds(),
                    self.allow_insecure_loopback_relay,
                    None,
                )
                .is_err()
            {
                continue;
            }
            let scope = format!("locator:{}", record.certificate.claims.control_signing_key);
            if self
                .sequences
                .record(&identity, &scope, record.locator.claims.sequence)
                .await
                .is_ok()
            {
                resolved.push(record);
            }
        }
        resolved.sort_by(|left, right| {
            left.certificate
                .claims
                .device_id
                .cmp(&right.certificate.claims.device_id)
                .then_with(|| {
                    left.certificate
                        .claims
                        .control_signing_key
                        .cmp(&right.certificate.claims.control_signing_key)
                })
        });
        if resolved.is_empty() {
            return Err(ClientError::Discovery(
                "no valid injected v3 device locators were found".to_owned(),
            ));
        }
        Ok(resolved)
    }
}

/// Publish a verified root-signed device directory with an existing scoped session.
///
/// # Errors
///
/// Returns an error if the session identity does not own the directory or the write fails.
pub async fn publish_v3_directory(
    session: &PubkySession,
    directory: &V3DeviceDirectory,
) -> Result<()> {
    let identity = session.public_key().z32();
    directory.verify(&identity, now_seconds(), None)?;
    let encoded =
        serde_json::to_vec(directory).map_err(|error| ClientError::Discovery(error.to_string()))?;
    if encoded.len() > ABSOLUTE_MAX_RECORD_BYTES {
        return Err(ClientError::Discovery(
            "v3 directory exceeds publication limit".to_owned(),
        ));
    }
    session
        .storage()
        .put(V3_DIRECTORY_PATH, encoded)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

/// Publish a verified device locator with an existing scoped session.
///
/// # Errors
///
/// Returns an error if the session identity does not own the certified locator or the write
/// fails. The Pubky root secret is neither accepted nor needed.
pub async fn publish_v3_locator(
    session: &PubkySession,
    certificate: &V3DeviceCertificate,
    locator: &V3SignedLocator,
    allow_insecure_loopback_relay: bool,
) -> Result<()> {
    let identity = session.public_key().z32();
    locator.verify(
        certificate,
        &identity,
        now_seconds(),
        allow_insecure_loopback_relay,
        None,
    )?;
    let path = v3_locator_path(&certificate.claims.control_signing_key)?;
    let encoded =
        serde_json::to_vec(locator).map_err(|error| ClientError::Discovery(error.to_string()))?;
    if encoded.len() > ABSOLUTE_MAX_RECORD_BYTES {
        return Err(ClientError::Discovery(
            "v3 locator exceeds publication limit".to_owned(),
        ));
    }
    session
        .storage()
        .put(path, encoded)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

fn canonical_identity(identity: &str) -> Result<String> {
    let key = identity
        .parse::<PublicKey>()
        .map_err(|_| ClientError::Discovery("invalid Pubky identity".to_owned()))?;
    let canonical = key.z32();
    if canonical != identity {
        return Err(ClientError::Discovery(
            "Pubky identity is not canonical".to_owned(),
        ));
    }
    Ok(canonical)
}

fn addressed(identity: &str, path: &str) -> Result<String> {
    let identity = canonical_identity(identity)?;
    if !path.starts_with('/')
        || path.contains("..")
        || path
            .chars()
            .any(|character| matches!(character, '?' | '#' | '\\'))
    {
        return Err(ClientError::Discovery(
            "invalid v3 public-storage path".to_owned(),
        ));
    }
    Ok(format!("pubky://{identity}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_identity_injection_before_address_construction() {
        assert!(addressed("victim/pub/elsewhere", V3_DIRECTORY_PATH).is_err());
        assert!(addressed("https://example.test", V3_DIRECTORY_PATH).is_err());
    }

    #[test]
    fn rejects_oversized_content_length_without_weakening_stream_cap() {
        assert!(reject_oversized_declared_length(Some(65), 64).is_err());
        assert!(reject_oversized_declared_length(Some(64), 64).is_ok());
        assert!(
            reject_oversized_declared_length(None, 64).is_ok(),
            "chunked/unknown bodies proceed to the independent streaming cap"
        );
    }
}
