use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures_util::StreamExt as _;
use hole_punchky_protocol::{
    V3_DIRECTORY_PATH, V3DeviceCertificate, V3DeviceDirectory, V3SignedLocator, now_seconds,
    v3_locator_path,
};
use n0_future::time;
use pubky::{Pubky, PubkySession, PublicKey};
use tokio::sync::{Mutex, RwLock};

use crate::{ClientError, MemorySequenceStore, Result, SequenceStore};

const MAX_DEVICES: usize = 8;
const ABSOLUTE_MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_EPHEMERAL_SEQUENCE_FLOORS: usize = 256;

/// One root-certified v3 device and its independently device-signed, fresh iroh locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedV3Device {
    /// Generation of the verified root-signed directory containing this certificate.
    directory_generation: u64,
    /// Exact verified directory snapshot, retained for authenticated floor commits.
    directory: Option<V3DeviceDirectory>,
    /// Root-signed device certificate from the identity's directory.
    pub certificate: V3DeviceCertificate,
    /// Device-signed endpoint id and relay hints.
    pub locator: V3SignedLocator,
}

impl ResolvedV3Device {
    /// Generation of the verified directory snapshot containing this device.
    #[must_use]
    pub const fn directory_generation(&self) -> u64 {
        self.directory_generation
    }
}

/// Resolve all currently valid v3 devices for one canonical Pubky identity.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait V3DeviceResolver: Send + Sync {
    /// Return valid devices and commit their authenticated floors to durable anti-rollback state.
    ///
    /// Use this only for user-initiated outbound discovery. Network-backed implementations may
    /// inherit their Pubky SDK's endpoint, DNS, and redirect egress policy; a remote party must
    /// never be able to choose this identity implicitly.
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>>;

    /// Resolve an explicitly accepted inbound identity using bounded, evictable process-local
    /// anti-rollback state only.
    ///
    /// This may perform Pubky/PKARR and homeserver network requests, so it must never be called
    /// for a remotely supplied identity before application consent. Eviction can only weaken
    /// temporary rollback memory; [`Self::commit_device`] still checks durable floors before an
    /// accepted peer receives an acknowledgement. Consent authorizes resolving this identity; it
    /// does not by itself prove that every SDK-selected transport address is globally routable.
    async fn resolve_devices_for_accepted_inbound(
        &self,
        identity: &str,
    ) -> Result<Vec<ResolvedV3Device>>;

    /// Commit one just-observed, fully verified device's directory and locator floors.
    ///
    /// Callers must re-observe and compare the exact certificate and locator immediately before
    /// this operation. Implementations re-verify cryptographic bindings and reject durable
    /// rollback before returning.
    async fn commit_device(&self, device: &ResolvedV3Device) -> Result<()>;
}

#[derive(Debug, Clone, Copy)]
enum ResolutionPersistence {
    Ephemeral,
    Durable,
}

#[derive(Debug)]
struct EphemeralFloor {
    value: u64,
    touched: u64,
}

#[derive(Debug, Default)]
struct EphemeralFloorState {
    clock: u64,
    floors: HashMap<String, EphemeralFloor>,
}

#[derive(Debug, Default)]
struct EphemeralSequenceCache {
    state: Mutex<EphemeralFloorState>,
}

impl EphemeralSequenceCache {
    async fn observe(&self, identity: &str, scope: &str, value: u64) -> Result<()> {
        if value == 0 {
            return Err(ClientError::State(
                "sequence values must be greater than zero".to_owned(),
            ));
        }
        let key = format!("{identity}:{scope}");
        let mut state = self.state.lock().await;
        if state
            .floors
            .get(&key)
            .is_some_and(|floor| value < floor.value)
        {
            return Err(ClientError::State(
                "authenticated record rolled back".to_owned(),
            ));
        }
        state.clock = state.clock.checked_add(1).unwrap_or_else(|| {
            for floor in state.floors.values_mut() {
                floor.touched = 0;
            }
            1
        });
        let touched = state.clock;
        if !state.floors.contains_key(&key) && state.floors.len() >= MAX_EPHEMERAL_SEQUENCE_FLOORS {
            let oldest = state
                .floors
                .iter()
                .min_by_key(|(candidate, floor)| (floor.touched, candidate.as_str()))
                .map(|(candidate, _)| candidate.clone());
            if let Some(oldest) = oldest {
                state.floors.remove(&oldest);
            }
        }
        state.floors.insert(key, EphemeralFloor { value, touched });
        Ok(())
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.state.lock().await.floors.len()
    }
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
///
/// The underlying Pubky SDK owns transport endpoint selection, DNS, and redirect behavior. Never
/// invoke accepted-inbound resolution before the application has explicitly consented to the
/// exact offline-authenticated identity.
#[derive(Clone)]
pub struct PubkyV3Resolver {
    pubky: Pubky,
    sequences: Arc<dyn SequenceStore>,
    ephemeral_sequences: Arc<EphemeralSequenceCache>,
    config: V3DiscoveryConfig,
}

impl PubkyV3Resolver {
    /// Create a resolver with an explicit anti-rollback store and default network bounds.
    #[must_use]
    pub fn new(pubky: Pubky, sequences: Arc<dyn SequenceStore>) -> Self {
        Self {
            pubky,
            sequences,
            ephemeral_sequences: Arc::default(),
            config: V3DiscoveryConfig::default(),
        }
    }

    /// Override discovery resource bounds and local-development relay policy.
    #[must_use]
    pub fn with_config(mut self, config: V3DiscoveryConfig) -> Self {
        self.config = config;
        self
    }

    async fn record_floor(
        &self,
        persistence: ResolutionPersistence,
        identity: &str,
        scope: &str,
        value: u64,
    ) -> Result<()> {
        match persistence {
            ResolutionPersistence::Ephemeral => {
                self.ephemeral_sequences
                    .observe(identity, scope, value)
                    .await
            }
            ResolutionPersistence::Durable => self.sequences.record(identity, scope, value).await,
        }
    }

    async fn resolve_inner(
        &self,
        identity: &str,
        persistence: ResolutionPersistence,
    ) -> Result<Vec<ResolvedV3Device>> {
        let directory_address = addressed(identity, V3_DIRECTORY_PATH)?;
        let directory_bytes = self
            .fetch_bounded(directory_address, self.config.directory_max_bytes)
            .await?;
        let directory: V3DeviceDirectory = serde_json::from_slice(&directory_bytes)
            .map_err(|_| ClientError::Discovery("malformed v3 device directory".to_owned()))?;
        let now = now_seconds();
        directory.verify(identity, now, None)?;
        self.record_floor(
            persistence,
            identity,
            "directory",
            directory.claims.generation,
        )
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
                .record_floor(persistence, identity, &scope, locator.claims.sequence)
                .await
                .is_err()
            {
                continue;
            }
            resolved.push(ResolvedV3Device {
                directory_generation: directory.claims.generation,
                directory: Some(directory.clone()),
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

    async fn resolve_bounded(
        &self,
        identity: &str,
        persistence: ResolutionPersistence,
    ) -> Result<Vec<ResolvedV3Device>> {
        self.config.validate()?;
        let identity = canonical_identity(identity)?;
        time::timeout(
            self.config.overall_timeout,
            self.resolve_inner(&identity, persistence),
        )
        .await
        .map_err(|_| ClientError::Timeout("resolving v3 Pubky devices"))?
    }

    async fn commit_verified_device(&self, device: &ResolvedV3Device) -> Result<()> {
        let identity = canonical_identity(&device.certificate.claims.identity)?;
        let now = now_seconds();
        let directory = device.directory.as_ref().ok_or_else(|| {
            ClientError::State("missing authenticated v3 directory snapshot".to_owned())
        })?;
        directory.verify(&identity, now, None)?;
        if directory.claims.generation != device.directory_generation
            || !directory
                .claims
                .devices
                .iter()
                .any(|certificate| certificate == &device.certificate)
        {
            return Err(ClientError::UnexpectedPeer);
        }
        device.locator.verify(
            &device.certificate,
            &identity,
            now,
            self.config.allow_insecure_loopback_relay,
            None,
        )?;
        if device.directory_generation == 0 {
            return Err(ClientError::State(
                "directory generation must be greater than zero".to_owned(),
            ));
        }
        self.sequences
            .record(&identity, "directory", device.directory_generation)
            .await?;
        let scope = format!("locator:{}", device.certificate.claims.control_signing_key);
        self.sequences
            .record(&identity, &scope, device.locator.claims.sequence)
            .await
    }

    async fn fetch_bounded(&self, address: String, max_bytes: usize) -> Result<Vec<u8>> {
        let response = time::timeout(
            self.config.connect_timeout,
            self.pubky.public_storage().get(address),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting to Pubky public storage"))?
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
        reject_oversized_declared_length(response.content_length(), max_bytes)?;
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|error| ClientError::Discovery(error.to_string()))?;
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

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl V3DeviceResolver for PubkyV3Resolver {
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>> {
        self.resolve_bounded(identity, ResolutionPersistence::Durable)
            .await
    }

    async fn resolve_devices_for_accepted_inbound(
        &self,
        identity: &str,
    ) -> Result<Vec<ResolvedV3Device>> {
        self.resolve_bounded(identity, ResolutionPersistence::Ephemeral)
            .await
    }

    async fn commit_device(&self, device: &ResolvedV3Device) -> Result<()> {
        self.commit_verified_device(device).await
    }
}

/// In-memory v3 resolver for deterministic tests and offline injection.
#[derive(Clone)]
pub struct StaticV3Resolver {
    records: Arc<RwLock<Vec<ResolvedV3Device>>>,
    sequences: Arc<dyn SequenceStore>,
    ephemeral_sequences: Arc<EphemeralSequenceCache>,
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
            ephemeral_sequences: Arc::default(),
            allow_insecure_loopback_relay,
        }
    }

    /// Use an explicit durable anti-rollback store for committed resolutions.
    #[must_use]
    pub fn with_sequence_store(mut self, sequences: Arc<dyn SequenceStore>) -> Self {
        self.sequences = sequences;
        self
    }

    /// Replace all injected records. Verification occurs on every resolution.
    pub async fn replace(&self, records: Vec<ResolvedV3Device>) {
        *self.records.write().await = records;
    }

    /// Add an injected certificate/locator pair.
    pub async fn insert(&self, certificate: V3DeviceCertificate, locator: V3SignedLocator) {
        self.records.write().await.push(ResolvedV3Device {
            directory_generation: 1,
            directory: None,
            certificate,
            locator,
        });
    }

    async fn record_floor(
        &self,
        persistence: ResolutionPersistence,
        identity: &str,
        scope: &str,
        value: u64,
    ) -> Result<()> {
        match persistence {
            ResolutionPersistence::Ephemeral => {
                self.ephemeral_sequences
                    .observe(identity, scope, value)
                    .await
            }
            ResolutionPersistence::Durable => self.sequences.record(identity, scope, value).await,
        }
    }

    async fn resolve_inner(
        &self,
        identity: &str,
        persistence: ResolutionPersistence,
    ) -> Result<Vec<ResolvedV3Device>> {
        let identity = canonical_identity(identity)?;
        let records = self.records.read().await.clone();
        let mut resolved = Vec::new();
        for record in records
            .into_iter()
            .filter(|record| record.certificate.claims.identity == identity)
            .take(MAX_DEVICES)
        {
            if record.directory_generation == 0
                || record
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
            resolved.push(record);
        }
        let Some(generation) = resolved.first().map(|record| record.directory_generation) else {
            return Err(ClientError::Discovery(
                "no valid injected v3 device locators were found".to_owned(),
            ));
        };
        if resolved
            .iter()
            .any(|record| record.directory_generation != generation)
        {
            return Err(ClientError::Discovery(
                "injected v3 devices do not share one directory generation".to_owned(),
            ));
        }
        self.record_floor(persistence, &identity, "directory", generation)
            .await?;
        let mut accepted = Vec::with_capacity(resolved.len());
        for record in resolved {
            let scope = format!("locator:{}", record.certificate.claims.control_signing_key);
            if self
                .record_floor(
                    persistence,
                    &identity,
                    &scope,
                    record.locator.claims.sequence,
                )
                .await
                .is_ok()
            {
                accepted.push(record);
            }
        }
        accepted.sort_by(|left, right| {
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
        if accepted.is_empty() {
            return Err(ClientError::Discovery(
                "no valid injected v3 device locators were found".to_owned(),
            ));
        }
        Ok(accepted)
    }

    async fn commit_verified_device(&self, device: &ResolvedV3Device) -> Result<()> {
        let identity = canonical_identity(&device.certificate.claims.identity)?;
        if !self.records.read().await.iter().any(|current| {
            current.directory_generation == device.directory_generation
                && current.certificate == device.certificate
                && current.locator == device.locator
        }) {
            return Err(ClientError::UnexpectedPeer);
        }
        device.locator.verify(
            &device.certificate,
            &identity,
            now_seconds(),
            self.allow_insecure_loopback_relay,
            None,
        )?;
        if device.directory_generation == 0 {
            return Err(ClientError::State(
                "directory generation must be greater than zero".to_owned(),
            ));
        }
        self.sequences
            .record(&identity, "directory", device.directory_generation)
            .await?;
        let scope = format!("locator:{}", device.certificate.claims.control_signing_key);
        self.sequences
            .record(&identity, &scope, device.locator.claims.sequence)
            .await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl V3DeviceResolver for StaticV3Resolver {
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>> {
        self.resolve_inner(identity, ResolutionPersistence::Durable)
            .await
    }

    async fn resolve_devices_for_accepted_inbound(
        &self,
        identity: &str,
    ) -> Result<Vec<ResolvedV3Device>> {
        self.resolve_inner(identity, ResolutionPersistence::Ephemeral)
            .await
    }

    async fn commit_device(&self, device: &ResolvedV3Device) -> Result<()> {
        self.commit_verified_device(device).await
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
    use hole_punchky_protocol::{V3DeviceCredential, v3_random_nonce};
    use pubky::Keypair;
    use url::Url;

    use super::*;

    #[derive(Debug, Default)]
    struct RecordingSequenceStore {
        values: Mutex<HashMap<String, u64>>,
    }

    #[async_trait]
    impl SequenceStore for RecordingSequenceStore {
        async fn record(&self, identity: &str, scope: &str, value: u64) -> Result<()> {
            let key = format!("{identity}:{scope}");
            let mut values = self.values.lock().await;
            if values.get(&key).is_some_and(|floor| value < *floor) {
                return Err(ClientError::State(
                    "authenticated record rolled back".to_owned(),
                ));
            }
            values.insert(key, value);
            Ok(())
        }
    }

    impl RecordingSequenceStore {
        async fn len(&self) -> usize {
            self.values.lock().await.len()
        }
    }

    fn device_record(
        root: &Keypair,
        device_id: &str,
        generation: u64,
        sequence: u64,
    ) -> (V3DeviceCredential, ResolvedV3Device) {
        let now = now_seconds();
        let credential = V3DeviceCredential::issue(
            root,
            device_id,
            now.saturating_sub(1),
            now.saturating_add(3_600),
        )
        .unwrap_or_else(|error| panic!("issuing device: {error}"));
        let locator = V3SignedLocator::sign(
            &credential,
            vec![
                Url::parse("https://relay.example/")
                    .unwrap_or_else(|error| panic!("relay URL: {error}")),
            ],
            v3_random_nonce(),
            sequence,
            now,
            now.saturating_add(300),
        )
        .unwrap_or_else(|error| panic!("signing locator: {error}"));
        let record = ResolvedV3Device {
            directory_generation: generation,
            directory: None,
            certificate: credential.certificate.clone(),
            locator,
        };
        (credential, record)
    }

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

    #[tokio::test]
    async fn unauthenticated_identity_flood_uses_only_bounded_ephemeral_floors() {
        let durable = Arc::new(RecordingSequenceStore::default());
        let resolver = StaticV3Resolver::new(false).with_sequence_store(durable.clone());
        for index in 0..(MAX_EPHEMERAL_SEQUENCE_FLOORS + 32) {
            let root = Keypair::random();
            let identity = root.public_key().z32();
            let (_, record) = device_record(&root, &format!("device-{index}"), 1, 1);
            resolver.replace(vec![record]).await;
            resolver
                .resolve_devices_for_accepted_inbound(&identity)
                .await
                .unwrap_or_else(|error| panic!("observing identity {index}: {error}"));
        }
        assert_eq!(durable.len().await, 0);
        assert_eq!(
            resolver.ephemeral_sequences.len().await,
            MAX_EPHEMERAL_SEQUENCE_FLOORS,
            "ephemeral floors must evict instead of becoming a permanent admission failure"
        );
    }

    #[tokio::test]
    async fn committing_an_observed_device_persists_floors_and_rejects_rollback() {
        let durable = Arc::new(RecordingSequenceStore::default());
        let root = Keypair::random();
        let identity = root.public_key().z32();
        let (credential, current) = device_record(&root, "device", 9, 7);
        let resolver = StaticV3Resolver::new(false).with_sequence_store(durable.clone());
        resolver.replace(vec![current]).await;
        let observed = resolver
            .resolve_devices_for_accepted_inbound(&identity)
            .await
            .unwrap_or_else(|error| panic!("observing current device: {error}"));
        assert_eq!(durable.len().await, 0);
        resolver
            .commit_device(&observed[0])
            .await
            .unwrap_or_else(|error| panic!("committing accepted device: {error}"));
        assert_eq!(durable.len().await, 2);

        let now = now_seconds();
        let rollback_locator = V3SignedLocator::sign(
            &credential,
            vec![
                Url::parse("https://relay.example/")
                    .unwrap_or_else(|error| panic!("relay URL: {error}")),
            ],
            v3_random_nonce(),
            6,
            now,
            now.saturating_add(300),
        )
        .unwrap_or_else(|error| panic!("signing rollback locator: {error}"));
        let rollback = ResolvedV3Device {
            directory_generation: 8,
            directory: None,
            certificate: credential.certificate.clone(),
            locator: rollback_locator,
        };
        let restarted = StaticV3Resolver::new(false).with_sequence_store(durable.clone());
        restarted.replace(vec![rollback]).await;
        let rollback_observed = restarted
            .resolve_devices_for_accepted_inbound(&identity)
            .await
            .unwrap_or_else(|error| panic!("ephemerally observing rollback: {error}"));
        assert!(
            restarted
                .commit_device(&rollback_observed[0])
                .await
                .is_err()
        );
        assert_eq!(durable.len().await, 2);
    }
}
