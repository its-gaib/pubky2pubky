//! Bounded homeserver discovery and publication for protocol v1.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt as _;
use n0_future::time;
use pubky::{Pubky, PubkySession, PublicKey};
use pubky2pubky_protocol::{
    V1_CURRENTNESS_PATH_PREFIX, V1_DEVICE_RECORD_PATH_PREFIX, V1_MAX_CURRENTNESS_PROOF_BYTES,
    V1_MAX_DEVICE_RECORD_BYTES, V1DeviceRecord, V1SignedCurrentnessProof, now_seconds,
};
use tokio::sync::RwLock;

use crate::{AuthenticatedSequenceObservation, ClientError, Result, SequenceStore};

/// Maximum v1 devices discoverable for one Pubky identity.
pub const V1_MAX_DEVICES: usize = 8;

const ABSOLUTE_MAX_TOTAL_BYTES: usize = 8 * V1_MAX_DEVICE_RECORD_BYTES;
const LIST_DETECTION_LIMIT: u16 = 9;

/// One exact, fully verified self-contained v1 device publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedV1Device {
    /// Exact hash-derived public-storage path.
    pub path: String,
    /// Complete Grant authorization, device certificate, and current locator.
    pub record: V1DeviceRecord,
}

/// Strict resource and timeout bounds for v1 homeserver discovery.
#[derive(Debug, Clone)]
pub struct V1DiscoveryConfig {
    /// Time allowed to receive response headers for one public-storage request.
    pub connect_timeout: Duration,
    /// Total time allowed for one list or exact-fetch operation.
    pub overall_timeout: Duration,
    /// Maximum bytes read for one device record.
    pub record_max_bytes: usize,
    /// Maximum aggregate bytes accepted across one device listing.
    pub total_record_max_bytes: usize,
    /// Maximum bytes read for one currentness proof.
    pub currentness_max_bytes: usize,
    /// Permit plain-HTTP loopback relay URLs only in explicitly local tests.
    pub allow_insecure_loopback_relay: bool,
}

impl Default for V1DiscoveryConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            overall_timeout: Duration::from_secs(30),
            record_max_bytes: V1_MAX_DEVICE_RECORD_BYTES,
            total_record_max_bytes: ABSOLUTE_MAX_TOTAL_BYTES,
            currentness_max_bytes: V1_MAX_CURRENTNESS_PROOF_BYTES,
            allow_insecure_loopback_relay: false,
        }
    }
}

impl V1DiscoveryConfig {
    fn validate(&self) -> Result<()> {
        if self.connect_timeout.is_zero()
            || self.overall_timeout.is_zero()
            || self.connect_timeout > self.overall_timeout
            || self.record_max_bytes == 0
            || self.record_max_bytes > V1_MAX_DEVICE_RECORD_BYTES
            || self.total_record_max_bytes < self.record_max_bytes
            || self.total_record_max_bytes > ABSOLUTE_MAX_TOTAL_BYTES
            || self.currentness_max_bytes == 0
            || self.currentness_max_bytes > V1_MAX_CURRENTNESS_PROOF_BYTES
        {
            return Err(ClientError::Discovery(
                "invalid v1 discovery resource bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

/// V1 discovery, exact currentness exchange, and atomic remote-observation boundary.
///
/// [`Self::resolve_devices`] is only for a locally user-selected outbound identity.
/// [`Self::fetch_currentness_proof`] may use an identity learned from the peer and therefore must
/// never be called before explicit inbound application consent.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait V1DeviceResolver: Send + Sync {
    /// List and verify up to eight current device records for a user-selected identity.
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV1Device>>;

    /// Fetch and verify one exact hash-derived device-record path.
    async fn fetch_device_record(&self, identity: &str, path: &str) -> Result<ResolvedV1Device>;

    /// Fetch one exact hash-derived currentness-proof path without yet trusting its contents.
    async fn fetch_currentness_proof(
        &self,
        identity: &str,
        path: &str,
    ) -> Result<V1SignedCurrentnessProof>;

    /// Publish a bounded currentness proof under this resolver's local authenticated identity.
    async fn publish_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()>;

    /// Best-effort exact deletion of a proof previously published by this resolver.
    async fn delete_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()>;

    /// Atomically commit the digest-bound locator observation after mutual currentness succeeds.
    async fn commit_remote_record(&self, device: &ResolvedV1Device) -> Result<()>;
}

/// Network-backed v1 resolver and currentness publisher.
#[derive(Clone)]
pub struct PubkyV1Resolver {
    pubky: Pubky,
    session: PubkySession,
    sequences: Arc<dyn SequenceStore>,
    config: V1DiscoveryConfig,
}

impl PubkyV1Resolver {
    /// Create a resolver using one authenticated local session and durable observation store.
    #[must_use]
    pub fn new(pubky: Pubky, session: PubkySession, sequences: Arc<dyn SequenceStore>) -> Self {
        Self {
            pubky,
            session,
            sequences,
            config: V1DiscoveryConfig::default(),
        }
    }

    /// Override strict discovery bounds and local-test relay policy.
    #[must_use]
    pub fn with_config(mut self, config: V1DiscoveryConfig) -> Self {
        self.config = config;
        self
    }

    async fn fetch_bounded(&self, address: String, maximum: usize) -> Result<Vec<u8>> {
        let response = time::timeout(
            self.config.connect_timeout,
            self.pubky.public_storage().get(address),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting to v1 Pubky public storage"))?
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
        if response.content_length().is_some_and(|declared| {
            usize::try_from(declared).map_or(true, |length| length > maximum)
        }) {
            return Err(ClientError::Discovery(
                "v1 discovery record declares an oversized body".to_owned(),
            ));
        }
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|error| ClientError::Discovery(error.to_string()))?;
            if chunk.len() > maximum.saturating_sub(bytes.len()) {
                return Err(ClientError::Discovery(
                    "v1 discovery record exceeds byte limit".to_owned(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn fetch_record_inner(&self, identity: &str, path: &str) -> Result<ResolvedV1Device> {
        validate_device_path(path)?;
        let address = addressed(identity, path)?;
        let bytes = self
            .fetch_bounded(address, self.config.record_max_bytes)
            .await?;
        let record = V1DeviceRecord::decode_and_verify(
            &bytes,
            identity,
            now_seconds(),
            self.config.allow_insecure_loopback_relay,
            None,
        )?;
        if record.path()? != path {
            return Err(ClientError::UnexpectedPeer);
        }
        Ok(ResolvedV1Device {
            path: path.to_owned(),
            record,
        })
    }

    async fn resolve_inner(&self, identity: &str) -> Result<Vec<ResolvedV1Device>> {
        let identity = canonical_identity(identity)?;
        let prefix_address = addressed(&identity, V1_DEVICE_RECORD_PATH_PREFIX)?;
        let entries = self
            .pubky
            .public_storage()
            .list(prefix_address)
            .map_err(|error| ClientError::Discovery(error.to_string()))?
            .shallow(true)
            .limit(LIST_DETECTION_LIMIT)
            .send()
            .await
            .map_err(|error| ClientError::Discovery(error.to_string()))?;
        if entries.len() > V1_MAX_DEVICES {
            return Err(ClientError::Discovery(
                "v1 device listing exceeds the eight-device limit".to_owned(),
            ));
        }

        let mut paths = Vec::with_capacity(entries.len());
        let mut unique = HashSet::new();
        for entry in entries {
            if entry.owner.z32() != identity {
                return Err(ClientError::UnexpectedPeer);
            }
            let path = entry.path.as_str();
            validate_device_path(path)?;
            if !unique.insert(path.to_owned()) {
                return Err(ClientError::Discovery(
                    "duplicate v1 device listing entry".to_owned(),
                ));
            }
            paths.push(path.to_owned());
        }
        paths.sort();

        let mut total = 0usize;
        let mut devices = Vec::with_capacity(paths.len());
        for path in paths {
            let device = self.fetch_record_inner(&identity, &path).await?;
            let encoded = serde_json::to_vec(&device.record)
                .map_err(|error| ClientError::Discovery(error.to_string()))?;
            total = total
                .checked_add(encoded.len())
                .ok_or_else(|| ClientError::Discovery("v1 byte total overflow".to_owned()))?;
            if total > self.config.total_record_max_bytes {
                return Err(ClientError::Discovery(
                    "v1 device records exceed aggregate byte limit".to_owned(),
                ));
            }
            devices.push(device);
        }
        devices.sort_by(|left, right| {
            left.record
                .certificate
                .claims
                .device_id
                .cmp(&right.record.certificate.claims.device_id)
                .then_with(|| {
                    left.record
                        .certificate
                        .claims
                        .control_signing_key
                        .cmp(&right.record.certificate.claims.control_signing_key)
                })
        });
        Ok(devices)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl V1DeviceResolver for PubkyV1Resolver {
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV1Device>> {
        self.config.validate()?;
        time::timeout(self.config.overall_timeout, self.resolve_inner(identity))
            .await
            .map_err(|_| ClientError::Timeout("listing v1 Pubky devices"))?
    }

    async fn fetch_device_record(&self, identity: &str, path: &str) -> Result<ResolvedV1Device> {
        self.config.validate()?;
        let identity = canonical_identity(identity)?;
        time::timeout(
            self.config.overall_timeout,
            self.fetch_record_inner(&identity, path),
        )
        .await
        .map_err(|_| ClientError::Timeout("fetching exact v1 device record"))?
    }

    async fn fetch_currentness_proof(
        &self,
        identity: &str,
        path: &str,
    ) -> Result<V1SignedCurrentnessProof> {
        self.config.validate()?;
        let identity = canonical_identity(identity)?;
        validate_currentness_path(path)?;
        let bytes = time::timeout(
            self.config.overall_timeout,
            self.fetch_bounded(
                addressed(&identity, path)?,
                self.config.currentness_max_bytes,
            ),
        )
        .await
        .map_err(|_| ClientError::Timeout("fetching exact v1 currentness proof"))??;
        serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Discovery("malformed v1 currentness proof".to_owned()))
    }

    async fn publish_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()> {
        publish_v1_currentness_proof(&self.session, proof).await
    }

    async fn delete_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()> {
        delete_v1_currentness_proof(&self.session, proof).await
    }

    async fn commit_remote_record(&self, device: &ResolvedV1Device) -> Result<()> {
        device.record.verify(
            &device.record.certificate.claims.identity,
            now_seconds(),
            self.config.allow_insecure_loopback_relay,
            None,
        )?;
        if device.record.path()? != device.path {
            return Err(ClientError::UnexpectedPeer);
        }
        self.sequences
            .record_batch(vec![record_observation(&device.record)?])
            .await
    }
}

#[derive(Debug, Default)]
struct StaticV1State {
    records: RwLock<HashMap<String, V1DeviceRecord>>,
    proofs: RwLock<HashMap<String, V1SignedCurrentnessProof>>,
}

/// In-memory v1 resolver/publisher for deterministic tests and offline injection.
#[derive(Clone)]
pub struct StaticV1Resolver {
    local_identity: String,
    state: Arc<StaticV1State>,
    sequences: Arc<dyn SequenceStore>,
    request_count: Arc<AtomicUsize>,
    allow_insecure_loopback_relay: bool,
}

impl StaticV1Resolver {
    /// Create an isolated resolver for one local identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless `local_identity` is canonical.
    pub fn new(
        local_identity: &str,
        sequences: Arc<dyn SequenceStore>,
        allow_insecure_loopback_relay: bool,
    ) -> Result<Self> {
        Ok(Self {
            local_identity: canonical_identity(local_identity)?,
            state: Arc::default(),
            sequences,
            request_count: Arc::default(),
            allow_insecure_loopback_relay,
        })
    }

    /// Create another local view sharing the same injected public-storage state.
    ///
    /// # Errors
    ///
    /// Returns an error unless `local_identity` is canonical.
    pub fn for_local_identity(
        &self,
        local_identity: &str,
        sequences: Arc<dyn SequenceStore>,
    ) -> Result<Self> {
        Ok(Self {
            local_identity: canonical_identity(local_identity)?,
            state: Arc::clone(&self.state),
            sequences,
            request_count: Arc::new(AtomicUsize::new(0)),
            allow_insecure_loopback_relay: self.allow_insecure_loopback_relay,
        })
    }

    /// Insert or replace one exact verified device record.
    ///
    /// # Errors
    ///
    /// Returns an error when the record or derived path is invalid.
    pub async fn insert_record(&self, record: V1DeviceRecord) -> Result<String> {
        let identity = record.certificate.claims.identity.clone();
        record.verify(
            &identity,
            now_seconds(),
            self.allow_insecure_loopback_relay,
            None,
        )?;
        let path = record.path()?;
        self.state
            .records
            .write()
            .await
            .insert(storage_key(&identity, &path), record);
        Ok(path)
    }

    /// Number of read/resolution calls made through this local view.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    fn note_request(&self) {
        self.request_count.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl V1DeviceResolver for StaticV1Resolver {
    async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV1Device>> {
        self.note_request();
        let identity = canonical_identity(identity)?;
        let records = self.state.records.read().await;
        let mut devices = Vec::new();
        for record in records.values() {
            if record.certificate.claims.identity != identity {
                continue;
            }
            if devices.len() >= V1_MAX_DEVICES {
                return Err(ClientError::Discovery(
                    "injected v1 device listing exceeds limit".to_owned(),
                ));
            }
            record.verify(
                &identity,
                now_seconds(),
                self.allow_insecure_loopback_relay,
                None,
            )?;
            devices.push(ResolvedV1Device {
                path: record.path()?,
                record: record.clone(),
            });
        }
        devices.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(devices)
    }

    async fn fetch_device_record(&self, identity: &str, path: &str) -> Result<ResolvedV1Device> {
        self.note_request();
        let identity = canonical_identity(identity)?;
        validate_device_path(path)?;
        let record = self
            .state
            .records
            .read()
            .await
            .get(&storage_key(&identity, path))
            .cloned()
            .ok_or_else(|| ClientError::Discovery("v1 device record not found".to_owned()))?;
        record.verify(
            &identity,
            now_seconds(),
            self.allow_insecure_loopback_relay,
            None,
        )?;
        if record.path()? != path {
            return Err(ClientError::UnexpectedPeer);
        }
        Ok(ResolvedV1Device {
            path: path.to_owned(),
            record,
        })
    }

    async fn fetch_currentness_proof(
        &self,
        identity: &str,
        path: &str,
    ) -> Result<V1SignedCurrentnessProof> {
        self.note_request();
        let identity = canonical_identity(identity)?;
        validate_currentness_path(path)?;
        self.state
            .proofs
            .read()
            .await
            .get(&storage_key(&identity, path))
            .cloned()
            .ok_or_else(|| ClientError::Discovery("v1 currentness proof not found".to_owned()))
    }

    async fn publish_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()> {
        let encoded =
            serde_json::to_vec(proof).map_err(|error| ClientError::Discovery(error.to_string()))?;
        if encoded.len() > V1_MAX_CURRENTNESS_PROOF_BYTES {
            return Err(ClientError::Discovery(
                "v1 currentness proof exceeds publication limit".to_owned(),
            ));
        }
        let path = proof.path()?;
        self.state
            .proofs
            .write()
            .await
            .insert(storage_key(&self.local_identity, &path), proof.clone());
        Ok(())
    }

    async fn delete_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()> {
        let path = proof.path()?;
        self.state
            .proofs
            .write()
            .await
            .remove(&storage_key(&self.local_identity, &path));
        Ok(())
    }

    async fn commit_remote_record(&self, device: &ResolvedV1Device) -> Result<()> {
        let identity = device.record.certificate.claims.identity.clone();
        device.record.verify(
            &identity,
            now_seconds(),
            self.allow_insecure_loopback_relay,
            None,
        )?;
        if device.record.path()? != device.path {
            return Err(ClientError::UnexpectedPeer);
        }
        self.sequences
            .record_batch(vec![record_observation(&device.record)?])
            .await
    }
}

/// Publish one exact verified device record under its hash-derived path.
///
/// # Errors
///
/// Returns an error unless the session owns the record and the write succeeds.
pub async fn publish_v1_device_record(
    session: &PubkySession,
    record: &V1DeviceRecord,
    allow_insecure_loopback_relay: bool,
) -> Result<()> {
    let identity = session.public_key().z32();
    record.verify(
        &identity,
        now_seconds(),
        allow_insecure_loopback_relay,
        None,
    )?;
    let encoded =
        serde_json::to_vec(record).map_err(|error| ClientError::Discovery(error.to_string()))?;
    if encoded.len() > V1_MAX_DEVICE_RECORD_BYTES {
        return Err(ClientError::Discovery(
            "v1 device record exceeds publication limit".to_owned(),
        ));
    }
    session
        .storage()
        .put(record.path()?, encoded)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

/// Delete exactly the hash-derived path of one supplied device record.
///
/// # Errors
///
/// Returns an error unless the session owns the record or deletion fails.
pub async fn delete_v1_device_record(
    session: &PubkySession,
    record: &V1DeviceRecord,
) -> Result<()> {
    if session.public_key().z32() != record.certificate.claims.identity {
        return Err(ClientError::UnexpectedPeer);
    }
    session
        .storage()
        .delete(record.path()?)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

/// Publish a bounded proof under its exact hash-derived path.
///
/// The handshake verifies the proof against the local identity and exact records before calling
/// this storage-only helper.
///
/// # Errors
///
/// Returns an error for an invalid path, oversized proof, or failed write.
pub async fn publish_v1_currentness_proof(
    session: &PubkySession,
    proof: &V1SignedCurrentnessProof,
) -> Result<()> {
    let encoded =
        serde_json::to_vec(proof).map_err(|error| ClientError::Discovery(error.to_string()))?;
    if encoded.len() > V1_MAX_CURRENTNESS_PROOF_BYTES {
        return Err(ClientError::Discovery(
            "v1 currentness proof exceeds publication limit".to_owned(),
        ));
    }
    session
        .storage()
        .put(proof.path()?, encoded)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

/// Delete exactly the path derived from a supplied currentness proof.
///
/// # Errors
///
/// Returns an error for an invalid proof path or failed deletion.
pub async fn delete_v1_currentness_proof(
    session: &PubkySession,
    proof: &V1SignedCurrentnessProof,
) -> Result<()> {
    session
        .storage()
        .delete(proof.path()?)
        .await
        .map_err(|error| ClientError::Discovery(error.to_string()))?;
    Ok(())
}

fn record_observation(record: &V1DeviceRecord) -> Result<AuthenticatedSequenceObservation> {
    let encoded = record.digest()?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&encoded)
        .map_err(|_| ClientError::State("invalid v1 record digest".to_owned()))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(ClientError::State(
            "non-canonical v1 record digest".to_owned(),
        ));
    }
    let digest = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ClientError::State("invalid v1 record digest length".to_owned()))?;
    AuthenticatedSequenceObservation::new(
        record.certificate.claims.identity.clone(),
        format!(
            "v1:locator:{}",
            record.certificate.claims.control_signing_key
        ),
        record.locator.claims.sequence,
        digest,
    )
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

fn validate_hash_path(path: &str, prefix: &str, label: &'static str) -> Result<()> {
    let Some(name) = path.strip_prefix(prefix) else {
        return Err(ClientError::Discovery(format!("invalid {label} path")));
    };
    let Some(digest) = name.strip_suffix(".json") else {
        return Err(ClientError::Discovery(format!("invalid {label} path")));
    };
    if digest.contains('/') {
        return Err(ClientError::Discovery(format!("invalid {label} path")));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(digest)
        .map_err(|_| ClientError::Discovery(format!("invalid {label} path")))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != digest {
        return Err(ClientError::Discovery(format!("invalid {label} path")));
    }
    Ok(())
}

fn validate_device_path(path: &str) -> Result<()> {
    validate_hash_path(path, V1_DEVICE_RECORD_PATH_PREFIX, "v1 device record")
}

fn validate_currentness_path(path: &str) -> Result<()> {
    validate_hash_path(path, V1_CURRENTNESS_PATH_PREFIX, "v1 currentness proof")
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
            "invalid v1 public-storage path".to_owned(),
        ));
    }
    Ok(format!("pubky://{identity}{path}"))
}

fn storage_key(identity: &str, path: &str) -> String {
    format!("{identity}:{path}")
}

#[cfg(test)]
mod tests {
    use pubky::{Capability, ClientId, GrantClaims, GrantId, Keypair};
    use pubky2pubky_protocol::{V1DeviceCredential, V1GrantAuthorization, V1SignedLocator};
    use url::Url;

    use super::*;
    use crate::MemorySequenceStore;

    fn test_record(
        root: &Keypair,
        cnf: &Keypair,
        sequence: u64,
    ) -> (V1DeviceCredential, V1DeviceRecord) {
        let now = now_seconds();
        let claims = GrantClaims {
            iss: root.public_key(),
            client_id: ClientId::new("test.example")
                .unwrap_or_else(|error| panic!("client id: {error}")),
            caps: vec![
                Capability::write("/pub/pubky2pubky/")
                    .unwrap_or_else(|error| panic!("capability: {error}")),
            ],
            cnf: cnf.public_key(),
            jti: GrantId::generate(),
            iat: now.saturating_sub(10),
            exp: now + 3_600,
        };
        let authorization = V1GrantAuthorization::from_jws(
            claims.sign(root, "pubky-grant"),
            &root.public_key().z32(),
            now,
        )
        .unwrap_or_else(|error| panic!("authorization: {error}"));
        let credential = V1DeviceCredential::issue(
            authorization,
            &root.public_key().z32(),
            cnf,
            "test",
            now,
            now + 1_800,
        )
        .unwrap_or_else(|error| panic!("credential: {error}"));
        let locator = V1SignedLocator::sign(
            &credential,
            vec![
                Url::parse("https://relay.example/")
                    .unwrap_or_else(|error| panic!("relay: {error}")),
            ],
            pubky2pubky_protocol::v1_random_challenge(),
            sequence,
            now,
            now + 600,
        )
        .unwrap_or_else(|error| panic!("locator: {error}"));
        let record = V1DeviceRecord::new(&credential, locator, now, false)
            .unwrap_or_else(|error| panic!("record: {error}"));
        (credential, record)
    }

    #[tokio::test]
    async fn static_resolver_is_exact_bounded_and_commits_digest_equivocation() {
        let root = Keypair::random();
        let cnf = Keypair::random();
        let sequences = Arc::new(MemorySequenceStore::default());
        let resolver = StaticV1Resolver::new(&root.public_key().z32(), sequences, false)
            .unwrap_or_else(|error| panic!("resolver: {error}"));
        let (credential, record) = test_record(&root, &cnf, 1);
        let path = resolver
            .insert_record(record.clone())
            .await
            .unwrap_or_else(|error| panic!("insert: {error}"));
        let devices = resolver
            .resolve_devices(&root.public_key().z32())
            .await
            .unwrap_or_else(|error| panic!("resolve: {error}"));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].path, path);
        resolver
            .commit_remote_record(&devices[0])
            .await
            .unwrap_or_else(|error| panic!("commit: {error}"));
        resolver
            .commit_remote_record(&devices[0])
            .await
            .unwrap_or_else(|error| panic!("repeat: {error}"));

        let now = now_seconds();
        let changed_locator = V1SignedLocator::sign(
            &credential,
            vec![
                Url::parse("https://other-relay.example/")
                    .unwrap_or_else(|error| panic!("relay: {error}")),
            ],
            pubky2pubky_protocol::v1_random_challenge(),
            1,
            now,
            now + 600,
        )
        .unwrap_or_else(|error| panic!("locator: {error}"));
        let equivocation = V1DeviceRecord::new(&credential, changed_locator, now, false)
            .unwrap_or_else(|error| panic!("equivocation: {error}"));
        let equivocation = ResolvedV1Device {
            path: equivocation
                .path()
                .unwrap_or_else(|error| panic!("path: {error}")),
            record: equivocation,
        };
        assert!(resolver.commit_remote_record(&equivocation).await.is_err());
    }

    #[test]
    fn path_validation_rejects_traversal_and_noncanonical_hashes() {
        assert!(validate_device_path("/pub/pubky2pubky/v1/devices/../x.json").is_err());
        assert!(validate_currentness_path("/pub/pubky2pubky/v1/currentness/a=.json").is_err());
        assert!(addressed("not-a-pubky", V1_DEVICE_RECORD_PATH_PREFIX).is_err());
    }
}
