//! Grant-authorized iroh QUIC peer transport for protocol v1.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::FutureExt as _;
#[cfg(not(target_arch = "wasm32"))]
use iroh::tls::CaTlsConfig;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    TransportAddr,
    endpoint::{Connection, QuicTransportConfig, RecvStream, SendStream, VarInt, presets},
};
use n0_future::{
    task::{JoinHandle, spawn},
    time::{self, Instant},
};
use pubky2pubky_protocol::{
    V1_IROH_ALPN, V1_MAX_ACK_BYTES, V1_MAX_CURRENTNESS_LIFETIME_SECONDS,
    V1_MAX_HANDSHAKE_LIFETIME_SECONDS, V1_MAX_HELLO_BYTES, V1_MAX_LOCATOR_LIFETIME_SECONDS,
    V1_PROTOCOL_VERSION, V1CurrentnessRole, V1DeviceCredential, V1DeviceRecord, V1SignedAck,
    V1SignedCurrentnessProof, V1SignedHello, V1SignedLocator, now_seconds, v1_currentness_path,
    v1_random_challenge,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::{
    ClientError, IrohRelayConfig, PathPolicy, Peer, PublicContactDisclosure,
    PublisherSequenceStore, ResolvedV1Device, Result, V1DeviceResolver,
};

const MAX_APPLICATIONS: usize = 16;
const MAX_TRUSTED_RELAYS: usize = 4;
const MAX_CA_CERTIFICATES: usize = 16;
const MAX_CA_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_AUTH_TOKEN_BYTES: usize = 4 * 1024;
const MAX_BROWSER_MESSAGE_BYTES: usize = 64 * 1024;
const DEFAULT_NATIVE_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const PER_CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024;
const MAX_PRE_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_PROOF_CONTROL_BYTES: usize = 4 * 1024;
const MAX_ACTIVE_RECORDS: usize = 8;

/// V1 endpoint, relay, handshake, consent, and resource policy.
#[derive(Debug, Clone)]
pub struct V1ClientConfig {
    /// Whether this endpoint may use direct IP paths or is constrained to an iroh relay.
    pub path_policy: PathPolicy,
    /// Locally trusted exact iroh relay origins. Remote locators can only select this set.
    pub trusted_relays: Vec<IrohRelayConfig>,
    /// Additional local DER CA roots for configured relays; never read from a locator.
    pub relay_ca_certificates: Vec<Vec<u8>>,
    /// Permit exact plain-HTTP loopback relay origins for explicit local tests.
    pub allow_insecure_loopback_relay: bool,
    /// UDP bind addresses used for native direct path discovery and hole punching.
    pub udp_bind_addresses: Vec<SocketAddr>,
    /// Time allowed for the endpoint to become relay-reachable.
    pub endpoint_online_timeout: Duration,
    /// Strict unauthenticated TLS and first-Hello deadline.
    pub pre_hello_timeout: Duration,
    /// Total time allowed to resolve and try a bounded device set.
    pub negotiation_timeout: Duration,
    /// Time allowed for one QUIC connection and the complete mutual-proof handshake.
    pub peer_handshake_timeout: Duration,
    /// Maximum post-authentication application message size.
    pub max_message_bytes: usize,
    /// Maximum simultaneous unauthenticated inbound handshakes.
    pub max_unauthenticated_handshakes: usize,
    /// Maximum offline-authenticated Hellos waiting for application consent.
    pub incoming_queue_capacity: usize,
    /// Maximum queued consent requests from one authenticated Pubky identity.
    pub max_pending_per_identity: usize,
    /// Maximum unexpired authenticated Hello replay entries.
    pub replay_cache_capacity: usize,
    /// Maximum replay entries retained for one Pubky identity.
    pub replay_cache_per_identity_capacity: usize,
    /// Exact application identifiers accepted on inbound v1 connections.
    pub accepted_applications: Vec<String>,
    disclosure: PublicContactDisclosure,
}

impl V1ClientConfig {
    /// Construct native direct-with-relay-fallback policy after explicit privacy acknowledgement.
    #[must_use]
    pub fn direct(disclosure: PublicContactDisclosure, accepted_applications: Vec<String>) -> Self {
        Self {
            path_policy: PathPolicy::DirectWithRelayFallback,
            trusted_relays: Vec::new(),
            relay_ca_certificates: Vec::new(),
            allow_insecure_loopback_relay: false,
            udp_bind_addresses: vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            endpoint_online_timeout: Duration::from_secs(15),
            pre_hello_timeout: Duration::from_secs(3),
            negotiation_timeout: Duration::from_secs(30),
            peer_handshake_timeout: Duration::from_secs(20),
            max_message_bytes: DEFAULT_NATIVE_MESSAGE_BYTES,
            max_unauthenticated_handshakes: 16,
            incoming_queue_capacity: 16,
            max_pending_per_identity: 2,
            replay_cache_capacity: 1_024,
            replay_cache_per_identity_capacity: 32,
            accepted_applications,
            disclosure,
        }
    }

    /// Construct relay-only policy after acknowledging relay-visible contact metadata.
    ///
    /// This is the only policy accepted by browser Wasm builds. Iroh terminates authenticated
    /// QUIC in the browser and the relay carries ciphertext only.
    #[must_use]
    pub fn relay_only(
        disclosure: PublicContactDisclosure,
        accepted_applications: Vec<String>,
    ) -> Self {
        Self {
            path_policy: PathPolicy::RelayOnly,
            trusted_relays: Vec::new(),
            relay_ca_certificates: Vec::new(),
            allow_insecure_loopback_relay: false,
            udp_bind_addresses: Vec::new(),
            endpoint_online_timeout: Duration::from_secs(15),
            pre_hello_timeout: Duration::from_secs(3),
            negotiation_timeout: Duration::from_secs(30),
            peer_handshake_timeout: Duration::from_secs(20),
            max_message_bytes: if cfg!(target_arch = "wasm32") {
                MAX_BROWSER_MESSAGE_BYTES
            } else {
                DEFAULT_NATIVE_MESSAGE_BYTES
            },
            max_unauthenticated_handshakes: 16,
            incoming_queue_capacity: 16,
            max_pending_per_identity: 2,
            replay_cache_capacity: 1_024,
            replay_cache_per_identity_capacity: 32,
            accepted_applications,
            disclosure,
        }
    }

    /// Privacy acknowledgement used to construct this configuration.
    #[must_use]
    pub const fn public_contact_disclosure(&self) -> PublicContactDisclosure {
        self.disclosure
    }

    #[allow(
        clippy::too_many_lines,
        reason = "transport privacy, relay, and resource bounds form one policy validation"
    )]
    fn validate(&self) -> Result<()> {
        match (self.path_policy, self.disclosure) {
            (
                PathPolicy::DirectWithRelayFallback,
                PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
            )
            | (
                PathPolicy::RelayOnly,
                PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            ) => {}
            _ => {
                return Err(ClientError::Iroh(
                    "v1 path policy does not match its privacy acknowledgement".to_owned(),
                ));
            }
        }
        #[cfg(target_arch = "wasm32")]
        self.validate_browser_constraints()?;
        if self.trusted_relays.is_empty() || self.trusted_relays.len() > MAX_TRUSTED_RELAYS {
            return Err(ClientError::Iroh(
                "v1 requires one to four locally trusted relays".to_owned(),
            ));
        }
        let mut relay_origins = HashSet::new();
        for relay in &self.trusted_relays {
            validate_trusted_relay_url(&relay.url, self.allow_insecure_loopback_relay)?;
            if !relay_origins.insert(origin(&relay.url)?) {
                return Err(ClientError::Iroh(
                    "duplicate v1 trusted relay origin".to_owned(),
                ));
            }
            if relay
                .auth_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_AUTH_TOKEN_BYTES)
            {
                return Err(ClientError::Iroh(
                    "invalid local v1 relay authentication token".to_owned(),
                ));
            }
        }
        if self.relay_ca_certificates.len() > MAX_CA_CERTIFICATES
            || self.relay_ca_certificates.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_CA_CERTIFICATE_BYTES
            })
        {
            return Err(ClientError::Iroh(
                "invalid local v1 relay CA certificate set".to_owned(),
            ));
        }
        match self.path_policy {
            PathPolicy::DirectWithRelayFallback => {
                if self.udp_bind_addresses.is_empty() || self.udp_bind_addresses.len() > 2 {
                    return Err(ClientError::Iroh(
                        "v1 direct mode requires one or two UDP bind addresses".to_owned(),
                    ));
                }
                let mut families = HashSet::new();
                if self
                    .udp_bind_addresses
                    .iter()
                    .any(|address| !families.insert(address.is_ipv4()))
                {
                    return Err(ClientError::Iroh(
                        "v1 accepts at most one UDP bind per IP family".to_owned(),
                    ));
                }
            }
            PathPolicy::RelayOnly if !self.udp_bind_addresses.is_empty() => {
                return Err(ClientError::Iroh(
                    "v1 relay-only mode forbids UDP bind addresses".to_owned(),
                ));
            }
            PathPolicy::RelayOnly => {}
        }
        if self.endpoint_online_timeout.is_zero()
            || self.pre_hello_timeout.is_zero()
            || self.negotiation_timeout.is_zero()
            || self.peer_handshake_timeout.is_zero()
            || self.endpoint_online_timeout > MAX_TIMEOUT
            || self.pre_hello_timeout > MAX_PRE_HELLO_TIMEOUT
            || self.negotiation_timeout > MAX_TIMEOUT
            || self.peer_handshake_timeout > MAX_TIMEOUT
            || self.max_message_bytes == 0
            || self.max_message_bytes > u32::MAX as usize
            || !(1..=64).contains(&self.max_unauthenticated_handshakes)
            || !(1..=64).contains(&self.incoming_queue_capacity)
            || !(1..=self.incoming_queue_capacity).contains(&self.max_pending_per_identity)
            || !(1..=4_096).contains(&self.replay_cache_capacity)
            || !(1..=self.replay_cache_capacity).contains(&self.replay_cache_per_identity_capacity)
        {
            return Err(ClientError::Iroh(
                "invalid v1 client resource bounds".to_owned(),
            ));
        }
        if self.accepted_applications.is_empty()
            || self.accepted_applications.len() > MAX_APPLICATIONS
        {
            return Err(ClientError::Iroh(
                "v1 requires a bounded inbound application allowlist".to_owned(),
            ));
        }
        let mut applications = HashSet::new();
        for application in &self.accepted_applications {
            validate_application(application)?;
            if !applications.insert(application) {
                return Err(ClientError::Iroh(
                    "duplicate v1 inbound application".to_owned(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn validate_browser_constraints(&self) -> Result<()> {
        if self.path_policy != PathPolicy::RelayOnly
            || !self.relay_ca_certificates.is_empty()
            || self
                .trusted_relays
                .iter()
                .any(|relay| relay.auth_token.is_some())
            || self.max_message_bytes > MAX_BROWSER_MESSAGE_BYTES
        {
            return Err(ClientError::Iroh(
                "browser v1 requires relay-only transport without tokens, custom CAs, or oversized messages"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofReady {
    version: u16,
    challenge: String,
    initiator_proof_path: String,
    responder_proof_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofConfirmed {
    version: u16,
    challenge: String,
    initiator_proof_path: String,
    responder_proof_path: String,
}

struct AbortTask(JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct V1Inner {
    credential: Arc<V1DeviceCredential>,
    endpoint: Endpoint,
    resolver: Arc<dyn V1DeviceResolver>,
    config: V1ClientConfig,
    pending: Arc<PendingQueue>,
    active_records: Arc<Mutex<HashMap<String, V1DeviceRecord>>>,
    instance_nonce: String,
    _accept_task: AbortTask,
}

/// Pubky-discovered iroh v1 endpoint for native or relay-only browser peers.
///
/// Every returned [`Peer`] uses one bounded stream over authenticated TLS 1.3 QUIC with the exact
/// v1 ALPN. Inbound Hello verification is fully offline before consent. After consent, both peers
/// must prove live identity-level homeserver write authority using the Ack's fresh challenge. The
/// proof does not claim the embedded Grant itself was checked for revocation by the homeserver.
#[derive(Clone)]
pub struct V1Client {
    inner: Arc<V1Inner>,
}

struct PendingV1 {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    local: Arc<V1DeviceCredential>,
    resolver: Arc<dyn V1DeviceResolver>,
    sender: ResolvedV1Device,
    target: ResolvedV1Device,
    hello: V1SignedHello,
    max_message_bytes: usize,
    allow_insecure_loopback_relay: bool,
    deadline: Instant,
    expiry_cancel: Option<oneshot::Sender<()>>,
    _capacity_permit: OwnedSemaphorePermit,
}

/// An offline-authenticated v1 Hello awaiting explicit application consent.
///
/// No Pubky resolver, PKARR, DNS, redirect, HTTP, or other sender-chosen network operation has
/// occurred. Rejecting, dropping, or allowing the deadline to expire closes the QUIC connection.
pub struct IncomingV1 {
    pending: Option<PendingV1>,
}

impl std::fmt::Debug for IncomingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = formatter.debug_struct("IncomingV1");
        if let Some(pending) = &self.pending {
            value
                .field("identity", &pending.hello.claims.from_identity)
                .field("device_id", &pending.hello.claims.from_device_id)
                .field("application", &pending.hello.claims.application);
        }
        value.finish_non_exhaustive()
    }
}

impl IncomingV1 {
    /// Root-authorized caller Pubky identity verified entirely offline.
    #[must_use]
    pub fn identity(&self) -> &str {
        self.pending
            .as_ref()
            .map_or("", |pending| &pending.hello.claims.from_identity)
    }

    /// Grant-authorized caller device id verified entirely offline.
    #[must_use]
    pub fn device_id(&self) -> &str {
        self.pending
            .as_ref()
            .map_or("", |pending| &pending.hello.claims.from_device_id)
    }

    /// Authenticated requested application identifier.
    #[must_use]
    pub fn application(&self) -> &str {
        self.pending
            .as_ref()
            .map_or("", |pending| &pending.hello.claims.application)
    }

    /// Consent and complete the two-sided homeserver currentness exchange.
    ///
    /// The first resolver read involving the caller occurs only after entering this method. The
    /// returned [`Peer`] is released only after the initiator proof is fetched and verified, the
    /// remote record observation commits atomically, and `ProofConfirmed` is sent.
    ///
    /// # Errors
    ///
    /// Returns an error on expiry, publication/fetch failure, invalid proof, rollback,
    /// equivocation, confirmation failure, or transport failure.
    pub async fn accept(mut self) -> Result<Peer> {
        let pending = self.pending.take().ok_or(ClientError::ChannelClosed)?;
        let connection = pending.connection.clone();
        let result = accept_pending(pending).await;
        if result.is_err() {
            connection.close(1u32.into(), b"v1 accepted handshake failed");
        }
        result
    }

    /// Reject without sending an Ack or an application-controlled reason.
    pub fn reject(mut self) {
        if let Some(pending) = self.pending.take() {
            pending
                .connection
                .close(1u32.into(), b"application rejected v1 Hello");
        }
    }
}

impl Drop for IncomingV1 {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending
                .connection
                .close(1u32.into(), b"application dropped v1 Hello");
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the proof exchange deliberately keeps its confirmation barrier in one transaction"
)]
async fn accept_pending(mut pending: PendingV1) -> Result<Peer> {
    pending.expiry_cancel.take();
    let Some(remaining) = pending.deadline.checked_duration_since(Instant::now()) else {
        return Err(ClientError::Timeout("accepting inbound v1 peer"));
    };
    let now = now_seconds();
    let expires_at = pending
        .hello
        .claims
        .expires_at
        .min(now.saturating_add(V1_MAX_CURRENTNESS_LIFETIME_SECONDS));
    if expires_at <= now {
        return Err(ClientError::Timeout("accepting inbound v1 peer"));
    }
    let challenge = v1_random_challenge();
    let ack = if pending.allow_insecure_loopback_relay {
        V1SignedAck::sign_for_local_development(
            &pending.local,
            &pending.hello,
            &pending.sender.record,
            &pending.target.record,
            challenge.clone(),
            now,
            expires_at,
        )?
    } else {
        V1SignedAck::sign(
            &pending.local,
            &pending.hello,
            &pending.sender.record,
            &pending.target.record,
            challenge.clone(),
            now,
            expires_at,
        )?
    };
    let proof = V1SignedCurrentnessProof::sign(
        &pending.local,
        &pending.target.record,
        &pending.sender.record,
        &pending.hello,
        V1CurrentnessRole::Responder,
        challenge.clone(),
        now,
        expires_at,
        pending.allow_insecure_loopback_relay,
    )?;
    pending.resolver.publish_currentness_proof(&proof).await?;
    let operation = async {
        write_json(&mut pending.send, &ack, V1_MAX_ACK_BYTES).await?;
        let ready: ProofReady = read_json(&mut pending.recv, MAX_PROOF_CONTROL_BYTES).await?;
        validate_proof_control(
            ready.version,
            &ready.challenge,
            &challenge,
            &ready.initiator_proof_path,
            &ready.responder_proof_path,
            &pending.hello,
            &pending.sender.record,
            &pending.target.record,
        )?;
        let initiator_proof = pending
            .resolver
            .fetch_currentness_proof(
                &pending.hello.claims.from_identity,
                &ready.initiator_proof_path,
            )
            .await?;
        initiator_proof.verify(
            &pending.sender.record,
            &pending.target.record,
            &pending.hello,
            V1CurrentnessRole::Initiator,
            &challenge,
            now_seconds(),
            pending.allow_insecure_loopback_relay,
        )?;
        pending
            .resolver
            .commit_remote_record(&pending.sender)
            .await?;
        let confirmed = ProofConfirmed {
            version: V1_PROTOCOL_VERSION,
            challenge: challenge.clone(),
            initiator_proof_path: ready.initiator_proof_path,
            responder_proof_path: ready.responder_proof_path,
        };
        write_json(&mut pending.send, &confirmed, MAX_PROOF_CONTROL_BYTES).await?;
        Result::<()>::Ok(())
    };
    let exchange = time::timeout(remaining, operation)
        .await
        .map_err(|_| ClientError::Timeout("completing accepted v1 currentness exchange"))?;
    let _ = pending.resolver.delete_currentness_proof(&proof).await;
    exchange?;

    let session_id = nonce_uuid(&pending.hello.claims.session_nonce)?;
    Ok(Peer::new(
        pending.connection,
        pending.send,
        pending.recv,
        session_id,
        pending.sender.record.certificate.claims.identity.clone(),
        pending.sender.record.certificate.claims.device_id.clone(),
        pending.max_message_bytes,
    ))
}

struct PendingQueueState {
    order: VecDeque<String>,
    entries: HashMap<String, IncomingV1>,
    per_identity: HashMap<String, usize>,
    closed: bool,
}

struct PendingQueue {
    state: Mutex<PendingQueueState>,
    notify: Notify,
    capacity: usize,
    per_identity_capacity: usize,
}

impl PendingQueue {
    fn new(capacity: usize, per_identity_capacity: usize) -> Self {
        Self {
            state: Mutex::new(PendingQueueState {
                order: VecDeque::with_capacity(capacity),
                entries: HashMap::with_capacity(capacity),
                per_identity: HashMap::new(),
                closed: false,
            }),
            notify: Notify::new(),
            capacity,
            per_identity_capacity,
        }
    }

    async fn insert(&self, key: String, incoming: IncomingV1) -> Result<()> {
        let mut state = self.state.lock().await;
        Self::prune_expired(&mut state, Instant::now());
        if state.closed {
            return Err(ClientError::ChannelClosed);
        }
        if state.entries.len() >= self.capacity || state.entries.contains_key(&key) {
            return Err(ClientError::Iroh(
                "authenticated v1 peer queue is full".to_owned(),
            ));
        }
        let identity = incoming.identity().to_owned();
        let count = state.per_identity.get(&identity).copied().unwrap_or(0);
        if count >= self.per_identity_capacity {
            return Err(ClientError::Iroh(
                "authenticated v1 identity pending limit reached".to_owned(),
            ));
        }
        state.per_identity.insert(identity, count + 1);
        state.order.push_back(key.clone());
        state.entries.insert(key, incoming);
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    async fn expire(&self, key: &str) {
        let mut state = self.state.lock().await;
        Self::remove(&mut state, key);
        drop(state);
        self.notify.notify_waiters();
    }

    async fn next(&self) -> Result<IncomingV1> {
        loop {
            let notified = self.notify.notified();
            {
                let mut state = self.state.lock().await;
                Self::prune_expired(&mut state, Instant::now());
                while let Some(key) = state.order.pop_front() {
                    if let Some(incoming) = Self::remove(&mut state, &key) {
                        return Ok(incoming);
                    }
                }
                if state.closed {
                    return Err(ClientError::ChannelClosed);
                }
            }
            notified.await;
        }
    }

    async fn close(&self) {
        let mut state = self.state.lock().await;
        state.closed = true;
        state.order.clear();
        state.per_identity.clear();
        state.entries.clear();
        drop(state);
        self.notify.notify_waiters();
    }

    fn prune_expired(state: &mut PendingQueueState, now: Instant) {
        let expired: Vec<String> = state
            .entries
            .iter()
            .filter(|(_, incoming)| {
                incoming
                    .pending
                    .as_ref()
                    .is_none_or(|pending| pending.deadline <= now)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            Self::remove(state, &key);
        }
    }

    fn remove(state: &mut PendingQueueState, key: &str) -> Option<IncomingV1> {
        let incoming = state.entries.remove(key)?;
        state.order.retain(|queued| queued != key);
        let identity = incoming.identity().to_owned();
        if let Some(count) = state.per_identity.get_mut(&identity) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_identity.remove(&identity);
            }
        }
        Some(incoming)
    }
}

impl std::fmt::Debug for V1Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("V1Client")
            .field("identity", &self.identity())
            .field("device_id", &self.device_id())
            .field("iroh_endpoint_id", &self.iroh_endpoint_id())
            .finish_non_exhaustive()
    }
}

impl V1Client {
    /// Bind a v1 iroh endpoint and start its bounded offline-authentication accept loop.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials/configuration, browser path-policy violations, or
    /// relay registration failure.
    #[allow(
        clippy::too_many_lines,
        reason = "endpoint policy and bounded accept-task setup are one security transaction"
    )]
    pub async fn bind(
        credential: V1DeviceCredential,
        resolver: Arc<dyn V1DeviceResolver>,
        config: V1ClientConfig,
    ) -> Result<Self> {
        config.validate()?;
        credential.verify(now_seconds())?;
        let key_bytes = credential.iroh_secret_key_bytes()?;
        let secret = SecretKey::from_bytes(&key_bytes);
        if secret.public().to_z32() != credential.iroh_endpoint_id() {
            return Err(ClientError::UnexpectedPeer);
        }

        let relay_configs = config
            .trusted_relays
            .iter()
            .map(|trusted| {
                let mut relay = RelayConfig::from(RelayUrl::from(trusted.url.clone()));
                if let Some(token) = &trusted.auth_token {
                    relay = relay.with_auth_token(token);
                }
                relay
            })
            .collect::<Vec<_>>();
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(1))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(PER_CONNECTION_RECEIVE_WINDOW))
            .receive_window(VarInt::from_u32(PER_CONNECTION_RECEIVE_WINDOW))
            .build();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![V1_IROH_ALPN.to_vec()])
            .max_tls_tickets(0)
            .transport_config(transport)
            .relay_mode(RelayMode::Custom(
                relay_configs.into_iter().collect::<RelayMap>(),
            ))
            .clear_address_lookup();
        #[cfg(not(target_arch = "wasm32"))]
        let mut builder = builder.clear_ip_transports();
        #[cfg(target_arch = "wasm32")]
        let builder = builder;
        #[cfg(not(target_arch = "wasm32"))]
        if !config.relay_ca_certificates.is_empty() {
            builder = builder
                .ca_tls_config(CaTlsConfig::default().with_extra_roots(
                    config.relay_ca_certificates.iter().cloned().map(Into::into),
                ));
        }
        #[cfg(not(target_arch = "wasm32"))]
        if config.path_policy == PathPolicy::DirectWithRelayFallback {
            for address in &config.udp_bind_addresses {
                builder = builder
                    .bind_addr(*address)
                    .map_err(|error| ClientError::Iroh(error.to_string()))?;
            }
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        if time::timeout(config.endpoint_online_timeout, endpoint.online())
            .await
            .is_err()
        {
            endpoint.close().await;
            return Err(ClientError::Timeout(
                "registering v1 endpoint with iroh relay",
            ));
        }

        let credential = Arc::new(credential);
        let active_records = Arc::new(Mutex::new(HashMap::new()));
        let replay = Arc::new(Mutex::new(ReplayCache::new(
            config.replay_cache_capacity,
            config.replay_cache_per_identity_capacity,
        )));
        let semaphore = Arc::new(Semaphore::new(config.max_unauthenticated_handshakes));
        let pending = Arc::new(PendingQueue::new(
            config.incoming_queue_capacity,
            config.max_pending_per_identity,
        ));
        let task_endpoint = endpoint.clone();
        let task_credential = Arc::clone(&credential);
        let task_resolver = Arc::clone(&resolver);
        let task_records = Arc::clone(&active_records);
        let task_pending = Arc::clone(&pending);
        let task_config = config.clone();
        let task = spawn(async move {
            while let Some(incoming) = task_endpoint.accept().await {
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    drop(incoming);
                    continue;
                };
                let credential = Arc::clone(&task_credential);
                let resolver = Arc::clone(&task_resolver);
                let records = Arc::clone(&task_records);
                let replay = Arc::clone(&replay);
                let pending = Arc::clone(&task_pending);
                let config = task_config.clone();
                let deadline = Instant::now() + config.pre_hello_timeout;
                drop(spawn(async move {
                    if let Err(error) = handle_incoming_v1(
                        incoming, credential, resolver, records, replay, pending, config, deadline,
                        permit,
                    )
                    .await
                    {
                        debug!(%error, "discarded unauthenticated v1 iroh connection");
                    }
                }));
            }
        });

        Ok(Self {
            inner: Arc::new(V1Inner {
                credential,
                endpoint,
                resolver,
                config,
                pending,
                active_records,
                instance_nonce: v1_random_challenge(),
                _accept_task: AbortTask(task),
            }),
        })
    }

    /// Local Pubky identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        self.inner.credential.identity()
    }

    /// Local Grant-authorized device id.
    #[must_use]
    pub fn device_id(&self) -> &str {
        self.inner.credential.device_id()
    }

    /// Local certified iroh endpoint id.
    #[must_use]
    pub fn iroh_endpoint_id(&self) -> &str {
        self.inner.credential.iroh_endpoint_id()
    }

    /// Grant-`cnf`-signed local device certificate.
    #[must_use]
    pub fn credential(&self) -> &V1DeviceCredential {
        &self.inner.credential
    }

    /// Sign and register a self-contained current device record with an explicit sequence.
    ///
    /// Only locally configured relay URLs are published. Production callers should allocate the
    /// sequence through [`Self::next_record`] using durable transactional state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid sequence/lifetime, expired credential, or signing failure.
    pub async fn current_record(
        &self,
        sequence: u64,
        lifetime: Duration,
    ) -> Result<V1DeviceRecord> {
        let lifetime_seconds = lifetime.as_secs();
        if lifetime_seconds == 0 || lifetime_seconds > V1_MAX_LOCATOR_LIFETIME_SECONDS {
            return Err(ClientError::Iroh(
                "v1 locator lifetime is outside protocol bounds".to_owned(),
            ));
        }
        let now = now_seconds();
        let expires_at = now
            .checked_add(lifetime_seconds)
            .ok_or_else(|| ClientError::Iroh("v1 locator expiry overflow".to_owned()))?;
        let relay_urls = self
            .inner
            .config
            .trusted_relays
            .iter()
            .map(|relay| relay.url.clone())
            .collect();
        let locator = if self.inner.config.allow_insecure_loopback_relay {
            V1SignedLocator::sign_for_local_development(
                &self.inner.credential,
                relay_urls,
                self.inner.instance_nonce.clone(),
                sequence,
                now,
                expires_at,
            )?
        } else {
            V1SignedLocator::sign(
                &self.inner.credential,
                relay_urls,
                self.inner.instance_nonce.clone(),
                sequence,
                now,
                expires_at,
            )?
        };
        let record = V1DeviceRecord::new(
            &self.inner.credential,
            locator,
            now,
            self.inner.config.allow_insecure_loopback_relay,
        )?;
        let digest = record.digest()?;
        let mut active = self.inner.active_records.lock().await;
        active.retain(|_, value| value.locator.claims.expires_at > now);
        if active.len() >= MAX_ACTIVE_RECORDS && !active.contains_key(&digest) {
            let oldest = active
                .iter()
                .min_by_key(|(_, value)| value.locator.claims.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                active.remove(&oldest);
            }
        }
        active.insert(digest, record.clone());
        Ok(record)
    }

    /// Allocate the next durable locator sequence, sign, and register its complete record.
    ///
    /// # Errors
    ///
    /// Returns an error if sequence allocation or record signing fails.
    pub async fn next_record(
        &self,
        sequences: &dyn PublisherSequenceStore,
        lifetime: Duration,
    ) -> Result<V1DeviceRecord> {
        let sequence = sequences
            .next_locator_sequence(self.identity(), self.inner.credential.control_signing_key())
            .await?;
        self.current_record(sequence, lifetime).await
    }

    /// Resolve a user-selected Pubky identity and connect to one device deterministically.
    ///
    /// Every locator relay origin is intersected with the exact local allowlist before any dial.
    /// The returned [`Peer`] is withheld until both homeserver proofs and the final confirmation
    /// complete.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery, relay policy, QUIC, proof exchange, or atomic remote
    /// observation fails.
    pub async fn dial(
        &self,
        target_identity: &str,
        target_device_id: Option<&str>,
        application: &str,
    ) -> Result<Peer> {
        validate_application(application)?;
        time::timeout(
            self.inner.config.negotiation_timeout,
            self.dial_inner(target_identity, target_device_id, application),
        )
        .await
        .map_err(|_| ClientError::Timeout("resolving and connecting to v1 peer"))?
    }

    async fn dial_inner(
        &self,
        target_identity: &str,
        target_device_id: Option<&str>,
        application: &str,
    ) -> Result<Peer> {
        let mut devices = self.inner.resolver.resolve_devices(target_identity).await?;
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
        let candidates: Vec<_> = devices
            .into_iter()
            .filter(|device| {
                target_device_id
                    .is_none_or(|wanted| device.record.certificate.claims.device_id == wanted)
            })
            .take(MAX_ACTIVE_RECORDS)
            .collect();
        if candidates.is_empty() {
            return Err(ClientError::Discovery(
                "requested v1 device is not currently published".to_owned(),
            ));
        }
        let mut failures = 0usize;
        for candidate in candidates {
            match self.dial_device(candidate, application).await {
                Ok(peer) => return Ok(peer),
                Err(_) => failures = failures.saturating_add(1),
            }
        }
        Err(ClientError::Iroh(format!(
            "all {failures} bounded v1 device attempts failed"
        )))
    }

    async fn dial_device(&self, target: ResolvedV1Device, application: &str) -> Result<Peer> {
        let identity = &target.record.certificate.claims.identity;
        target.record.verify(
            identity,
            now_seconds(),
            self.inner.config.allow_insecure_loopback_relay,
            None,
        )?;
        if target.record.path()? != target.path {
            return Err(ClientError::UnexpectedPeer);
        }
        // This intersection occurs before constructing an EndpointAddr or calling iroh. A signed
        // locator can never introduce a new relay origin or turn an attacker-controlled URL into
        // resolver/dial egress.
        let relay_urls = trusted_destination_relays(&target.record.locator, &self.inner.config)?;
        if relay_urls.is_empty() {
            return Err(ClientError::InvalidRelayUrl);
        }
        let expected_id = EndpointId::from_z32(&target.record.certificate.claims.iroh_endpoint_id)
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let address = EndpointAddr::from_parts(
            expected_id,
            relay_urls
                .into_iter()
                .map(|url| TransportAddr::Relay(RelayUrl::from(url))),
        );
        let connection = time::timeout(
            self.inner.config.peer_handshake_timeout,
            self.inner.endpoint.connect(address, V1_IROH_ALPN),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting v1 iroh QUIC peer"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let result = self
            .finish_outbound_handshake(connection.clone(), expected_id, &target, application)
            .await;
        if result.is_err() {
            connection.close(1u32.into(), b"invalid v1 handshake");
        }
        result
    }

    async fn finish_outbound_handshake(
        &self,
        connection: Connection,
        expected_id: EndpointId,
        target: &ResolvedV1Device,
        application: &str,
    ) -> Result<Peer> {
        if connection.remote_id() != expected_id {
            return Err(ClientError::UnexpectedPeer);
        }
        let (mut send, mut recv) = time::timeout(
            self.inner.config.peer_handshake_timeout,
            connection.open_bi(),
        )
        .await
        .map_err(|_| ClientError::Timeout("opening v1 authenticated QUIC stream"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let now = now_seconds();
        let sender_record = {
            let mut active = self.inner.active_records.lock().await;
            active.retain(|_, record| record.locator.claims.expires_at > now);
            active
                .iter()
                .max_by(|(left_digest, left), (right_digest, right)| {
                    left.locator
                        .claims
                        .sequence
                        .cmp(&right.locator.claims.sequence)
                        .then_with(|| left_digest.cmp(right_digest))
                })
                .map(|(_, record)| record.clone())
        }
        .ok_or_else(|| {
            ClientError::State(
                "a current local v1 record must be registered before dialing".to_owned(),
            )
        })?;
        let expiry = now
            .saturating_add(V1_MAX_HANDSHAKE_LIFETIME_SECONDS.min(30))
            .min(sender_record.locator.claims.expires_at)
            .min(target.record.locator.claims.expires_at)
            .min(sender_record.certificate.claims.expires_at)
            .min(target.record.certificate.claims.expires_at);
        if expiry <= now {
            return Err(ClientError::Timeout("creating v1 Hello"));
        }
        let hello = if self.inner.config.allow_insecure_loopback_relay {
            V1SignedHello::sign_for_local_development(
                &self.inner.credential,
                &sender_record,
                &target.record,
                application,
                v1_random_challenge(),
                (now, expiry),
            )?
        } else {
            V1SignedHello::sign(
                &self.inner.credential,
                &sender_record,
                &target.record,
                application,
                v1_random_challenge(),
                (now, expiry),
            )?
        };
        let handshake = self.outbound_proof_exchange(
            &mut send,
            &mut recv,
            &hello,
            &sender_record,
            target,
            application,
        );
        time::timeout(self.inner.config.peer_handshake_timeout, handshake)
            .await
            .map_err(|_| ClientError::Timeout("exchanging v1 Hello and currentness proofs"))??;
        let session_id = nonce_uuid(&hello.claims.session_nonce)?;
        Ok(Peer::new(
            connection,
            send,
            recv,
            session_id,
            target.record.certificate.claims.identity.clone(),
            target.record.certificate.claims.device_id.clone(),
            self.inner.config.max_message_bytes,
        ))
    }

    async fn outbound_proof_exchange(
        &self,
        send: &mut SendStream,
        recv: &mut RecvStream,
        hello: &V1SignedHello,
        sender_record: &V1DeviceRecord,
        target: &ResolvedV1Device,
        application: &str,
    ) -> Result<()> {
        write_json(send, hello, V1_MAX_HELLO_BYTES).await?;
        let ack: V1SignedAck = read_json(recv, V1_MAX_ACK_BYTES).await?;
        ack.verify(
            &target.record,
            sender_record,
            hello,
            application,
            now_seconds(),
            self.inner.config.allow_insecure_loopback_relay,
        )?;
        let challenge = ack.claims.responder_nonce.clone();
        let proof = V1SignedCurrentnessProof::sign(
            &self.inner.credential,
            sender_record,
            &target.record,
            hello,
            V1CurrentnessRole::Initiator,
            challenge.clone(),
            ack.claims.issued_at,
            ack.claims.expires_at,
            self.inner.config.allow_insecure_loopback_relay,
        )?;
        self.inner
            .resolver
            .publish_currentness_proof(&proof)
            .await?;
        let operation = async {
            let initiator_path = proof.path()?;
            let responder_path = currentness_path(
                V1CurrentnessRole::Responder,
                &challenge,
                hello,
                &target.record,
            )?;
            let responder_proof = self
                .inner
                .resolver
                .fetch_currentness_proof(
                    &target.record.certificate.claims.identity,
                    &responder_path,
                )
                .await?;
            responder_proof.verify(
                &target.record,
                sender_record,
                hello,
                V1CurrentnessRole::Responder,
                &challenge,
                now_seconds(),
                self.inner.config.allow_insecure_loopback_relay,
            )?;
            let ready = ProofReady {
                version: V1_PROTOCOL_VERSION,
                challenge: challenge.clone(),
                initiator_proof_path: initiator_path.clone(),
                responder_proof_path: responder_path.clone(),
            };
            write_json(send, &ready, MAX_PROOF_CONTROL_BYTES).await?;
            let confirmed: ProofConfirmed = read_json(recv, MAX_PROOF_CONTROL_BYTES).await?;
            if confirmed.version != V1_PROTOCOL_VERSION
                || confirmed.challenge != challenge
                || confirmed.initiator_proof_path != initiator_path
                || confirmed.responder_proof_path != responder_path
            {
                return Err(ClientError::UnexpectedPeer);
            }
            self.inner.resolver.commit_remote_record(target).await?;
            Result::<()>::Ok(())
        };
        let result = operation.await;
        let _ = self.inner.resolver.delete_currentness_proof(&proof).await;
        result
    }

    /// Receive the next offline-authenticated Hello for an explicit consent decision.
    ///
    /// # Errors
    ///
    /// Returns an error after this endpoint is closed.
    pub async fn next_incoming(&self) -> Result<IncomingV1> {
        self.inner.pending.next().await
    }

    /// Alias for [`Self::next_incoming`].
    ///
    /// # Errors
    ///
    /// Returns an error after this endpoint is closed.
    pub async fn accept(&self) -> Result<IncomingV1> {
        self.next_incoming().await
    }

    /// Close the endpoint and all queued consent requests.
    pub async fn close(&self) {
        self.inner.pending.close().await;
        self.inner.endpoint.close().await;
    }
}

#[derive(Debug)]
struct ReplayCache {
    capacity: usize,
    per_identity_capacity: usize,
    entries: HashMap<String, ReplayEntry>,
}

#[derive(Debug)]
struct ReplayEntry {
    identity: String,
    expires_at: u64,
}

impl ReplayCache {
    fn new(capacity: usize, per_identity_capacity: usize) -> Self {
        Self {
            capacity,
            per_identity_capacity,
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, key: String, identity: String, expires_at: u64, now: u64) -> Result<()> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        if self.entries.contains_key(&key) {
            return Err(ClientError::UnexpectedPeer);
        }
        if self.entries.len() >= self.capacity {
            return Err(ClientError::Iroh(
                "v1 replay cache reached its authenticated-entry limit".to_owned(),
            ));
        }
        if self
            .entries
            .values()
            .filter(|entry| entry.identity == identity)
            .count()
            >= self.per_identity_capacity
        {
            return Err(ClientError::Iroh(
                "v1 replay cache reached its per-identity limit".to_owned(),
            ));
        }
        self.entries.insert(
            key,
            ReplayEntry {
                identity,
                expires_at,
            },
        );
        Ok(())
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_v1(
    incoming: iroh::endpoint::Incoming,
    local: Arc<V1DeviceCredential>,
    resolver: Arc<dyn V1DeviceResolver>,
    active_records: Arc<Mutex<HashMap<String, V1DeviceRecord>>>,
    replay: Arc<Mutex<ReplayCache>>,
    pending_queue: Arc<PendingQueue>,
    config: V1ClientConfig,
    pre_hello_deadline: Instant,
    capacity_permit: OwnedSemaphorePermit,
) -> Result<()> {
    let connection = timeout_at(pre_hello_deadline, async move { incoming.await })
        .await
        .map_err(|_| ClientError::Timeout("pre-authenticating inbound v1 QUIC"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let result = authenticate_incoming_v1(
        connection.clone(),
        local,
        resolver,
        active_records,
        replay,
        pending_queue,
        &config,
        pre_hello_deadline,
        capacity_permit,
    )
    .await;
    if result.is_err() {
        connection.close(1u32.into(), b"invalid v1 handshake");
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_incoming_v1(
    connection: Connection,
    local: Arc<V1DeviceCredential>,
    resolver: Arc<dyn V1DeviceResolver>,
    active_records: Arc<Mutex<HashMap<String, V1DeviceRecord>>>,
    replay: Arc<Mutex<ReplayCache>>,
    pending_queue: Arc<PendingQueue>,
    config: &V1ClientConfig,
    pre_hello_deadline: Instant,
    capacity_permit: OwnedSemaphorePermit,
) -> Result<()> {
    let remote_endpoint = connection.remote_id();
    let (send, recv, hello) = receive_initial_hello(&connection, pre_hello_deadline).await?;
    let operation = async {
        if !config
            .accepted_applications
            .iter()
            .any(|application| application == &hello.claims.application)
        {
            return Err(ClientError::UnexpectedPeer);
        }
        let target = {
            let mut records = active_records.lock().await;
            let now = now_seconds();
            records.retain(|_, record| record.locator.claims.expires_at > now);
            records
                .get(&hello.claims.target_device_record_digest)
                .cloned()
        }
        .ok_or(ClientError::UnexpectedPeer)?;
        let sender_record = hello.claims.from_device_record.clone();
        hello.verify(
            &sender_record,
            &target,
            &hello.claims.application,
            now_seconds(),
            config.allow_insecure_loopback_relay,
        )?;
        if target.certificate != local.certificate
            || target.authorization != local.authorization
            || target.certificate.claims.identity != local.identity()
        {
            return Err(ClientError::UnexpectedPeer);
        }
        let certified_remote =
            EndpointId::from_z32(&sender_record.certificate.claims.iroh_endpoint_id)
                .map_err(|error| ClientError::Iroh(error.to_string()))?;
        if certified_remote != remote_endpoint {
            return Err(ClientError::UnexpectedPeer);
        }
        let deadline = pending_deadline(
            hello.claims.expires_at,
            config.peer_handshake_timeout,
            now_seconds(),
        )?;
        let replay_key = reserve_replay(&replay, &hello).await?;
        let (expiry_cancel, cancelled) = oneshot::channel();
        let expiry_connection = connection.clone();
        let admission = pending_queue
            .insert(
                replay_key.clone(),
                IncomingV1 {
                    pending: Some(PendingV1 {
                        connection,
                        send,
                        recv,
                        local,
                        resolver,
                        sender: ResolvedV1Device {
                            path: sender_record.path()?,
                            record: sender_record,
                        },
                        target: ResolvedV1Device {
                            path: target.path()?,
                            record: target,
                        },
                        hello,
                        max_message_bytes: config.max_message_bytes,
                        allow_insecure_loopback_relay: config.allow_insecure_loopback_relay,
                        deadline,
                        expiry_cancel: Some(expiry_cancel),
                        _capacity_permit: capacity_permit,
                    }),
                },
            )
            .await;
        if let Err(error) = admission {
            replay.lock().await.remove(&replay_key);
            return Err(error);
        }
        spawn_pending_expiry(
            &pending_queue,
            replay_key,
            deadline,
            expiry_connection,
            cancelled,
        );
        Ok(())
    };
    // This entire operation is offline. In particular, no method on `resolver` is called with a
    // remotely supplied identity before application consent.
    time::timeout(config.peer_handshake_timeout, operation)
        .await
        .map_err(|_| ClientError::Timeout("authenticating signed inbound v1 Hello"))?
}

async fn receive_initial_hello(
    connection: &Connection,
    deadline: Instant,
) -> Result<(SendStream, RecvStream, V1SignedHello)> {
    timeout_at(deadline, async {
        let (send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        if recv.is_0rtt() {
            return Err(ClientError::UnexpectedPeer);
        }
        let hello = read_json(&mut recv, V1_MAX_HELLO_BYTES).await?;
        Ok((send, recv, hello))
    })
    .await
    .map_err(|_| ClientError::Timeout("receiving initial v1 Hello"))?
}

async fn reserve_replay(replay: &Arc<Mutex<ReplayCache>>, hello: &V1SignedHello) -> Result<String> {
    let key = format!(
        "{}:{}",
        hello.claims.from_control_signing_key, hello.claims.session_nonce
    );
    replay.lock().await.insert(
        key.clone(),
        hello.claims.from_identity.clone(),
        hello.claims.expires_at,
        now_seconds(),
    )?;
    Ok(key)
}

fn pending_deadline(expires_at: u64, limit: Duration, now: u64) -> Result<Instant> {
    let lifetime = limit.min(Duration::from_secs(expires_at.saturating_sub(now)));
    if lifetime.is_zero() {
        return Err(ClientError::Timeout("queueing inbound v1 consent"));
    }
    Ok(Instant::now() + lifetime)
}

fn spawn_pending_expiry(
    pending_queue: &Arc<PendingQueue>,
    replay_key: String,
    deadline: Instant,
    connection: Connection,
    cancelled: oneshot::Receiver<()>,
) {
    let weak_queue: Weak<PendingQueue> = Arc::downgrade(pending_queue);
    drop(spawn(async move {
        let timeout = time::sleep_until(deadline).fuse();
        let cancelled = cancelled.fuse();
        futures_util::pin_mut!(timeout, cancelled);
        futures_util::select_biased! {
            _ = cancelled => {}
            () = timeout => {
                if let Some(queue) = weak_queue.upgrade() {
                    queue.expire(&replay_key).await;
                }
                connection.close(1u32.into(), b"v1 consent timeout");
            }
        }
    }));
}

async fn timeout_at<F>(
    deadline: Instant,
    future: F,
) -> std::result::Result<F::Output, time::Elapsed>
where
    F: std::future::Future,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::ZERO);
    time::timeout(remaining, future).await
}

fn trusted_destination_relays(
    locator: &V1SignedLocator,
    config: &V1ClientConfig,
) -> Result<Vec<Url>> {
    let advertised: HashSet<String> = locator
        .claims
        .relay_urls
        .iter()
        .map(origin)
        .collect::<Result<_>>()?;
    let mut trusted: Vec<Url> = config
        .trusted_relays
        .iter()
        .filter_map(|relay| {
            origin(&relay.url)
                .ok()
                .filter(|value| advertised.contains(value))
                .map(|_| relay.url.clone())
        })
        .collect();
    trusted.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    trusted.dedup();
    Ok(trusted)
}

fn validate_trusted_relay_url(url: &Url, allow_loopback: bool) -> Result<()> {
    validate_trusted_relay_url_for_environment(url, allow_loopback, cfg!(target_arch = "wasm32"))
}

fn validate_trusted_relay_url_for_environment(
    url: &Url,
    allow_loopback: bool,
    browser_wasm: bool,
) -> Result<()> {
    let secure = url.scheme() == "https";
    let local_host = url.host_str().is_some_and(|host| {
        if browser_wasm {
            matches!(url.host(), Some(url::Host::Ipv4(address)) if address == Ipv4Addr::LOCALHOST)
                || matches!(url.host(), Some(url::Host::Ipv6(address)) if address == Ipv6Addr::LOCALHOST)
        } else {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }
    });
    let local = allow_loopback
        && url.scheme() == "http"
        && local_host
        && (!browser_wasm || url.port().is_some());
    if (!secure && !local)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::InvalidRelayUrl);
    }
    Ok(())
}

fn origin(url: &Url) -> Result<String> {
    match url.origin() {
        url::Origin::Tuple(scheme, host, port) => Ok(format!("{scheme}://{host}:{port}")),
        url::Origin::Opaque(_) => Err(ClientError::InvalidRelayUrl),
    }
}

fn validate_application(application: &str) -> Result<()> {
    if application.is_empty()
        || application.len() > 128
        || !application
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(ClientError::Iroh(
            "invalid v1 application identifier".to_owned(),
        ));
    }
    Ok(())
}

fn currentness_path(
    role: V1CurrentnessRole,
    challenge: &str,
    hello: &V1SignedHello,
    record: &V1DeviceRecord,
) -> Result<String> {
    Ok(v1_currentness_path(
        role,
        challenge,
        &hello.digest()?,
        &record.digest()?,
        &record.authorization.digest()?,
        &record.locator.digest()?,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn validate_proof_control(
    version: u16,
    received_challenge: &str,
    expected_challenge: &str,
    initiator_path: &str,
    responder_path: &str,
    hello: &V1SignedHello,
    initiator_record: &V1DeviceRecord,
    responder_record: &V1DeviceRecord,
) -> Result<()> {
    if version != V1_PROTOCOL_VERSION
        || received_challenge != expected_challenge
        || initiator_path
            != currentness_path(
                V1CurrentnessRole::Initiator,
                expected_challenge,
                hello,
                initiator_record,
            )?
        || responder_path
            != currentness_path(
                V1CurrentnessRole::Responder,
                expected_challenge,
                hello,
                responder_record,
            )?
    {
        return Err(ClientError::UnexpectedPeer);
    }
    Ok(())
}

fn nonce_uuid(nonce: &str) -> Result<Uuid> {
    let decoded = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| ClientError::UnexpectedPeer)?;
    let prefix = decoded.get(..16).ok_or(ClientError::UnexpectedPeer)?;
    Uuid::from_slice(prefix).map_err(|_| ClientError::UnexpectedPeer)
}

async fn write_json<T: Serialize>(stream: &mut SendStream, value: &T, max: usize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|error| ClientError::Iroh(error.to_string()))?;
    if bytes.len() > max {
        return Err(ClientError::Iroh(
            "v1 QUIC control message exceeds byte limit".to_owned(),
        ));
    }
    write_bytes(stream, &bytes).await
}

async fn read_json<T: for<'de> Deserialize<'de>>(stream: &mut RecvStream, max: usize) -> Result<T> {
    let bytes = read_bytes(stream, max).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Iroh("malformed v1 QUIC control message".to_owned()))
}

async fn write_bytes(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ClientError::Iroh("v1 QUIC frame is too large".to_owned()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))
}

async fn read_bytes(stream: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max {
        return Err(ClientError::Iroh(format!(
            "v1 peer frame exceeds the {max} byte limit"
        )));
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    Ok(bytes)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use iroh_relay::server::{
        RelayConfig as RelayServerConfig, Server as RelayServer,
        ServerConfig as RelayServerConfigSet,
    };
    use pubky::{Capability, ClientId, GrantClaims, GrantId, Keypair};
    use pubky2pubky_protocol::{V1GrantAuthorization, V1SignedCurrentnessProof};
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{ConnectionPath, MemorySequenceStore, StaticV1Resolver};

    const TEST_APPLICATION: &str = "pubky2pubky/test/echo";

    struct CommitGate {
        entered: AtomicBool,
        release: Semaphore,
    }

    impl CommitGate {
        fn new() -> Self {
            Self {
                entered: AtomicBool::new(false),
                release: Semaphore::new(0),
            }
        }
    }

    #[derive(Clone)]
    struct ControlledResolver {
        inner: StaticV1Resolver,
        discard_publications: bool,
        commit_gate: Option<Arc<CommitGate>>,
    }

    #[async_trait]
    impl V1DeviceResolver for ControlledResolver {
        async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV1Device>> {
            self.inner.resolve_devices(identity).await
        }

        async fn fetch_device_record(
            &self,
            identity: &str,
            path: &str,
        ) -> Result<ResolvedV1Device> {
            self.inner.fetch_device_record(identity, path).await
        }

        async fn fetch_currentness_proof(
            &self,
            identity: &str,
            path: &str,
        ) -> Result<V1SignedCurrentnessProof> {
            self.inner.fetch_currentness_proof(identity, path).await
        }

        async fn publish_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()> {
            if self.discard_publications {
                return Ok(());
            }
            self.inner.publish_currentness_proof(proof).await
        }

        async fn delete_currentness_proof(&self, proof: &V1SignedCurrentnessProof) -> Result<()> {
            self.inner.delete_currentness_proof(proof).await
        }

        async fn commit_remote_record(&self, device: &ResolvedV1Device) -> Result<()> {
            if let Some(gate) = &self.commit_gate {
                gate.entered.store(true, Ordering::SeqCst);
                gate.release
                    .acquire()
                    .await
                    .map_err(|_| ClientError::ChannelClosed)?
                    .forget();
            }
            self.inner.commit_remote_record(device).await
        }
    }

    fn credential(root: &Keypair, cnf: &Keypair, device_id: &str) -> V1DeviceCredential {
        let now = now_seconds();
        let claims = GrantClaims {
            iss: root.public_key(),
            client_id: ClientId::new("chat.example")
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
        let identity = root.public_key().z32();
        let authorization =
            V1GrantAuthorization::from_jws(claims.sign(root, "pubky-grant"), &identity, now)
                .unwrap_or_else(|error| panic!("grant authorization: {error}"));
        V1DeviceCredential::issue(authorization, &identity, cnf, device_id, now, now + 1_800)
            .unwrap_or_else(|error| panic!("device credential: {error}"))
    }

    async fn relay() -> (RelayServer, Url) {
        let mut server_config = RelayServerConfigSet::default();
        server_config.relay = Some(RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0)));
        let server = RelayServer::spawn(server_config)
            .await
            .unwrap_or_else(|error| panic!("starting local relay: {error}"));
        let address = server
            .http_addr()
            .unwrap_or_else(|| panic!("local relay did not expose HTTP"));
        let url = Url::parse(&format!("http://{address}"))
            .unwrap_or_else(|error| panic!("local relay URL: {error}"));
        (server, url)
    }

    fn config(relay_url: Url) -> V1ClientConfig {
        let mut config = V1ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        config.trusted_relays = vec![IrohRelayConfig::new(relay_url)];
        config.allow_insecure_loopback_relay = true;
        config.endpoint_online_timeout = Duration::from_secs(10);
        config.negotiation_timeout = Duration::from_secs(15);
        config.peer_handshake_timeout = Duration::from_secs(10);
        config
    }

    async fn prepared_clients(
        relay_url: Url,
        discard_alice_publications: bool,
    ) -> (V1Client, V1Client) {
        let alice_root = Keypair::random();
        let alice_cnf = Keypair::random();
        let bob_root = Keypair::random();
        let bob_cnf = Keypair::random();
        let alice_credential = credential(&alice_root, &alice_cnf, "alice-device");
        let bob_credential = credential(&bob_root, &bob_cnf, "bob-device");
        let alice_static = StaticV1Resolver::new(
            alice_credential.identity(),
            Arc::new(MemorySequenceStore::default()),
            true,
        )
        .unwrap_or_else(|error| panic!("Alice resolver: {error}"));
        let bob_static = alice_static
            .for_local_identity(
                bob_credential.identity(),
                Arc::new(MemorySequenceStore::default()),
            )
            .unwrap_or_else(|error| panic!("Bob resolver: {error}"));
        let alice_resolver = Arc::new(ControlledResolver {
            inner: alice_static.clone(),
            discard_publications: discard_alice_publications,
            commit_gate: None,
        });
        let bob_resolver = Arc::new(ControlledResolver {
            inner: bob_static,
            discard_publications: false,
            commit_gate: None,
        });
        let alice = V1Client::bind(alice_credential, alice_resolver, config(relay_url.clone()))
            .await
            .unwrap_or_else(|error| panic!("binding Alice: {error}"));
        let bob = V1Client::bind(bob_credential, bob_resolver, config(relay_url))
            .await
            .unwrap_or_else(|error| panic!("binding Bob: {error}"));
        for record in [
            alice
                .current_record(1, Duration::from_secs(300))
                .await
                .unwrap_or_else(|error| panic!("Alice record: {error}")),
            bob.current_record(1, Duration::from_secs(300))
                .await
                .unwrap_or_else(|error| panic!("Bob record: {error}")),
        ] {
            alice_static
                .insert_record(record)
                .await
                .unwrap_or_else(|error| panic!("publishing record: {error}"));
        }
        (alice, bob)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoint_rejects_unpublished_alpn_without_fallback() {
        let (relay, relay_url) = relay().await;
        let (alice, bob) = prepared_clients(relay_url, false).await;
        let attempted = tokio::time::timeout(
            Duration::from_secs(5),
            alice
                .inner
                .endpoint
                .connect(bob.inner.endpoint.addr(), b"pubky2pubky/iroh/v4"),
        )
        .await
        .unwrap_or_else(|_| panic!("non-v1 ALPN negotiation did not terminate"));
        assert!(attempted.is_err(), "a non-v1 ALPN must be rejected");
        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    async fn wait_for_gate(gate: &CommitGate) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("responder did not reach the confirmation barrier"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end test intentionally shows every consent and confirmation barrier"
    )]
    async fn consent_currentness_confirmation_and_relay_e2e() {
        let (relay, relay_url) = relay().await;
        let gate = Arc::new(CommitGate::new());

        let alice_root = Keypair::random();
        let alice_cnf = Keypair::random();
        let bob_root = Keypair::random();
        let bob_cnf = Keypair::random();
        let alice_credential = credential(&alice_root, &alice_cnf, "alice-device");
        let bob_credential = credential(&bob_root, &bob_cnf, "bob-device");
        let alice_static = StaticV1Resolver::new(
            alice_credential.identity(),
            Arc::new(MemorySequenceStore::default()),
            true,
        )
        .unwrap_or_else(|error| panic!("Alice resolver: {error}"));
        let bob_static = alice_static
            .for_local_identity(
                bob_credential.identity(),
                Arc::new(MemorySequenceStore::default()),
            )
            .unwrap_or_else(|error| panic!("Bob resolver: {error}"));
        let alice_resolver = Arc::new(ControlledResolver {
            inner: alice_static.clone(),
            discard_publications: false,
            commit_gate: None,
        });
        let bob_resolver = Arc::new(ControlledResolver {
            inner: bob_static,
            discard_publications: false,
            commit_gate: Some(gate.clone()),
        });
        let alice = V1Client::bind(alice_credential, alice_resolver, config(relay_url.clone()))
            .await
            .unwrap_or_else(|error| panic!("binding Alice: {error}"));
        let bob = V1Client::bind(bob_credential, bob_resolver.clone(), config(relay_url))
            .await
            .unwrap_or_else(|error| panic!("binding Bob: {error}"));
        for record in [
            alice
                .current_record(1, Duration::from_secs(300))
                .await
                .unwrap_or_else(|error| panic!("Alice record: {error}")),
            bob.current_record(1, Duration::from_secs(300))
                .await
                .unwrap_or_else(|error| panic!("Bob record: {error}")),
        ] {
            alice_static
                .insert_record(record)
                .await
                .unwrap_or_else(|error| panic!("publishing record: {error}"));
        }

        let dialing_alice = alice.clone();
        let bob_identity = bob.identity().to_owned();
        let mut dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, Some("bob-device"), TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(5), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for v1 Hello"))
            .unwrap_or_else(|error| panic!("receiving v1 Hello: {error}"));
        assert_eq!(incoming.identity(), alice.identity());
        assert_eq!(incoming.device_id(), "alice-device");
        assert_eq!(incoming.application(), TEST_APPLICATION);
        assert_eq!(
            bob_resolver.inner.request_count(),
            0,
            "no resolver/PKARR/homeserver egress may precede application consent"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut dial)
                .await
                .is_err(),
            "the initiator must not receive a Peer before consent"
        );

        let mut accepting_bob = tokio::spawn(async move { incoming.accept().await });
        wait_for_gate(&gate).await;
        assert!(
            !accepting_bob.is_finished() && !dial.is_finished(),
            "neither side may receive a Peer before durable observation and ProofConfirmed"
        );
        gate.release.add_permits(1);
        let bob_peer = tokio::time::timeout(Duration::from_secs(5), &mut accepting_bob)
            .await
            .unwrap_or_else(|_| panic!("timed out confirming Bob"))
            .unwrap_or_else(|error| panic!("Bob accept task: {error}"))
            .unwrap_or_else(|error| panic!("Bob accept failed: {error}"));
        let alice_peer = tokio::time::timeout(Duration::from_secs(5), &mut dial)
            .await
            .unwrap_or_else(|_| panic!("timed out confirming Alice"))
            .unwrap_or_else(|error| panic!("Alice dial task: {error}"))
            .unwrap_or_else(|error| panic!("Alice dial failed: {error}"));
        assert!(bob_resolver.inner.request_count() > 0);
        assert_eq!(
            alice_peer
                .wait_for_path(ConnectionPath::Relayed, Duration::from_secs(5))
                .await,
            ConnectionPath::Relayed
        );
        alice_peer
            .send(b"v1 encrypted request")
            .await
            .unwrap_or_else(|error| panic!("sending request: {error}"));
        assert_eq!(
            bob_peer
                .recv()
                .await
                .unwrap_or_else(|error| panic!("receiving request: {error}")),
            b"v1 encrypted request"
        );

        alice_peer
            .close()
            .await
            .unwrap_or_else(|error| panic!("closing Alice peer: {error}"));
        bob_peer
            .close()
            .await
            .unwrap_or_else(|error| panic!("closing Bob peer: {error}"));
        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn missing_initiator_currentness_proof_releases_no_peer() {
        let (relay, relay_url) = relay().await;
        let (alice, bob) = prepared_clients(relay_url, true).await;
        let dialing_alice = alice.clone();
        let bob_identity = bob.identity().to_owned();
        let dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, Some("bob-device"), TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(5), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for v1 Hello"))
            .unwrap_or_else(|error| panic!("receiving v1 Hello: {error}"));
        let accepted = tokio::time::timeout(Duration::from_secs(5), incoming.accept())
            .await
            .unwrap_or_else(|_| panic!("missing proof did not fail responder handshake"));
        assert!(
            accepted.is_err(),
            "the responder must not return Peer without the initiator proof"
        );
        let dialed = tokio::time::timeout(Duration::from_secs(5), dial)
            .await
            .unwrap_or_else(|_| panic!("missing proof did not close initiator handshake"))
            .unwrap_or_else(|error| panic!("Alice dial task: {error}"));
        assert!(
            dialed.is_err(),
            "the initiator must not return Peer without final confirmation"
        );
        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[test]
    fn signed_locator_cannot_select_link_local_or_untrusted_relay_origin() {
        let root = Keypair::random();
        let cnf = Keypair::random();
        let credential = credential(&root, &cnf, "device");
        let now = now_seconds();
        let locator = V1SignedLocator::sign(
            &credential,
            vec![
                Url::parse("https://169.254.169.254/")
                    .unwrap_or_else(|error| panic!("attacker URL: {error}")),
            ],
            v1_random_challenge(),
            1,
            now,
            now + 60,
        )
        .unwrap_or_else(|error| panic!("signing locator: {error}"));
        let mut local = V1ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        local.trusted_relays = vec![IrohRelayConfig::new(
            Url::parse("https://trusted.example/")
                .unwrap_or_else(|error| panic!("trusted URL: {error}")),
        )];
        assert!(
            trusted_destination_relays(&locator, &local)
                .unwrap_or_else(|error| panic!("matching relays: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn browser_loopback_relay_policy_is_literal_explicit_and_port_bound() {
        for allowed in ["http://127.0.0.1:3340/", "http://[::1]:3340/"] {
            let url =
                Url::parse(allowed).unwrap_or_else(|error| panic!("browser loopback URL: {error}"));
            assert!(validate_trusted_relay_url_for_environment(&url, true, true).is_ok());
            assert!(validate_trusted_relay_url_for_environment(&url, false, true).is_err());
        }

        for rejected in [
            "http://localhost:3340/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://127.0.0.1.evil:3340/",
            "http://127.0.0.2:3340/",
            "http://192.168.1.2:3340/",
            "http://[::2]:3340/",
            "http://user:secret@127.0.0.1:3340/",
            "http://127.0.0.1:3340/path",
            "http://127.0.0.1:3340/?query=1",
            "http://127.0.0.1:3340/#fragment",
        ] {
            let url = Url::parse(rejected)
                .unwrap_or_else(|error| panic!("rejected browser relay URL: {error}"));
            assert!(
                validate_trusted_relay_url_for_environment(&url, true, true).is_err(),
                "browser policy unexpectedly accepted {rejected}"
            );
        }
    }

    #[test]
    fn browser_transport_constraints_remain_relay_only_and_secret_free() {
        let relay_url = Url::parse("http://127.0.0.1:3340/")
            .unwrap_or_else(|error| panic!("browser relay URL: {error}"));
        let mut baseline = V1ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        baseline.trusted_relays = vec![IrohRelayConfig::new(relay_url.clone())];
        baseline.allow_insecure_loopback_relay = true;
        baseline.max_message_bytes = 4_096;
        assert!(baseline.validate_browser_constraints().is_ok());

        let mut direct = V1ClientConfig::direct(
            PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        direct.trusted_relays = vec![IrohRelayConfig::new(relay_url.clone())];
        assert!(direct.validate_browser_constraints().is_err());

        let mut token = baseline.clone();
        token.trusted_relays =
            vec![IrohRelayConfig::new(relay_url.clone()).with_auth_token("secret")];
        assert!(token.validate_browser_constraints().is_err());

        let mut custom_ca = baseline.clone();
        custom_ca.relay_ca_certificates = vec![vec![1]];
        assert!(custom_ca.validate_browser_constraints().is_err());

        let mut oversized = baseline;
        oversized.max_message_bytes = MAX_BROWSER_MESSAGE_BYTES + 1;
        assert!(oversized.validate_browser_constraints().is_err());
    }

    #[test]
    fn relay_only_policy_and_replay_cache_are_strict() {
        let relay = IrohRelayConfig::new(
            Url::parse("https://trusted.example/")
                .unwrap_or_else(|error| panic!("trusted URL: {error}")),
        );
        let mut mismatched = V1ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        mismatched.trusted_relays = vec![relay.clone()];
        assert!(mismatched.validate().is_err());
        let mut with_udp = V1ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        with_udp.trusted_relays = vec![relay];
        with_udp.udp_bind_addresses = vec![SocketAddr::from(([127, 0, 0, 1], 0))];
        assert!(with_udp.validate().is_err());

        let mut replay_cache = ReplayCache::new(2, 1);
        replay_cache
            .insert("nonce".to_owned(), "alice".to_owned(), 20, 10)
            .unwrap_or_else(|error| panic!("first nonce: {error}"));
        assert!(
            replay_cache
                .insert("nonce".to_owned(), "alice".to_owned(), 20, 10)
                .is_err()
        );
        assert!(
            replay_cache
                .insert("other".to_owned(), "alice".to_owned(), 20, 10)
                .is_err()
        );
    }
}
