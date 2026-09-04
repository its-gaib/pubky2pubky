use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::FutureExt as _;
use hole_punchky_protocol::{
    V3_IROH_ALPN, V3_MAX_HANDSHAKE_LIFETIME_SECONDS, V3_MAX_LOCATOR_LIFETIME_SECONDS,
    V3DeviceCertificate, V3DeviceCredential, V3SignedAck, V3SignedHello, V3SignedLocator,
    now_seconds, v3_random_nonce,
};
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
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::{
    ClientError, IrohRelayConfig, PathPolicy, Peer, PublisherSequenceStore, ResolvedV3Device,
    Result, V3DeviceResolver,
};

const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
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

/// Explicit acknowledgement required before enabling v3's direct-capable public contact model.
///
/// V3 publishes an iroh endpoint id and home-relay origin. Any party that knows the Pubky can
/// initiate QUIC without prior manual consent. The relay and recipient can observe connection
/// metadata; when iroh upgrades to a direct path, the peers can learn each other's public network
/// addresses. Payloads and authenticated application messages remain end-to-end encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicContactDisclosure {
    /// The application accepts address/metadata exposure before application-level consent.
    AcknowledgePreConsentNetworkExposure,
    /// The application accepts relay-visible connection metadata before application consent.
    ///
    /// Relay-only peers do not reveal their IP addresses to each other, but the configured relay
    /// can observe endpoint ids, connection timing, and traffic shape. Application payloads remain
    /// end-to-end encrypted inside iroh QUIC.
    AcknowledgePreConsentRelayMetadataExposure,
}

/// V3 endpoint, relay, handshake, and resource policy.
#[derive(Debug, Clone)]
pub struct V3ClientConfig {
    /// Whether this endpoint may use direct IP paths or is constrained to an iroh relay.
    pub path_policy: PathPolicy,
    /// Locally trusted iroh relay origins. Locator records can only select from this set.
    pub trusted_relays: Vec<IrohRelayConfig>,
    /// Additional local DER CA roots for the trusted relays; never sourced from a locator.
    pub relay_ca_certificates: Vec<Vec<u8>>,
    /// Allow exact plain-HTTP loopback relay origins for explicit local development.
    pub allow_insecure_loopback_relay: bool,
    /// UDP bind addresses used for direct path discovery and hole punching.
    pub udp_bind_addresses: Vec<SocketAddr>,
    /// Time allowed for the local endpoint to become relay-reachable.
    pub endpoint_online_timeout: Duration,
    /// Strict inbound limit for TLS and receiving the first bounded Hello frame.
    ///
    /// Before a Hello supplies an identity, an iroh relay address can represent many peers and is
    /// not a trustworthy source key. The global unauthenticated cap and this short deadline bound
    /// stalled connections without constraining homeserver discovery latency.
    pub pre_hello_timeout: Duration,
    /// Total time allowed to resolve and try a bounded set of target devices.
    pub negotiation_timeout: Duration,
    /// Time allowed for each QUIC connect and signed Hello/Ack exchange.
    pub peer_handshake_timeout: Duration,
    /// Maximum application message size after authentication.
    pub max_message_bytes: usize,
    /// Maximum simultaneous, not-yet-authenticated inbound QUIC handshakes.
    pub max_unauthenticated_handshakes: usize,
    /// Maximum authenticated peers waiting for the application to call [`V3Client::accept`].
    pub incoming_queue_capacity: usize,
    /// Maximum authenticated consent requests queued for any one Pubky identity.
    pub max_pending_per_identity: usize,
    /// Maximum unexpired authenticated Hello nonces retained to reject replay.
    pub replay_cache_capacity: usize,
    /// Maximum replay-cache entries retained for any one authenticated Pubky identity.
    pub replay_cache_per_identity_capacity: usize,
    /// Exact application names accepted on inbound v3 connections.
    pub accepted_applications: Vec<String>,
    disclosure: PublicContactDisclosure,
}

impl V3ClientConfig {
    /// Construct direct-with-relay-fallback policy after explicit privacy acknowledgement.
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
            peer_handshake_timeout: Duration::from_secs(15),
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

    /// Construct a relay-only policy after acknowledging relay-visible pre-consent metadata.
    ///
    /// This is the only v3 policy accepted by browser Wasm builds. Iroh terminates authenticated
    /// QUIC in the browser; the relay forwards ciphertext and cannot read application payloads.
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
            peer_handshake_timeout: Duration::from_secs(15),
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

    fn validate_policy_disclosure(&self) -> Result<()> {
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
                    "v3 path policy does not match its privacy acknowledgement".to_owned(),
                ));
            }
        }
        #[cfg(target_arch = "wasm32")]
        if self.path_policy != PathPolicy::RelayOnly
            || self.allow_insecure_loopback_relay
            || !self.relay_ca_certificates.is_empty()
            || self
                .trusted_relays
                .iter()
                .any(|relay| relay.auth_token.is_some())
            || self.max_message_bytes > MAX_BROWSER_MESSAGE_BYTES
        {
            return Err(ClientError::Iroh(
                "browser v3 requires HTTPS relay-only transport without tokens, custom CAs, or oversized messages"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        self.validate_policy_disclosure()?;
        if self.trusted_relays.is_empty() || self.trusted_relays.len() > MAX_TRUSTED_RELAYS {
            return Err(ClientError::Iroh(
                "v3 requires one to four locally trusted relays".to_owned(),
            ));
        }
        let mut relay_origins = HashSet::new();
        for relay in &self.trusted_relays {
            validate_trusted_relay_url(&relay.url, self.allow_insecure_loopback_relay)?;
            if !relay_origins.insert(origin(&relay.url)?) {
                return Err(ClientError::Iroh(
                    "duplicate trusted relay origin".to_owned(),
                ));
            }
            if relay
                .auth_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_AUTH_TOKEN_BYTES)
            {
                return Err(ClientError::Iroh(
                    "invalid local iroh relay authentication token".to_owned(),
                ));
            }
        }
        if self.relay_ca_certificates.len() > MAX_CA_CERTIFICATES
            || self.relay_ca_certificates.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_CA_CERTIFICATE_BYTES
            })
        {
            return Err(ClientError::Iroh(
                "invalid local relay CA certificate set".to_owned(),
            ));
        }
        match self.path_policy {
            PathPolicy::DirectWithRelayFallback => {
                if self.udp_bind_addresses.is_empty() || self.udp_bind_addresses.len() > 2 {
                    return Err(ClientError::Iroh(
                        "v3 direct mode requires one or two UDP bind addresses".to_owned(),
                    ));
                }
                let mut families = HashSet::new();
                if self
                    .udp_bind_addresses
                    .iter()
                    .any(|address| !families.insert(address.is_ipv4()))
                {
                    return Err(ClientError::Iroh(
                        "v3 accepts at most one UDP bind per IP family".to_owned(),
                    ));
                }
            }
            PathPolicy::RelayOnly if !self.udp_bind_addresses.is_empty() => {
                return Err(ClientError::Iroh(
                    "v3 relay-only mode forbids UDP bind addresses".to_owned(),
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
                "invalid v3 client resource bounds".to_owned(),
            ));
        }
        if self.accepted_applications.is_empty()
            || self.accepted_applications.len() > MAX_APPLICATIONS
        {
            return Err(ClientError::Iroh(
                "v3 requires a bounded inbound application allowlist".to_owned(),
            ));
        }
        let mut applications = HashSet::new();
        for application in &self.accepted_applications {
            validate_application(application)?;
            if !applications.insert(application) {
                return Err(ClientError::Iroh(
                    "duplicate v3 inbound application".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

struct AbortTask(JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct V3Inner {
    credential: Arc<V3DeviceCredential>,
    endpoint: Endpoint,
    resolver: Arc<dyn V3DeviceResolver>,
    config: V3ClientConfig,
    pending: Arc<PendingQueue>,
    active_locators: Arc<Mutex<HashMap<String, V3SignedLocator>>>,
    instance_nonce: String,
    _accept_task: AbortTask,
}

/// Pubky-discovered iroh v3 endpoint for native or relay-only browser peers.
///
/// Every returned [`Peer`] is the single bounded stream of an iroh-authenticated TLS 1.3 QUIC
/// connection under the fixed v3 ALPN. There is no plaintext or non-QUIC message fallback.
/// Iroh 1.1 does not expose an inbound server switch that universally rejects hostile 0-RTT.
/// This client awaits the full handshake, never opts into the 0-RTT API, bounds pre-consent flow
/// control, and authenticates/replay-checks the certificate-bearing Hello entirely offline before
/// surfacing a consent request. Current Pubky publication and revocation state are checked only
/// after the application explicitly accepts.
#[derive(Clone)]
pub struct V3Client {
    inner: Arc<V3Inner>,
}

struct PendingV3 {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    local: Arc<V3DeviceCredential>,
    resolver: Arc<dyn V3DeviceResolver>,
    sender_certificate: V3DeviceCertificate,
    sender_locator: V3SignedLocator,
    target_locator: V3SignedLocator,
    hello: V3SignedHello,
    max_message_bytes: usize,
    allow_insecure_loopback_relay: bool,
    deadline: Instant,
    expiry_cancel: Option<oneshot::Sender<()>>,
    _capacity_permit: OwnedSemaphorePermit,
}

impl PendingV3 {
    async fn revalidate_and_commit_sender(&self) -> Result<ResolvedV3Device> {
        if self.deadline <= Instant::now() || now_seconds() > self.hello.claims.expires_at {
            return Err(ClientError::Timeout("accepting inbound v3 peer"));
        }
        let devices = timeout_at(
            self.deadline,
            self.resolver
                .resolve_devices_for_accepted_inbound(&self.hello.claims.from_identity),
        )
        .await
        .map_err(|_| ClientError::Timeout("revalidating accepted v3 peer"))??;
        let current = devices
            .into_iter()
            .find(|device| {
                device.certificate == self.sender_certificate
                    && device.locator == self.sender_locator
            })
            .ok_or(ClientError::UnexpectedPeer)?;
        self.hello.verify(
            &current.certificate,
            &self.local.certificate,
            &self.target_locator,
            &self.hello.claims.application,
            now_seconds(),
            self.allow_insecure_loopback_relay,
        )?;
        timeout_at(self.deadline, self.resolver.commit_device(&current))
            .await
            .map_err(|_| ClientError::Timeout("committing accepted v3 peer"))??;
        Ok(current)
    }
}

/// An offline-authenticated v3 Hello awaiting application consent.
///
/// At this stage QUIC has already contacted the recipient and iroh may have revealed public
/// network addresses while attempting a direct path. The embedded device certificate, locator,
/// Hello signature, remote iroh endpoint, target binding, application, lifetime, and replay key
/// have been verified without Pubky/PKARR or homeserver egress. Whether that exact certificate and
/// locator remain in the sender's current directory is deliberately not checked until
/// [`Self::accept`]. No signed Ack is sent and no application [`Peer`] is released before then.
/// Dropping or rejecting this value closes the connection.
pub struct IncomingV3 {
    pending: Option<PendingV3>,
}

impl std::fmt::Debug for IncomingV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = formatter.debug_struct("IncomingV3");
        if let Some(pending) = &self.pending {
            value
                .field("identity", &pending.hello.claims.from_identity)
                .field("device_id", &pending.hello.claims.from_device_id)
                .field("application", &pending.hello.claims.application);
        }
        value.finish_non_exhaustive()
    }
}

impl IncomingV3 {
    /// Cryptographically root-signed caller Pubky identity.
    ///
    /// Current directory membership and revocation state are checked by [`Self::accept`].
    #[must_use]
    pub fn identity(&self) -> &str {
        self.pending
            .as_ref()
            .map_or("", |pending| &pending.hello.claims.from_identity)
    }

    /// Cryptographically certified caller device id.
    ///
    /// Current directory membership and revocation state are checked by [`Self::accept`].
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

    /// Explicitly consent, send the signed Ack, and release the application stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the bounded consent window elapsed or the Ack cannot be signed/sent.
    pub async fn accept(mut self) -> Result<Peer> {
        let mut pending = self.pending.take().ok_or(ClientError::ChannelClosed)?;
        let current_sender = match pending.revalidate_and_commit_sender().await {
            Ok(current) => current,
            Err(error) => {
                pending
                    .connection
                    .close(1u32.into(), b"v3 peer revalidation failed");
                return Err(error);
            }
        };
        let Some(remaining) = pending.deadline.checked_duration_since(Instant::now()) else {
            pending.connection.close(1u32.into(), b"v3 consent expired");
            return Err(ClientError::Timeout("accepting inbound v3 peer"));
        };
        let now = now_seconds();
        let expires_at = pending
            .hello
            .claims
            .expires_at
            .min(now.saturating_add(V3_MAX_HANDSHAKE_LIFETIME_SECONDS.min(30)));
        let ack_result = if pending.allow_insecure_loopback_relay {
            V3SignedAck::sign_for_local_development(
                &pending.local,
                &pending.hello,
                &current_sender.certificate,
                &pending.target_locator,
                v3_random_nonce(),
                now,
                expires_at,
            )
        } else {
            V3SignedAck::sign(
                &pending.local,
                &pending.hello,
                &current_sender.certificate,
                &pending.target_locator,
                v3_random_nonce(),
                now,
                expires_at,
            )
        };
        let ack = match ack_result {
            Ok(ack) => ack,
            Err(error) => {
                pending.connection.close(1u32.into(), b"invalid v3 Ack");
                return Err(error.into());
            }
        };
        if let Err(error) = time::timeout(
            remaining,
            write_json(&mut pending.send, &ack, MAX_HANDSHAKE_BYTES),
        )
        .await
        .map_err(|_| ClientError::Timeout("sending accepted v3 Ack"))?
        {
            pending.connection.close(1u32.into(), b"v3 Ack failed");
            return Err(error);
        }
        // Dropping the sender cancels the detached deadline task. The task otherwise removes an
        // undrained queue entry itself and closes the QUIC connection at the consent deadline.
        pending.expiry_cancel.take();
        let session_id = match nonce_uuid(&pending.hello.claims.session_nonce) {
            Ok(session_id) => session_id,
            Err(error) => {
                pending
                    .connection
                    .close(1u32.into(), b"invalid v3 session nonce");
                return Err(error);
            }
        };
        Ok(Peer::new(
            pending.connection,
            pending.send,
            pending.recv,
            session_id,
            current_sender.certificate.claims.identity,
            current_sender.certificate.claims.device_id,
            pending.max_message_bytes,
        ))
    }

    /// Reject this request without an Ack or application-controlled reason on the wire.
    pub fn reject(mut self) {
        if let Some(pending) = self.pending.take() {
            pending
                .connection
                .close(1u32.into(), b"application rejected v3 Hello");
        }
    }
}

impl Drop for IncomingV3 {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending
                .connection
                .close(1u32.into(), b"application dropped v3 Hello");
        }
    }
}

struct PendingQueueState {
    order: VecDeque<String>,
    entries: HashMap<String, IncomingV3>,
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

    async fn insert(&self, key: String, incoming: IncomingV3) -> Result<()> {
        let mut state = self.state.lock().await;
        Self::prune_expired(&mut state, Instant::now());
        if state.closed {
            return Err(ClientError::ChannelClosed);
        }
        if state.entries.len() >= self.capacity || state.entries.contains_key(&key) {
            return Err(ClientError::Iroh(
                "authenticated v3 peer queue is full".to_owned(),
            ));
        }
        let identity = incoming.identity().to_owned();
        let count = state.per_identity.get(&identity).copied().unwrap_or(0);
        if count >= self.per_identity_capacity {
            return Err(ClientError::Iroh(
                "authenticated v3 identity pending limit reached".to_owned(),
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

    async fn next(&self) -> Result<IncomingV3> {
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

    fn remove(state: &mut PendingQueueState, key: &str) -> Option<IncomingV3> {
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

    #[cfg(test)]
    async fn len(&self) -> usize {
        let mut state = self.state.lock().await;
        Self::prune_expired(&mut state, Instant::now());
        state.entries.len()
    }
}

impl std::fmt::Debug for V3Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("V3Client")
            .field("identity", &self.identity())
            .field("device_id", &self.device_id())
            .field("iroh_endpoint_id", &self.iroh_endpoint_id())
            .finish_non_exhaustive()
    }
}

impl V3Client {
    /// Bind a v3 iroh endpoint and start a bounded authenticated accept loop.
    ///
    /// After an inbound Hello is surfaced and explicitly accepted, `resolver` requires that the
    /// caller's exact embedded certificate and locator remain present in its current root-signed
    /// Pubky publication. It is never invoked for remotely supplied discovery before consent.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid local credentials/configuration or relay registration
    /// failure.
    #[allow(
        clippy::too_many_lines,
        reason = "endpoint security policy and bounded accept-task setup are one transaction"
    )]
    pub async fn bind(
        credential: V3DeviceCredential,
        resolver: Arc<dyn V3DeviceResolver>,
        config: V3ClientConfig,
    ) -> Result<Self> {
        config.validate()?;
        credential
            .certificate
            .verify(credential.identity(), now_seconds())?;
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
            // V3 uses exactly one bidirectional stream for Hello, Ack, and framed messages.
            // Small initial flow-control windows bound bytes a hostile peer can pipeline while
            // application consent is pending; credit advances only as authenticated data is read.
            .max_concurrent_bidi_streams(VarInt::from_u32(1))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(PER_CONNECTION_RECEIVE_WINDOW))
            .receive_window(VarInt::from_u32(PER_CONNECTION_RECEIVE_WINDOW))
            .build();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![V3_IROH_ALPN.to_vec()])
            // The public v3 API never opts into iroh 0-RTT. Also retain no client-side TLS
            // tickets, so even future refactors cannot accidentally send replayable early data.
            // Iroh 1.1 has no server-side switch for refusing tickets from a hostile custom peer.
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
        let bind_direct = config.path_policy == PathPolicy::DirectWithRelayFallback;
        #[cfg(not(target_arch = "wasm32"))]
        if bind_direct {
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
                "registering v3 endpoint with iroh relay",
            ));
        }

        let credential = Arc::new(credential);
        let active_locators = Arc::new(Mutex::new(HashMap::new()));
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
        let task_locators = Arc::clone(&active_locators);
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
                let locators = Arc::clone(&task_locators);
                let replay = Arc::clone(&replay);
                let pending = Arc::clone(&task_pending);
                let config = task_config.clone();
                let pre_hello_deadline = Instant::now() + config.pre_hello_timeout;
                drop(spawn(async move {
                    if let Err(error) = handle_incoming_v3(
                        incoming,
                        credential,
                        resolver,
                        locators,
                        replay,
                        pending,
                        config,
                        pre_hello_deadline,
                        permit,
                    )
                    .await
                    {
                        debug!(%error, "discarded unauthenticated v3 iroh connection");
                    }
                }));
            }
        });

        Ok(Self {
            inner: Arc::new(V3Inner {
                credential,
                endpoint,
                resolver,
                config,
                pending,
                active_locators,
                instance_nonce: v3_random_nonce(),
                _accept_task: AbortTask(task),
            }),
        })
    }

    /// Local Pubky identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        self.inner.credential.identity()
    }

    /// Local delegated device id.
    #[must_use]
    pub fn device_id(&self) -> &str {
        self.inner.credential.device_id()
    }

    /// Local certified iroh endpoint id.
    #[must_use]
    pub fn iroh_endpoint_id(&self) -> &str {
        self.inner.credential.iroh_endpoint_id()
    }

    /// Root-signed local device certificate for a v3 directory publication.
    #[must_use]
    pub fn certificate(&self) -> &V3DeviceCertificate {
        &self.inner.credential.certificate
    }

    /// Sign and register a short-lived locator using an explicitly supplied sequence.
    ///
    /// Only locally configured relay origins are published. Direct IP addresses, relay CA roots,
    /// and relay authentication tokens are never included. Up to eight latest still-valid
    /// locators are accepted during refresh overlap. This low-level method is intended for tests,
    /// migration, and externally transactional sequence allocators. Production callers should use
    /// [`Self::next_locator`] with durable state; reusing a sequence with changed content can split
    /// peer views and losing a publisher counter requires device-certificate rotation.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero/overlong lifetime, invalid sequence, or signing failure.
    pub async fn current_locator(
        &self,
        sequence: u64,
        lifetime: Duration,
    ) -> Result<V3SignedLocator> {
        let lifetime_seconds = lifetime.as_secs();
        if lifetime_seconds == 0 || lifetime_seconds > V3_MAX_LOCATOR_LIFETIME_SECONDS {
            return Err(ClientError::Iroh(
                "v3 locator lifetime is outside protocol bounds".to_owned(),
            ));
        }
        let now = now_seconds();
        let expires_at = now
            .checked_add(lifetime_seconds)
            .ok_or_else(|| ClientError::Iroh("v3 locator expiry overflow".to_owned()))?;
        let relay_urls = self
            .inner
            .config
            .trusted_relays
            .iter()
            .map(|relay| relay.url.clone())
            .collect();
        let locator = if self.inner.config.allow_insecure_loopback_relay {
            V3SignedLocator::sign_for_local_development(
                &self.inner.credential,
                relay_urls,
                self.inner.instance_nonce.clone(),
                sequence,
                now,
                expires_at,
            )?
        } else {
            V3SignedLocator::sign(
                &self.inner.credential,
                relay_urls,
                self.inner.instance_nonce.clone(),
                sequence,
                now,
                expires_at,
            )?
        };
        let digest = locator.digest()?;
        let mut active = self.inner.active_locators.lock().await;
        active.retain(|_, value| value.claims.expires_at >= now);
        if active.len() >= 8 && !active.contains_key(&digest) {
            let oldest = active
                .iter()
                .min_by_key(|(_, value)| value.claims.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                active.remove(&oldest);
            }
        }
        active.insert(digest, locator.clone());
        Ok(locator)
    }

    /// Atomically allocate, sign, and register the next locator publication.
    ///
    /// This is the production-safe publication path. The supplied store must have been
    /// explicitly initialized when this exact root-signed device certificate was freshly
    /// issued. Missing state fails closed and requires device-certificate rotation.
    ///
    /// # Errors
    ///
    /// Returns an error if durable sequence allocation or locator signing fails.
    pub async fn next_locator(
        &self,
        sequences: &dyn PublisherSequenceStore,
        lifetime: Duration,
    ) -> Result<V3SignedLocator> {
        let sequence = sequences
            .next_locator_sequence(self.identity(), self.inner.credential.control_signing_key())
            .await?;
        self.current_locator(sequence, lifetime).await
    }

    /// Resolve a Pubky identity and connect to one certified v3 device deterministically.
    ///
    /// Device attempts are ordered by device id/control key and bounded to the protocol's eight
    /// devices. A locator can select only an exact origin present in `trusted_relays`.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery fails, no locally trusted common relay exists, or every
    /// bounded QUIC/handshake attempt fails.
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
        .map_err(|_| ClientError::Timeout("resolving and connecting to v3 peer"))?
    }

    async fn dial_inner(
        &self,
        target_identity: &str,
        target_device_id: Option<&str>,
        application: &str,
    ) -> Result<Peer> {
        let mut devices = self.inner.resolver.resolve_devices(target_identity).await?;
        devices.sort_by(|left, right| {
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
        let candidates: Vec<_> = devices
            .into_iter()
            .filter(|device| {
                target_device_id.is_none_or(|wanted| device.certificate.claims.device_id == wanted)
            })
            .take(8)
            .collect();
        if candidates.is_empty() {
            return Err(ClientError::Discovery(
                "requested v3 device is not currently published".to_owned(),
            ));
        }
        let mut failure_count = 0usize;
        for candidate in candidates {
            match self.dial_device(candidate, application).await {
                Ok(peer) => return Ok(peer),
                Err(_) => failure_count = failure_count.saturating_add(1),
            }
        }
        Err(ClientError::Iroh(format!(
            "all {failure_count} bounded v3 device attempts failed"
        )))
    }

    async fn dial_device(&self, target: ResolvedV3Device, application: &str) -> Result<Peer> {
        target.locator.verify(
            &target.certificate,
            &target.certificate.claims.identity,
            now_seconds(),
            self.inner.config.allow_insecure_loopback_relay,
            None,
        )?;
        let relay_urls = trusted_destination_relays(&target.locator, &self.inner.config)?;
        if relay_urls.is_empty() {
            return Err(ClientError::InvalidRelayUrl);
        }
        let expected_id = EndpointId::from_z32(&target.certificate.claims.iroh_endpoint_id)
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let address = EndpointAddr::from_parts(
            expected_id,
            relay_urls
                .into_iter()
                .map(|url| TransportAddr::Relay(RelayUrl::from(url))),
        );
        let connection = time::timeout(
            self.inner.config.peer_handshake_timeout,
            self.inner.endpoint.connect(address, V3_IROH_ALPN),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting v3 iroh QUIC peer"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let result = self
            .finish_outbound_handshake(connection.clone(), expected_id, &target, application)
            .await;
        if result.is_err() {
            connection.close(1u32.into(), b"invalid v3 handshake");
        }
        result
    }

    async fn finish_outbound_handshake(
        &self,
        connection: Connection,
        expected_id: EndpointId,
        target: &ResolvedV3Device,
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
        .map_err(|_| ClientError::Timeout("opening v3 authenticated QUIC stream"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let now = now_seconds();
        let sender_locator = {
            let mut active = self.inner.active_locators.lock().await;
            active.retain(|_, locator| locator.claims.expires_at >= now);
            active
                .iter()
                .max_by(|(left_digest, left), (right_digest, right)| {
                    left.claims
                        .sequence
                        .cmp(&right.claims.sequence)
                        .then_with(|| left_digest.cmp(right_digest))
                })
                .map(|(_, locator)| locator.clone())
        }
        .ok_or_else(|| {
            ClientError::State(
                "a current local v3 locator must be registered before dialing".to_owned(),
            )
        })?;
        let expiry = now
            .saturating_add(V3_MAX_HANDSHAKE_LIFETIME_SECONDS.min(30))
            .min(sender_locator.claims.expires_at)
            .min(target.locator.claims.expires_at)
            .min(target.certificate.claims.expires_at)
            .min(self.inner.credential.certificate.claims.expires_at);
        let hello = if self.inner.config.allow_insecure_loopback_relay {
            V3SignedHello::sign_for_local_development(
                &self.inner.credential,
                &sender_locator,
                &target.certificate,
                &target.locator,
                application,
                v3_random_nonce(),
                (now, expiry),
            )?
        } else {
            V3SignedHello::sign(
                &self.inner.credential,
                &sender_locator,
                &target.certificate,
                &target.locator,
                application,
                v3_random_nonce(),
                (now, expiry),
            )?
        };
        let handshake = async {
            write_json(&mut send, &hello, MAX_HANDSHAKE_BYTES).await?;
            let ack: V3SignedAck = read_json(&mut recv, MAX_HANDSHAKE_BYTES).await?;
            ack.verify(
                &target.certificate,
                &self.inner.credential.certificate,
                &hello,
                application,
                now_seconds(),
                self.inner.config.allow_insecure_loopback_relay,
            )?;
            Result::<()>::Ok(())
        };
        time::timeout(self.inner.config.peer_handshake_timeout, handshake)
            .await
            .map_err(|_| ClientError::Timeout("exchanging signed v3 Hello/Ack"))??;
        let session_id = nonce_uuid(&hello.claims.session_nonce)?;
        Ok(Peer::new(
            connection,
            send,
            recv,
            session_id,
            target.certificate.claims.identity.clone(),
            target.certificate.claims.device_id.clone(),
            self.inner.config.max_message_bytes,
        ))
    }

    /// Receive the next offline-authenticated Hello for an explicit application consent decision.
    ///
    /// The embedded root-signed device certificate and device-signed locator, endpoint-id
    /// matching, signed Hello, target binding, and replay checks have succeeded without any
    /// sender-controlled network discovery. Current Pubky directory membership and revocation
    /// state remain intentionally unchecked. Call [`IncomingV3::accept`] to perform that bounded
    /// discovery, commit anti-rollback floors, send the signed Ack, and obtain a [`Peer`].
    ///
    /// # Errors
    ///
    /// Returns an error after this endpoint is closed.
    pub async fn next_incoming(&self) -> Result<IncomingV3> {
        self.inner.pending.next().await
    }

    /// Alias for [`Self::next_incoming`].
    ///
    /// # Errors
    ///
    /// Returns an error after this endpoint is closed.
    pub async fn accept(&self) -> Result<IncomingV3> {
        self.next_incoming().await
    }

    /// Close the local iroh endpoint.
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
        self.entries.retain(|_, entry| entry.expires_at >= now);
        if self.entries.contains_key(&key) {
            return Err(ClientError::UnexpectedPeer);
        }
        if self.entries.len() >= self.capacity {
            return Err(ClientError::Iroh(
                "v3 replay cache is at its authenticated-entry limit".to_owned(),
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
                "v3 replay cache is at its per-identity entry limit".to_owned(),
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
async fn handle_incoming_v3(
    incoming: iroh::endpoint::Incoming,
    local: Arc<V3DeviceCredential>,
    resolver: Arc<dyn V3DeviceResolver>,
    active_locators: Arc<Mutex<HashMap<String, V3SignedLocator>>>,
    replay: Arc<Mutex<ReplayCache>>,
    pending_queue: Arc<PendingQueue>,
    config: V3ClientConfig,
    pre_hello_deadline: Instant,
    capacity_permit: OwnedSemaphorePermit,
) -> Result<()> {
    let connection = timeout_at(pre_hello_deadline, async move { incoming.await })
        .await
        .map_err(|_| ClientError::Timeout("pre-authenticating inbound v3 QUIC"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let result = authenticate_incoming_v3(
        connection.clone(),
        local,
        resolver,
        active_locators,
        replay,
        pending_queue,
        &config,
        pre_hello_deadline,
        capacity_permit,
    )
    .await;
    if result.is_err() {
        connection.close(1u32.into(), b"invalid v3 handshake");
    }
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "keeps untrusted connection state explicit at the authentication boundary"
)]
async fn authenticate_incoming_v3(
    connection: Connection,
    local: Arc<V3DeviceCredential>,
    resolver: Arc<dyn V3DeviceResolver>,
    active_locators: Arc<Mutex<HashMap<String, V3SignedLocator>>>,
    replay: Arc<Mutex<ReplayCache>>,
    pending_queue: Arc<PendingQueue>,
    config: &V3ClientConfig,
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
        let target_locator = {
            let mut locators = active_locators.lock().await;
            let now = now_seconds();
            locators.retain(|_, locator| locator.claims.expires_at >= now);
            locators.get(&hello.claims.target_locator_digest).cloned()
        }
        .ok_or(ClientError::UnexpectedPeer)?;

        let sender_certificate = hello.claims.from_certificate.clone();
        let sender_locator = hello.claims.from_locator.clone();
        hello.verify(
            &sender_certificate,
            &local.certificate,
            &target_locator,
            &hello.claims.application,
            now_seconds(),
            config.allow_insecure_loopback_relay,
        )?;
        let certified_remote = EndpointId::from_z32(&sender_certificate.claims.iroh_endpoint_id)
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
                IncomingV3 {
                    pending: Some(PendingV3 {
                        connection,
                        send,
                        recv,
                        local,
                        resolver,
                        sender_certificate,
                        sender_locator,
                        target_locator,
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
            // This task inserted the fresh replay key above. A request rejected by the global or
            // per-identity pending bound was never admitted and must not consume replay capacity.
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
    // Every operation here is offline. In particular, a remotely supplied identity cannot cause
    // Pubky/PKARR, homeserver, DNS, redirect, or direct-address egress before application consent.
    // The same global unauthenticated permit remains held until verification succeeds or times
    // out.
    time::timeout(config.peer_handshake_timeout, operation)
        .await
        .map_err(|_| ClientError::Timeout("authenticating signed inbound v3 Hello"))?
}

async fn receive_initial_hello(
    connection: &Connection,
    deadline: Instant,
) -> Result<(SendStream, RecvStream, V3SignedHello)> {
    timeout_at(deadline, async {
        let (send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        // `incoming.await` yields only after TLS 1.3, and this endpoint never calls
        // `Accepting::into_0rtt`. This rejects a visibly early stream, but cannot detect hostile
        // 0-RTT already buffered before the full await. Such bytes remain encrypted, flow-control
        // bounded, and are not surfaced as application data before explicit consent.
        if recv.is_0rtt() {
            return Err(ClientError::UnexpectedPeer);
        }
        let hello = read_json(&mut recv, MAX_HANDSHAKE_BYTES).await?;
        Ok((send, recv, hello))
    })
    .await
    .map_err(|_| ClientError::Timeout("receiving initial v3 Hello"))?
}

async fn reserve_replay(replay: &Arc<Mutex<ReplayCache>>, hello: &V3SignedHello) -> Result<String> {
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
        return Err(ClientError::Timeout("queueing inbound v3 consent"));
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
    // The queue owns the pending request, but the timer owns only a weak queue reference. Thus a
    // blocked application need not poll `next_incoming` for expiry to remove the entry, close the
    // connection, and release both its queue capacity and handshake permit.
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
                connection.close(1u32.into(), b"v3 consent timeout");
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
    locator: &V3SignedLocator,
    config: &V3ClientConfig,
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
    let secure = url.scheme() == "https";
    let local = allow_loopback
        && url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
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
            "invalid v3 application identifier".to_owned(),
        ));
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
            "v3 QUIC control message exceeds byte limit".to_owned(),
        ));
    }
    write_bytes(stream, &bytes).await
}

async fn read_json<T: for<'de> Deserialize<'de>>(stream: &mut RecvStream, max: usize) -> Result<T> {
    let bytes = read_bytes(stream, max).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Iroh("malformed v3 QUIC control message".to_owned()))
}

async fn write_bytes(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ClientError::Iroh("v3 QUIC frame is too large".to_owned()))?;
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
            "v3 peer frame exceeds the {max} byte limit"
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
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use hole_punchky_protocol::{V3DeviceCredential, now_seconds};
    use iroh_relay::server::{
        RelayConfig as RelayServerConfig, Server as RelayServer,
        ServerConfig as RelayServerConfigSet,
    };
    use pubky::Keypair;

    use super::*;
    use crate::{ConnectionPath, SequenceStore, StaticV3Resolver};

    const TEST_APPLICATION: &str = "pubky2pubky/test/echo";

    #[derive(Debug, Default)]
    struct CountingSequenceStore {
        writes: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SequenceStore for CountingSequenceStore {
        async fn record(&self, _identity: &str, _scope: &str, _value: u64) -> Result<()> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingV3Resolver {
        inner: StaticV3Resolver,
        outbound_resolutions: AtomicUsize,
        accepted_inbound_resolutions: AtomicUsize,
        commits: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl V3DeviceResolver for CountingV3Resolver {
        async fn resolve_devices(&self, identity: &str) -> Result<Vec<ResolvedV3Device>> {
            self.outbound_resolutions.fetch_add(1, Ordering::Relaxed);
            self.inner.resolve_devices(identity).await
        }

        async fn resolve_devices_for_accepted_inbound(
            &self,
            identity: &str,
        ) -> Result<Vec<ResolvedV3Device>> {
            self.accepted_inbound_resolutions
                .fetch_add(1, Ordering::Relaxed);
            self.inner
                .resolve_devices_for_accepted_inbound(identity)
                .await
        }

        async fn commit_device(&self, device: &ResolvedV3Device) -> Result<()> {
            self.commits.fetch_add(1, Ordering::Relaxed);
            self.inner.commit_device(device).await
        }
    }

    fn credential(root: &Keypair, device: &str) -> V3DeviceCredential {
        let now = now_seconds();
        V3DeviceCredential::issue(root, device, now.saturating_sub(1), now + 3_600)
            .unwrap_or_else(|error| panic!("issuing v3 credential: {error}"))
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

    fn config(relay_url: Url, force_relay: bool, handshake_timeout: Duration) -> V3ClientConfig {
        let mut config = if force_relay {
            V3ClientConfig::relay_only(
                PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
                vec![TEST_APPLICATION.to_owned()],
            )
        } else {
            V3ClientConfig::direct(
                PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
                vec![TEST_APPLICATION.to_owned()],
            )
        };
        config.trusted_relays = vec![IrohRelayConfig::new(relay_url)];
        config.allow_insecure_loopback_relay = true;
        if !force_relay {
            config.udp_bind_addresses = vec![SocketAddr::from(([127, 0, 0, 1], 0))];
        }
        config.endpoint_online_timeout = Duration::from_secs(10);
        config.negotiation_timeout = Duration::from_secs(15);
        config.peer_handshake_timeout = handshake_timeout;
        config
    }

    async fn pair(
        relay_url: Url,
        force_relay: bool,
        handshake_timeout: Duration,
    ) -> (V3Client, V3Client, String) {
        pair_with_configs(
            config(relay_url.clone(), force_relay, handshake_timeout),
            config(relay_url, force_relay, handshake_timeout),
        )
        .await
    }

    async fn pair_with_configs(
        alice_config: V3ClientConfig,
        bob_config: V3ClientConfig,
    ) -> (V3Client, V3Client, String) {
        let resolver = Arc::new(StaticV3Resolver::new(true));
        let alice_credential = credential(&Keypair::random(), "alice-device");
        let bob_credential = credential(&Keypair::random(), "bob-device");
        let alice = V3Client::bind(alice_credential, resolver.clone(), alice_config)
            .await
            .unwrap_or_else(|error| panic!("binding Alice: {error}"));
        let bob = V3Client::bind(bob_credential, resolver.clone(), bob_config)
            .await
            .unwrap_or_else(|error| panic!("binding Bob: {error}"));
        let alice_locator = alice
            .current_locator(1, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("Alice locator: {error}"));
        let bob_locator = bob
            .current_locator(1, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("Bob locator: {error}"));
        resolver
            .insert(alice.certificate().clone(), alice_locator)
            .await;
        resolver
            .insert(bob.certificate().clone(), bob_locator)
            .await;
        let bob_identity = bob.identity().to_owned();
        (alice, bob, bob_identity)
    }

    async fn wait_for_pending_len(client: &V3Client, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if client.inner.pending.len().await == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("pending queue did not reach length {expected}"));
    }

    async fn consent_and_echo(force_relay: bool, expected_path: ConnectionPath) {
        let (relay, relay_url) = relay().await;
        let (alice, bob, bob_identity) =
            pair(relay_url, force_relay, Duration::from_secs(10)).await;
        let dialing_alice = alice.clone();
        let mut dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, Some("bob-device"), TEST_APPLICATION)
                .await
        });

        let incoming = tokio::time::timeout(Duration::from_secs(5), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for authenticated Hello"))
            .unwrap_or_else(|error| panic!("receiving authenticated Hello: {error}"));
        assert_eq!(incoming.identity(), alice.identity());
        assert_eq!(incoming.device_id(), "alice-device");
        assert_eq!(incoming.application(), TEST_APPLICATION);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut dial)
                .await
                .is_err(),
            "initiator must not receive a Peer before explicit consent"
        );
        let bob_peer = incoming
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accepting Hello: {error}"));
        let alice_peer = tokio::time::timeout(Duration::from_secs(5), dial)
            .await
            .unwrap_or_else(|_| panic!("timed out completing accepted dial"))
            .unwrap_or_else(|error| panic!("dial task stopped: {error}"))
            .unwrap_or_else(|error| panic!("accepted dial failed: {error}"));

        alice_peer
            .send(b"v3 authenticated request")
            .await
            .unwrap_or_else(|error| panic!("sending request: {error}"));
        assert_eq!(
            bob_peer
                .recv()
                .await
                .unwrap_or_else(|error| panic!("receiving request: {error}")),
            b"v3 authenticated request"
        );
        bob_peer
            .send(b"v3 authenticated response")
            .await
            .unwrap_or_else(|error| panic!("sending response: {error}"));
        assert_eq!(
            alice_peer
                .recv()
                .await
                .unwrap_or_else(|error| panic!("receiving response: {error}")),
            b"v3 authenticated response"
        );
        let alice_path = alice_peer
            .wait_for_path(expected_path, Duration::from_secs(5))
            .await;
        let bob_path = bob_peer
            .wait_for_path(expected_path, Duration::from_secs(5))
            .await;
        assert_eq!(alice_path, expected_path);
        assert_eq!(bob_path, expected_path);
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
    async fn explicit_consent_releases_direct_authenticated_stream() {
        consent_and_echo(false, ConnectionPath::Direct).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relay_fallback_carries_authenticated_stream_when_ip_is_disabled() {
        consent_and_echo(true, ConnectionPath::Relayed).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inbound_pubky_resolution_starts_only_after_explicit_accept() {
        let (relay, relay_url) = relay().await;
        let alice_resolver = Arc::new(StaticV3Resolver::new(true));
        let bob_resolver = Arc::new(CountingV3Resolver {
            inner: StaticV3Resolver::new(true),
            ..CountingV3Resolver::default()
        });
        let alice = V3Client::bind(
            credential(&Keypair::random(), "alice-device"),
            alice_resolver.clone(),
            config(relay_url.clone(), true, Duration::from_secs(10)),
        )
        .await
        .unwrap_or_else(|error| panic!("binding Alice: {error}"));
        let bob = V3Client::bind(
            credential(&Keypair::random(), "bob-device"),
            bob_resolver.clone(),
            config(relay_url, true, Duration::from_secs(10)),
        )
        .await
        .unwrap_or_else(|error| panic!("binding Bob: {error}"));
        let alice_locator = alice
            .current_locator(1, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("Alice locator: {error}"));
        let bob_locator = bob
            .current_locator(1, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("Bob locator: {error}"));
        alice_resolver
            .insert(bob.certificate().clone(), bob_locator)
            .await;
        bob_resolver
            .inner
            .insert(alice.certificate().clone(), alice_locator)
            .await;

        let dialing_alice = alice.clone();
        let bob_identity = bob.identity().to_owned();
        let dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(5), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for offline-authenticated Hello"))
            .unwrap_or_else(|error| panic!("receiving offline-authenticated Hello: {error}"));

        assert_eq!(
            bob_resolver
                .accepted_inbound_resolutions
                .load(Ordering::Relaxed),
            0,
            "no resolver, Pubky, PKARR, DNS, or homeserver call may precede consent"
        );
        assert_eq!(bob_resolver.commits.load(Ordering::Relaxed), 0);

        let bob_peer = incoming
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accepting Hello: {error}"));
        let alice_peer = tokio::time::timeout(Duration::from_secs(5), dial)
            .await
            .unwrap_or_else(|_| panic!("accepted dial did not complete"))
            .unwrap_or_else(|error| panic!("dial task stopped: {error}"))
            .unwrap_or_else(|error| panic!("accepted dial failed: {error}"));
        assert_eq!(
            bob_resolver
                .accepted_inbound_resolutions
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(bob_resolver.commits.load(Ordering::Relaxed), 1);

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
    async fn inbound_floors_commit_only_after_exact_publication_is_revalidated() {
        let (relay, relay_url) = relay().await;
        let durable = Arc::new(CountingSequenceStore::default());
        let alice_resolver = Arc::new(StaticV3Resolver::new(true));
        let bob_resolver =
            Arc::new(StaticV3Resolver::new(true).with_sequence_store(durable.clone()));
        let alice_credential = credential(&Keypair::random(), "alice-device");
        let bob_credential = credential(&Keypair::random(), "bob-device");
        let alice = V3Client::bind(
            alice_credential,
            alice_resolver.clone(),
            config(relay_url.clone(), true, Duration::from_secs(10)),
        )
        .await
        .unwrap_or_else(|error| panic!("binding Alice: {error}"));
        let bob = V3Client::bind(
            bob_credential,
            bob_resolver.clone(),
            config(relay_url, true, Duration::from_secs(10)),
        )
        .await
        .unwrap_or_else(|error| panic!("binding Bob: {error}"));
        let alice_locator = alice
            .current_locator(1, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("Alice locator: {error}"));
        let bob_locator = bob
            .current_locator(1, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("Bob locator: {error}"));
        alice_resolver
            .insert(bob.certificate().clone(), bob_locator)
            .await;
        bob_resolver
            .insert(alice.certificate().clone(), alice_locator)
            .await;
        let bob_identity = bob.identity().to_owned();

        let first_alice = alice.clone();
        let first_identity = bob_identity.clone();
        let first_dial = tokio::spawn(async move {
            first_alice
                .dial(&first_identity, None, TEST_APPLICATION)
                .await
        });
        let first_incoming = tokio::time::timeout(Duration::from_secs(5), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for first Hello"))
            .unwrap_or_else(|error| panic!("receiving first Hello: {error}"));
        assert_eq!(durable.writes.load(Ordering::Relaxed), 0);

        let replacement = alice
            .current_locator(2, Duration::from_secs(300))
            .await
            .unwrap_or_else(|error| panic!("replacement Alice locator: {error}"));
        bob_resolver.replace(Vec::new()).await;
        bob_resolver
            .insert(alice.certificate().clone(), replacement)
            .await;
        assert!(first_incoming.accept().await.is_err());
        assert_eq!(durable.writes.load(Ordering::Relaxed), 0);
        let first_result = tokio::time::timeout(Duration::from_secs(5), first_dial)
            .await
            .unwrap_or_else(|_| panic!("changed-publication dial did not close"))
            .unwrap_or_else(|error| panic!("first dial task stopped: {error}"));
        assert!(first_result.is_err());

        let second_alice = alice.clone();
        let second_dial = tokio::spawn(async move {
            second_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let second_incoming = tokio::time::timeout(Duration::from_secs(5), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for second Hello"))
            .unwrap_or_else(|error| panic!("receiving second Hello: {error}"));
        assert_eq!(durable.writes.load(Ordering::Relaxed), 0);
        let bob_peer = second_incoming
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accepting revalidated Hello: {error}"));
        let alice_peer = tokio::time::timeout(Duration::from_secs(5), second_dial)
            .await
            .unwrap_or_else(|_| panic!("accepted dial did not complete"))
            .unwrap_or_else(|error| panic!("second dial task stopped: {error}"))
            .unwrap_or_else(|error| panic!("second dial failed: {error}"));
        assert_eq!(durable.writes.load(Ordering::Relaxed), 2);

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
    async fn rejection_closes_without_ack_or_peer() {
        let (relay, relay_url) = relay().await;
        let (alice, bob, bob_identity) = pair(relay_url, false, Duration::from_secs(5)).await;
        let dialing_alice = alice.clone();
        let dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(3), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for rejected Hello"))
            .unwrap_or_else(|error| panic!("receiving rejected Hello: {error}"));
        incoming.reject();
        let result = tokio::time::timeout(Duration::from_secs(3), dial)
            .await
            .unwrap_or_else(|_| panic!("rejected dial did not close"))
            .unwrap_or_else(|error| panic!("dial task stopped: {error}"));
        assert!(result.is_err(), "rejection must not release a Peer");
        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dropped_or_expired_consent_never_releases_peer() {
        let (relay, relay_url) = relay().await;
        let timeout = Duration::from_millis(500);
        let (alice, bob, bob_identity) = pair(relay_url, false, timeout).await;
        let dialing_alice = alice.clone();
        let dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(3), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for expiring Hello"))
            .unwrap_or_else(|error| panic!("receiving expiring Hello: {error}"));
        tokio::time::sleep(timeout + Duration::from_millis(150)).await;
        assert!(incoming.accept().await.is_err());
        let result = tokio::time::timeout(Duration::from_secs(3), dial)
            .await
            .unwrap_or_else(|_| panic!("expired dial did not close"))
            .unwrap_or_else(|error| panic!("dial task stopped: {error}"));
        assert!(result.is_err(), "expired consent must not release a Peer");
        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn undrained_expired_consent_releases_queue_and_handshake_capacity() {
        let (relay, relay_url) = relay().await;
        let alice_config = config(relay_url.clone(), false, Duration::from_secs(5));
        let mut bob_config = config(relay_url, false, Duration::from_millis(400));
        bob_config.max_unauthenticated_handshakes = 1;
        bob_config.incoming_queue_capacity = 1;
        bob_config.max_pending_per_identity = 1;
        let (alice, bob, bob_identity) = pair_with_configs(alice_config, bob_config).await;

        let first_alice = alice.clone();
        let first_identity = bob_identity.clone();
        let first = tokio::spawn(async move {
            first_alice
                .dial(&first_identity, None, TEST_APPLICATION)
                .await
        });
        wait_for_pending_len(&bob, 1).await;

        // Deliberately never drain the first request. Its own deadline task must remove it.
        wait_for_pending_len(&bob, 0).await;
        let first_result = tokio::time::timeout(Duration::from_secs(3), first)
            .await
            .unwrap_or_else(|_| panic!("expired undrained dial did not close"))
            .unwrap_or_else(|error| panic!("first dial task stopped: {error}"));
        assert!(first_result.is_err(), "expiry must not release a Peer");

        // A second authenticated connection proves both the queue slot and the sole global
        // handshake permit held by the first request were released without application polling.
        let second_alice = alice.clone();
        let second = tokio::spawn(async move {
            second_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(3), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("released capacity did not admit a second request"))
            .unwrap_or_else(|error| panic!("receiving second request: {error}"));
        incoming.reject();
        let second_result = tokio::time::timeout(Duration::from_secs(3), second)
            .await
            .unwrap_or_else(|_| panic!("rejected second dial did not close"))
            .unwrap_or_else(|error| panic!("second dial task stopped: {error}"));
        assert!(second_result.is_err(), "rejection must not release a Peer");

        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_pre_hello_connection_releases_global_capacity_on_short_deadline() {
        let (relay, relay_url) = relay().await;
        let alice_config = config(relay_url.clone(), false, Duration::from_secs(5));
        let mut bob_config = config(relay_url.clone(), false, Duration::from_secs(5));
        bob_config.pre_hello_timeout = Duration::from_millis(300);
        bob_config.max_unauthenticated_handshakes = 1;
        let (alice, bob, bob_identity) = pair_with_configs(alice_config, bob_config).await;

        let bob_endpoint = EndpointId::from_z32(bob.iroh_endpoint_id())
            .unwrap_or_else(|error| panic!("Bob endpoint id: {error}"));
        let address = EndpointAddr::from_parts(
            bob_endpoint,
            [TransportAddr::Relay(RelayUrl::from(relay_url))],
        );
        let stalled = tokio::time::timeout(
            Duration::from_secs(3),
            alice.inner.endpoint.connect(address, V3_IROH_ALPN),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out opening stalled QUIC connection"))
        .unwrap_or_else(|error| panic!("opening stalled QUIC connection: {error}"));

        // The client intentionally sends no stream or Hello. The independently short inbound
        // authentication deadline must close it instead of retaining the sole global permit for
        // the much longer consent/peer-handshake timeout.
        tokio::time::timeout(Duration::from_secs(2), stalled.closed())
            .await
            .unwrap_or_else(|_| panic!("stalled pre-Hello connection exceeded short deadline"));

        let dialing_alice = alice.clone();
        let dial = tokio::spawn(async move {
            dialing_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(3), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("released global capacity did not admit valid Hello"))
            .unwrap_or_else(|error| panic!("receiving valid Hello: {error}"));
        incoming.reject();
        let result = tokio::time::timeout(Duration::from_secs(3), dial)
            .await
            .unwrap_or_else(|_| panic!("rejected valid dial did not close"))
            .unwrap_or_else(|error| panic!("valid dial task stopped: {error}"));
        assert!(result.is_err(), "rejection must not release a Peer");

        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authenticated_identity_cannot_fill_multiple_pending_slots() {
        let (relay, relay_url) = relay().await;
        let alice_config = config(relay_url.clone(), false, Duration::from_secs(5));
        let mut bob_config = config(relay_url, false, Duration::from_secs(5));
        bob_config.max_unauthenticated_handshakes = 2;
        bob_config.incoming_queue_capacity = 2;
        bob_config.max_pending_per_identity = 1;
        bob_config.replay_cache_capacity = 2;
        bob_config.replay_cache_per_identity_capacity = 2;
        let (alice, bob, bob_identity) = pair_with_configs(alice_config, bob_config).await;

        let first_alice = alice.clone();
        let first_identity = bob_identity.clone();
        let first = tokio::spawn(async move {
            first_alice
                .dial(&first_identity, None, TEST_APPLICATION)
                .await
        });
        wait_for_pending_len(&bob, 1).await;

        let second_alice = alice.clone();
        let second_identity = bob_identity.clone();
        let second = tokio::spawn(async move {
            second_alice
                .dial(&second_identity, None, TEST_APPLICATION)
                .await
        });
        let second_result = tokio::time::timeout(Duration::from_secs(3), second)
            .await
            .unwrap_or_else(|_| panic!("same-identity excess dial was not rejected"))
            .unwrap_or_else(|error| panic!("second dial task stopped: {error}"));
        assert!(
            second_result.is_err(),
            "per-identity limit must reject a second queued request"
        );
        assert_eq!(bob.inner.pending.len().await, 1);

        let incoming = bob
            .next_incoming()
            .await
            .unwrap_or_else(|error| panic!("receiving first request: {error}"));
        incoming.reject();
        let first_result = tokio::time::timeout(Duration::from_secs(3), first)
            .await
            .unwrap_or_else(|_| panic!("rejected first dial did not close"))
            .unwrap_or_else(|error| panic!("first dial task stopped: {error}"));
        assert!(first_result.is_err(), "rejection must not release a Peer");

        // The queue-rejected second Hello must not poison the two-entry replay cache. The first
        // admitted nonce remains cached, leaving exactly one slot for this fresh third request.
        let third_alice = alice.clone();
        let third = tokio::spawn(async move {
            third_alice
                .dial(&bob_identity, None, TEST_APPLICATION)
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(3), bob.next_incoming())
            .await
            .unwrap_or_else(|_| panic!("queue rejection poisoned replay capacity"))
            .unwrap_or_else(|error| panic!("receiving third request: {error}"));
        incoming.reject();
        let third_result = tokio::time::timeout(Duration::from_secs(3), third)
            .await
            .unwrap_or_else(|_| panic!("rejected third dial did not close"))
            .unwrap_or_else(|error| panic!("third dial task stopped: {error}"));
        assert!(third_result.is_err(), "rejection must not release a Peer");

        alice.close().await;
        bob.close().await;
        relay
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("stopping relay: {error}"));
    }

    #[test]
    fn signed_locator_cannot_select_an_untrusted_relay_origin() {
        let root = Keypair::random();
        let credential = credential(&root, "device");
        let now = now_seconds();
        let advertised = Url::parse("https://attacker.invalid/")
            .unwrap_or_else(|error| panic!("attacker URL: {error}"));
        let locator = V3SignedLocator::sign(
            &credential,
            vec![advertised],
            v3_random_nonce(),
            1,
            now,
            now + 60,
        )
        .unwrap_or_else(|error| panic!("signing locator: {error}"));
        let mut local = V3ClientConfig::direct(
            PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        local.trusted_relays = vec![IrohRelayConfig::new(
            Url::parse("https://trusted.invalid/")
                .unwrap_or_else(|error| panic!("trusted URL: {error}")),
        )];
        assert!(
            trusted_destination_relays(&locator, &local)
                .unwrap_or_else(|error| panic!("matching relays: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn path_policy_requires_matching_acknowledgement_and_transport_settings() {
        let relay = IrohRelayConfig::new(
            Url::parse("https://trusted.invalid/")
                .unwrap_or_else(|error| panic!("trusted URL: {error}")),
        );
        let mut mismatched = V3ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentNetworkExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        mismatched.trusted_relays = vec![relay.clone()];
        assert!(mismatched.validate().is_err());

        let mut relay_with_udp = V3ClientConfig::relay_only(
            PublicContactDisclosure::AcknowledgePreConsentRelayMetadataExposure,
            vec![TEST_APPLICATION.to_owned()],
        );
        relay_with_udp.trusted_relays = vec![relay];
        relay_with_udp.udp_bind_addresses = vec![SocketAddr::from(([127, 0, 0, 1], 0))];
        assert!(relay_with_udp.validate().is_err());
    }

    #[test]
    fn replay_cache_rejects_repeat_without_evicting_live_entries() {
        let mut cache = ReplayCache::new(2, 1);
        cache
            .insert("first".to_owned(), "alice".to_owned(), 20, 10)
            .unwrap_or_else(|error| panic!("first insert: {error}"));
        assert!(
            cache
                .insert("first".to_owned(), "alice".to_owned(), 20, 10)
                .is_err()
        );
        assert!(
            cache
                .insert("second".to_owned(), "alice".to_owned(), 20, 10)
                .is_err(),
            "one identity cannot consume every global replay slot"
        );
        cache
            .insert("second".to_owned(), "bob".to_owned(), 20, 10)
            .unwrap_or_else(|error| panic!("second identity insert: {error}"));
        assert!(
            cache
                .insert("third".to_owned(), "carol".to_owned(), 20, 10)
                .is_err()
        );
        cache
            .insert("third".to_owned(), "alice".to_owned(), 30, 21)
            .unwrap_or_else(|error| panic!("insert after expiry: {error}"));
    }
}
