use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

use futures_util::StreamExt as _;
use hole_punchky_protocol::{
    Accept, Authenticated, ClientFrame, DeviceCertificate, DeviceCredential, EncryptedSignal,
    IROH_ALPN, IrohEndpointAddress, Knock, PROTOCOL_VERSION, ServerFrame, SignalPayload,
    now_seconds,
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    TransportAddr,
    endpoint::{Connection, RecvStream, SendStream, presets},
    tls::CaTlsConfig,
};
use n0_watcher::Watcher as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt as _,
    sync::{Mutex, broadcast, oneshot},
    task::JoinHandle,
};
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::{
    ClientError, IncomingKnock, RendezvousClient, RendezvousClientConfig, Result,
    signaling::WireEvent,
};

const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// Path policy applied to the iroh endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathPolicy {
    /// Attempt direct QUIC and keep the configured iroh relay as fallback.
    #[default]
    DirectWithRelayFallback,
    /// Disable IP transports and carry QUIC only through an iroh relay.
    RelayOnly,
}

/// Configuration for one trusted iroh relay.
#[derive(Clone)]
pub struct IrohRelayConfig {
    /// HTTP(S) endpoint of the relay.
    pub url: Url,
    /// Optional bearer token configured on a private relay.
    pub auth_token: Option<String>,
}

impl std::fmt::Debug for IrohRelayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IrohRelayConfig")
            .field("url", &self.url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl IrohRelayConfig {
    /// Configure a relay without application-level authentication.
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self {
            url,
            auth_token: None,
        }
    }

    /// Attach a bearer token used when registering with this relay.
    #[must_use]
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

/// Parameters sent in a consent-first knock.
#[derive(Debug, Clone)]
pub struct DialOptions {
    /// Application protocol expected on the resulting QUIC stream.
    pub application: String,
    /// Route only to this device id instead of fanning out to all online devices.
    pub target_device_id: Option<String>,
    /// Non-secret application hint shown before consent.
    pub metadata: Option<Value>,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            application: "hole-punchky/raw/1".to_owned(),
            target_device_id: None,
            metadata: None,
        }
    }
}

/// Actual network path selected by iroh QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    /// An IP path is selected.
    Direct,
    /// An iroh relay path is selected.
    Relayed,
    /// No selected path has been reported yet.
    Unknown,
}

/// An authenticated iroh QUIC stream connected to a known Pubky identity.
pub struct Peer {
    connection: Connection,
    send: Mutex<Option<SendStream>>,
    recv: Mutex<RecvStream>,
    session_id: Uuid,
    remote_identity: String,
    remote_device_id: String,
    max_message_bytes: usize,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Peer")
            .field("session_id", &self.session_id)
            .field("peer_identity", &self.remote_identity)
            .field("peer_device_id", &self.remote_device_id)
            .field("path", &self.path())
            .finish_non_exhaustive()
    }
}

impl Peer {
    fn new(
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        session_id: Uuid,
        remote_identity: String,
        remote_device_id: String,
        max_message_bytes: usize,
    ) -> Self {
        Self {
            connection,
            send: Mutex::new(Some(send)),
            recv: Mutex::new(recv),
            session_id,
            remote_identity,
            remote_device_id,
            max_message_bytes,
        }
    }

    /// Bound rendezvous session id.
    #[must_use]
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Authenticated peer Pubky identity.
    #[must_use]
    pub fn peer_identity(&self) -> &str {
        &self.remote_identity
    }

    /// Authenticated delegated device id.
    #[must_use]
    pub fn peer_device_id(&self) -> &str {
        &self.remote_device_id
    }

    /// Send one length-delimited binary message.
    ///
    /// # Errors
    ///
    /// Returns an error when the message exceeds the configured bound or QUIC is closed.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > self.max_message_bytes {
            return Err(ClientError::Iroh(format!(
                "message exceeds the {} byte limit",
                self.max_message_bytes
            )));
        }
        let mut guard = self.send.lock().await;
        let stream = guard.as_mut().ok_or(ClientError::ChannelClosed)?;
        write_bytes(stream, data).await
    }

    /// Send one UTF-8 message.
    ///
    /// # Errors
    ///
    /// Returns an error when the message exceeds the configured bound or QUIC is closed.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        self.send(text.as_bytes()).await
    }

    /// Receive one complete binary message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ChannelClosed`] at the end of the stream.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut stream = self.recv.lock().await;
        read_bytes(&mut stream, self.max_message_bytes).await
    }

    /// Inspect the selected iroh path.
    #[must_use]
    pub fn path(&self) -> ConnectionPath {
        selected_path(&self.connection)
    }

    /// Wait for a preferred path, returning the last observed path on timeout.
    pub async fn wait_for_path(
        &self,
        preferred: ConnectionPath,
        timeout: Duration,
    ) -> ConnectionPath {
        let connection = self.connection.clone();
        let wait = async move {
            let mut paths = connection.paths_stream();
            while let Some(snapshot) = paths.next().await {
                let current = snapshot
                    .iter()
                    .find(iroh::endpoint::Path::is_selected)
                    .map_or(ConnectionPath::Unknown, |path| {
                        if path.is_ip() {
                            ConnectionPath::Direct
                        } else if path.is_relay() {
                            ConnectionPath::Relayed
                        } else {
                            ConnectionPath::Unknown
                        }
                    });
                if current == preferred {
                    return current;
                }
            }
            ConnectionPath::Unknown
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or_else(|_| self.path())
    }

    /// Flush pending stream bytes to the QUIC transport.
    ///
    /// # Errors
    ///
    /// Returns an error when QUIC fails or the supplied timeout elapses.
    pub async fn flush(&self, timeout: Duration) -> Result<()> {
        let mut guard = self.send.lock().await;
        let stream = guard.as_mut().ok_or(ClientError::ChannelClosed)?;
        tokio::time::timeout(timeout, stream.flush())
            .await
            .map_err(|_| ClientError::Timeout("flushing peer QUIC stream"))?
            .map_err(|error| ClientError::Iroh(error.to_string()))
    }

    /// Finish the send direction and wait until the peer acknowledges all stream bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream was already closed, the peer stops it, QUIC fails, or
    /// the supplied timeout elapses before all bytes are acknowledged.
    pub async fn finish(&self, timeout: Duration) -> Result<()> {
        let mut stream = self
            .send
            .lock()
            .await
            .take()
            .ok_or(ClientError::ChannelClosed)?;
        stream
            .finish()
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        match tokio::time::timeout(timeout, stream.stopped()).await {
            Err(_) => Err(ClientError::Timeout("draining peer QUIC stream")),
            Ok(Err(error)) => Err(ClientError::Iroh(error.to_string())),
            Ok(Ok(Some(code))) => Err(ClientError::Iroh(format!(
                "peer stopped QUIC stream with code {code}"
            ))),
            Ok(Ok(None)) => Ok(()),
        }
    }

    /// Wait until the peer finishes its send direction.
    ///
    /// Call this after [`Self::finish`] on both peers when an application needs a symmetric,
    /// graceful shutdown before either side closes the QUIC connection. All framed messages must
    /// have been consumed first.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer sends trailing bytes, QUIC fails, or the supplied timeout
    /// elapses before the peer's FIN arrives.
    pub async fn wait_for_peer_finish(&self, timeout: Duration) -> Result<()> {
        let mut stream = self.recv.lock().await;
        let mut trailing = [0u8; 1];
        match tokio::time::timeout(timeout, stream.read(&mut trailing)).await {
            Err(_) => Err(ClientError::Timeout("waiting for peer QUIC stream finish")),
            Ok(Err(error)) => Err(ClientError::Iroh(error.to_string())),
            Ok(Ok(None | Some(0))) => Ok(()),
            Ok(Ok(Some(_))) => Err(ClientError::Iroh(
                "peer sent trailing bytes after the close handshake".to_owned(),
            )),
        }
    }

    /// Close this QUIC connection, making a best effort to finish the send direction first.
    ///
    /// # Errors
    ///
    /// This does not wait for buffered bytes to be acknowledged. Call [`Self::finish`] first when
    /// delivery confirmation is required.
    pub async fn close(&self) -> Result<()> {
        if let Some(mut stream) = self.send.lock().await.take() {
            let _ = stream.finish();
        }
        self.connection.close(0u32.into(), b"application closed");
        Ok(())
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"peer dropped");
    }
}

fn selected_path(connection: &Connection) -> ConnectionPath {
    connection
        .paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(ConnectionPath::Unknown, |path| {
            if path.is_ip() {
                ConnectionPath::Direct
            } else if path.is_relay() {
                ConnectionPath::Relayed
            } else {
                ConnectionPath::Unknown
            }
        })
}

fn has_public_direct_address(address: &EndpointAddr) -> bool {
    address.ip_addrs().any(|candidate| {
        !matches!(
            candidate.ip(),
            IpAddr::V4(ip) if ip.is_private()
        ) && !matches!(candidate.ip(), IpAddr::V6(ip) if ip.is_unique_local())
            && !candidate.ip().is_loopback()
            && !candidate.ip().is_unspecified()
            && !candidate.ip().is_multicast()
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamHello {
    version: u16,
    session_id: Uuid,
    from_identity: String,
    from_device_id: String,
    to_identity: String,
    to_device_id: String,
    application: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamAck {
    version: u16,
    session_id: Uuid,
}

struct PendingSession {
    remote_endpoint_id: EndpointId,
    remote_identity: String,
    remote_device_id: String,
    local_identity: String,
    local_device_id: String,
    application: String,
    sender: oneshot::Sender<IncomingPeer>,
}

struct IncomingPeer {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
}

struct AbortTask(JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct IrohTransport {
    endpoint: Endpoint,
    pending: Arc<Mutex<HashMap<Uuid, PendingSession>>>,
    _accept_task: Arc<AbortTask>,
    handshake_timeout: Duration,
    max_message_bytes: usize,
}

impl IrohTransport {
    pub(crate) async fn bind(
        credential: &DeviceCredential,
        config: &RendezvousClientConfig,
    ) -> Result<Self> {
        let key_bytes = credential.iroh_secret_key_bytes()?;
        let secret = SecretKey::from_bytes(&key_bytes);
        if secret.public().to_z32() != credential.iroh_endpoint_id() {
            return Err(ClientError::UnexpectedPeer);
        }

        let relay_map = config
            .relay_servers
            .iter()
            .map(|configured| {
                validate_relay_url(&configured.url, config.allow_insecure_relay)?;
                let relay_url = RelayUrl::from(configured.url.clone());
                // RelayConfig::from enables iroh's standard QUIC address-discovery endpoint on
                // UDP 7842. Without QAD a NATed endpoint usually advertises only private socket
                // addresses and can relay, but has no reflexive candidate to hole-punch.
                let mut relay = RelayConfig::from(relay_url);
                if let Some(token) = &configured.auth_token {
                    if token.is_empty() {
                        return Err(ClientError::Iroh(
                            "iroh relay authentication token must not be empty".to_owned(),
                        ));
                    }
                    relay = relay.with_auth_token(token);
                }
                Ok(relay)
            })
            .collect::<Result<Vec<_>>>()?;

        let relay_mode = if relay_map.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(relay_map.into_iter().collect::<RelayMap>())
        };
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![IROH_ALPN.to_vec()])
            .relay_mode(relay_mode)
            .clear_address_lookup()
            .clear_ip_transports();
        if !config.relay_ca_certificates.is_empty() {
            builder = builder
                .ca_tls_config(CaTlsConfig::default().with_extra_roots(
                    config.relay_ca_certificates.iter().cloned().map(Into::into),
                ));
        }
        if config.path_policy == PathPolicy::DirectWithRelayFallback {
            for address in &config.udp_bind_addresses {
                builder = builder
                    .bind_addr(*address)
                    .map_err(|error| ClientError::Iroh(error.to_string()))?;
            }
        } else if config.relay_servers.is_empty() {
            return Err(ClientError::Iroh(
                "relay-only policy requires at least one iroh relay".to_owned(),
            ));
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;

        if !config.relay_servers.is_empty()
            && tokio::time::timeout(config.endpoint_online_timeout, endpoint.online())
                .await
                .is_err()
        {
            endpoint.close().await;
            return Err(ClientError::Timeout("registering with iroh relay"));
        }

        let pending = Arc::new(Mutex::new(HashMap::new()));
        let task_endpoint = endpoint.clone();
        let task_pending = Arc::clone(&pending);
        let handshake_timeout = config.peer_handshake_timeout;
        let task = tokio::spawn(async move {
            while let Some(incoming) = task_endpoint.accept().await {
                let pending = Arc::clone(&task_pending);
                tokio::spawn(async move {
                    if let Err(error) = handle_incoming(incoming, pending, handshake_timeout).await
                    {
                        debug!(%error, "discarded unauthorized iroh connection");
                    }
                });
            }
        });

        debug!(endpoint_id = %endpoint.id().to_z32(), "iroh endpoint online");
        Ok(Self {
            endpoint,
            pending,
            _accept_task: Arc::new(AbortTask(task)),
            handshake_timeout,
            max_message_bytes: config.max_message_bytes,
        })
    }

    pub(crate) async fn endpoint_address(&self) -> IrohEndpointAddress {
        let mut watcher = self.endpoint.watch_addr();
        let address = if has_public_direct_address(&watcher.get()) {
            watcher.get()
        } else {
            let wait = async {
                loop {
                    watcher.updated().await.ok()?;
                    let address = watcher.get();
                    if has_public_direct_address(&address) {
                        return Some(address);
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(3), wait)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| watcher.get())
        };
        IrohEndpointAddress {
            endpoint_id: address.id.to_z32(),
            relay_urls: address.relay_urls().cloned().map(Url::from).collect(),
            direct_addresses: address.ip_addrs().copied().collect(),
        }
    }

    async fn register(
        &self,
        session_id: Uuid,
        remote_certificate: &DeviceCertificate,
        local_credential: &DeviceCredential,
        application: String,
    ) -> Result<oneshot::Receiver<IncomingPeer>> {
        let remote_endpoint_id = EndpointId::from_z32(&remote_certificate.claims.iroh_endpoint_id)
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let (sender, receiver) = oneshot::channel();
        let pending = PendingSession {
            remote_endpoint_id,
            remote_identity: remote_certificate.claims.identity.clone(),
            remote_device_id: remote_certificate.claims.device_id.clone(),
            local_identity: local_credential.identity().to_owned(),
            local_device_id: local_credential.device_id().to_owned(),
            application,
            sender,
        };
        if self
            .pending
            .lock()
            .await
            .insert(session_id, pending)
            .is_some()
        {
            return Err(ClientError::Iroh(
                "duplicate pending iroh session".to_owned(),
            ));
        }
        Ok(receiver)
    }

    async fn remove(&self, session_id: Uuid) {
        self.pending.lock().await.remove(&session_id);
    }

    pub(crate) async fn close(&self) {
        self.endpoint.close().await;
    }

    async fn dial(
        &self,
        endpoint: IrohEndpointAddress,
        hello: StreamHello,
    ) -> Result<IncomingPeer> {
        endpoint.validate()?;
        let expected_id = EndpointId::from_z32(&endpoint.endpoint_id)
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        let address = EndpointAddr::from_parts(
            expected_id,
            endpoint
                .relay_urls
                .into_iter()
                .map(|url| TransportAddr::Relay(RelayUrl::from(url)))
                .chain(endpoint.direct_addresses.into_iter().map(TransportAddr::Ip)),
        );
        let connection = tokio::time::timeout(
            self.handshake_timeout,
            self.endpoint.connect(address, IROH_ALPN),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting iroh QUIC peer"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
        if connection.remote_id() != expected_id {
            connection.close(1u32.into(), b"unexpected endpoint id");
            return Err(ClientError::UnexpectedPeer);
        }
        let (mut send, mut recv) =
            tokio::time::timeout(self.handshake_timeout, connection.open_bi())
                .await
                .map_err(|_| ClientError::Timeout("opening authenticated QUIC stream"))?
                .map_err(|error| ClientError::Iroh(error.to_string()))?;
        write_json(&mut send, &hello, MAX_HANDSHAKE_BYTES).await?;
        let ack: StreamAck = read_json(&mut recv, MAX_HANDSHAKE_BYTES).await?;
        if ack.version != PROTOCOL_VERSION || ack.session_id != hello.session_id {
            connection.close(1u32.into(), b"invalid session acknowledgement");
            return Err(ClientError::UnexpectedPeer);
        }
        Ok(IncomingPeer {
            connection,
            send,
            recv,
        })
    }
}

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    pending: Arc<Mutex<HashMap<Uuid, PendingSession>>>,
    timeout: Duration,
) -> Result<()> {
    let connection = tokio::time::timeout(timeout, async move { incoming.await })
        .await
        .map_err(|_| ClientError::Timeout("authenticating inbound iroh QUIC peer"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let remote_endpoint_id = connection.remote_id();
    let (mut send, mut recv) = tokio::time::timeout(timeout, connection.accept_bi())
        .await
        .map_err(|_| ClientError::Timeout("receiving authenticated QUIC stream"))?
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let hello: StreamHello = read_json(&mut recv, MAX_HANDSHAKE_BYTES).await?;
    let expected = {
        let mut sessions = pending.lock().await;
        let matches = sessions.get(&hello.session_id).is_some_and(|expected| {
            hello.version == PROTOCOL_VERSION
                && expected.remote_endpoint_id == remote_endpoint_id
                && expected.remote_identity == hello.from_identity
                && expected.remote_device_id == hello.from_device_id
                && expected.local_identity == hello.to_identity
                && expected.local_device_id == hello.to_device_id
                && expected.application == hello.application
        });
        matches
            .then(|| sessions.remove(&hello.session_id))
            .flatten()
    };
    let Some(expected) = expected else {
        connection.close(1u32.into(), b"unauthorized rendezvous session");
        return Err(ClientError::UnexpectedPeer);
    };
    write_json(
        &mut send,
        &StreamAck {
            version: PROTOCOL_VERSION,
            session_id: hello.session_id,
        },
        MAX_HANDSHAKE_BYTES,
    )
    .await?;
    expected
        .sender
        .send(IncomingPeer {
            connection,
            send,
            recv,
        })
        .map_err(|_| ClientError::ChannelClosed)
}

pub(crate) fn validate_relay_url(url: &Url, allow_insecure: bool) -> Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    if allow_insecure && url.scheme() == "http" && relay_url_is_loopback(url) {
        return Ok(());
    }
    Err(ClientError::InvalidRelayUrl)
}

fn relay_url_is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

async fn write_json<T: Serialize>(stream: &mut SendStream, value: &T, max: usize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|error| ClientError::Iroh(error.to_string()))?;
    if bytes.len() > max {
        return Err(ClientError::Iroh(
            "QUIC control message is too large".to_owned(),
        ));
    }
    write_bytes(stream, &bytes).await
}

async fn read_json<T: for<'de> Deserialize<'de>>(stream: &mut RecvStream, max: usize) -> Result<T> {
    let bytes = read_bytes(stream, max).await?;
    serde_json::from_slice(&bytes).map_err(|error| ClientError::Iroh(error.to_string()))
}

async fn write_bytes(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| ClientError::Iroh("QUIC message is too large".to_owned()))?;
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
    let mut encoded_length = [0u8; 4];
    stream
        .read_exact(&mut encoded_length)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    let length = u32::from_be_bytes(encoded_length) as usize;
    if length > max {
        return Err(ClientError::Iroh(format!(
            "peer message exceeds the {max} byte limit"
        )));
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| ClientError::Iroh(error.to_string()))?;
    Ok(bytes)
}

impl RendezvousClient {
    /// Knock a Pubky identity, obtain consent, then establish authenticated iroh QUIC.
    ///
    /// # Errors
    ///
    /// Returns an error on rejection, authentication, signaling, relay, or QUIC failure.
    pub async fn dial(&self, target_identity: &str, options: DialOptions) -> Result<Peer> {
        let timeout = self.config().negotiation_timeout;
        tokio::time::timeout(timeout, self.dial_inner(target_identity, options))
            .await
            .map_err(|_| ClientError::Timeout("negotiating outbound peer connection"))?
    }

    async fn dial_inner(&self, target_identity: &str, options: DialOptions) -> Result<Peer> {
        let mut events = self.subscribe();
        let session_id = Uuid::new_v4();
        let now = now_seconds();
        let knock = Authenticated::sign(
            Knock {
                version: PROTOCOL_VERSION,
                identity: self.credential().identity().to_owned(),
                device_id: self.credential().device_id().to_owned(),
                session_id,
                target_identity: target_identity.to_owned(),
                target_device_id: options.target_device_id.clone(),
                application: options.application.clone(),
                metadata: options.metadata,
                issued_at: now,
                expires_at: now + 30,
            },
            self.credential(),
        )?;
        self.send(ClientFrame::Knock(knock)).await?;

        let (accepted, endpoint) =
            wait_for_accept_and_endpoint(self, &mut events, session_id).await?;
        accepted.verify(now_seconds())?;
        if accepted.payload.session_id != session_id
            || accepted.payload.identity != target_identity
            || accepted.payload.target_identity != self.credential().identity()
            || options
                .target_device_id
                .as_ref()
                .is_some_and(|device| device != &accepted.payload.device_id)
            || endpoint.endpoint_id != accepted.certificate.claims.iroh_endpoint_id
        {
            return Err(ClientError::UnexpectedPeer);
        }
        for relay in &endpoint.relay_urls {
            validate_relay_url(relay, self.config().allow_insecure_relay)?;
        }

        let hello = StreamHello {
            version: PROTOCOL_VERSION,
            session_id,
            from_identity: self.credential().identity().to_owned(),
            from_device_id: self.credential().device_id().to_owned(),
            to_identity: accepted.payload.identity.clone(),
            to_device_id: accepted.payload.device_id.clone(),
            application: options.application,
        };
        let connected = self.transport().dial(endpoint, hello).await?;
        Ok(Peer::new(
            connected.connection,
            connected.send,
            connected.recv,
            session_id,
            accepted.payload.identity,
            accepted.payload.device_id,
            self.transport().max_message_bytes,
        ))
    }

    /// Accept a knock, release this device's encrypted iroh address, and await authenticated QUIC.
    ///
    /// # Errors
    ///
    /// Returns an error on an invalid knock, rendezvous failure, or QUIC timeout/failure.
    pub async fn accept(&self, incoming: IncomingKnock) -> Result<Peer> {
        let timeout = self.config().negotiation_timeout;
        tokio::time::timeout(timeout, self.accept_inner(incoming))
            .await
            .map_err(|_| ClientError::Timeout("negotiating inbound peer connection"))?
    }

    async fn accept_inner(&self, incoming: IncomingKnock) -> Result<Peer> {
        incoming.signed.verify(now_seconds())?;
        let knock = &incoming.signed.payload;
        if knock.target_identity != self.credential().identity()
            || knock
                .target_device_id
                .as_ref()
                .is_some_and(|device| device != self.credential().device_id())
        {
            return Err(ClientError::UnexpectedPeer);
        }
        let pending = self
            .transport()
            .register(
                knock.session_id,
                &incoming.signed.certificate,
                self.credential(),
                knock.application.clone(),
            )
            .await?;
        let result = self.accept_after_register(&incoming, pending).await;
        if result.is_err() {
            self.transport().remove(knock.session_id).await;
        }
        result
    }

    async fn accept_after_register(
        &self,
        incoming: &IncomingKnock,
        pending: oneshot::Receiver<IncomingPeer>,
    ) -> Result<Peer> {
        let knock = &incoming.signed.payload;
        let now = now_seconds();
        let accept = Authenticated::sign(
            Accept {
                version: PROTOCOL_VERSION,
                identity: self.credential().identity().to_owned(),
                device_id: self.credential().device_id().to_owned(),
                session_id: knock.session_id,
                target_identity: knock.identity.clone(),
                issued_at: now,
                expires_at: now + 30,
            },
            self.credential(),
        )?;
        self.send(ClientFrame::Accept(accept)).await?;

        let endpoint = self.transport().endpoint_address().await;
        endpoint.validate()?;
        let signal = EncryptedSignal::seal(
            self.credential(),
            &incoming.signed.certificate,
            knock.session_id,
            0,
            &SignalPayload::IrohEndpoint { endpoint },
            now_seconds(),
            now_seconds() + 30,
        )?;
        self.send(ClientFrame::Signal(signal)).await?;

        let connected = pending.await.map_err(|_| ClientError::ChannelClosed)?;
        Ok(Peer::new(
            connected.connection,
            connected.send,
            connected.recv,
            knock.session_id,
            knock.identity.clone(),
            knock.device_id.clone(),
            self.transport().max_message_bytes,
        ))
    }
}

async fn wait_for_accept_and_endpoint(
    client: &RendezvousClient,
    events: &mut broadcast::Receiver<WireEvent>,
    session_id: Uuid,
) -> Result<(Authenticated<Accept>, IrohEndpointAddress)> {
    let mut accepted: Option<Authenticated<Accept>> = None;
    let mut endpoint: Option<(DeviceCertificate, IrohEndpointAddress)> = None;
    loop {
        if let (Some(accept), Some((certificate, address))) = (&accepted, &endpoint) {
            if accept.certificate != *certificate {
                return Err(ClientError::UnexpectedPeer);
            }
            return Ok((accept.clone(), address.clone()));
        }
        match events.recv().await {
            Ok(WireEvent::Frame(frame)) => match *frame {
                ServerFrame::Accepted(value) if value.payload.session_id == session_id => {
                    accepted = Some(value);
                }
                ServerFrame::Signal(signal) if signal.header.session_id == session_id => {
                    let certificate = signal.certificate.clone();
                    let payload = signal.open(client.credential(), now_seconds())?;
                    if let SignalPayload::IrohEndpoint { endpoint: address } = payload {
                        endpoint = Some((certificate, address));
                    }
                }
                ServerFrame::Rejected(rejected) if rejected.payload.session_id == session_id => {
                    rejected.verify(now_seconds())?;
                    return Err(ClientError::Rejected(rejected.payload.reason));
                }
                ServerFrame::Error {
                    code,
                    message,
                    session_id: related,
                } if related.is_none() || related == Some(session_id) => {
                    return Err(ClientError::Server {
                        code,
                        message,
                        session_id: related,
                    });
                }
                _ => {}
            },
            Ok(WireEvent::Closed(reason)) => {
                return Err(ClientError::RendezvousClosed(reason));
            }
            Err(error) => return Err(ClientError::RendezvousClosed(error.to_string())),
        }
    }
}
