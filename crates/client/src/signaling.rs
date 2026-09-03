use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{SinkExt as _, StreamExt as _};
use hole_punchky_protocol::{
    Authenticated, ClientFrame, DeviceCredential, IROH_TRANSPORT, Knock, PROTOCOL_VERSION,
    Registration, Reject, ServerFrame, now_seconds,
};
use tokio::{
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::{
    ClientError, DescriptorResolver, IrohRelayConfig, PathPolicy, Result, peer::IrohTransport,
};

/// Connection and negotiation policy for a rendezvous client.
#[derive(Debug, Clone)]
pub struct RendezvousClientConfig {
    /// Timeout for the WebSocket handshake and signed registration.
    pub connect_timeout: Duration,
    /// Overall consent, signaling, and iroh connection timeout.
    pub negotiation_timeout: Duration,
    /// Application heartbeat interval used to keep the outbound NAT mapping alive.
    /// Must be non-zero.
    pub heartbeat_interval: Duration,
    /// Time allowed for this endpoint to register with an iroh relay.
    pub endpoint_online_timeout: Duration,
    /// Time allowed for each authenticated QUIC handshake phase.
    pub peer_handshake_timeout: Duration,
    /// Local UDP bind addresses. At most one address per IP family may be supplied.
    pub udp_bind_addresses: Vec<SocketAddr>,
    /// Trusted iroh relays used for NAT discovery and fallback.
    pub relay_servers: Vec<IrohRelayConfig>,
    /// Additional DER-encoded CA certificates trusted for relay QUIC address discovery.
    pub relay_ca_certificates: Vec<Vec<u8>>,
    /// Permit plain HTTP relay URLs with a loopback hostname for local tests.
    pub allow_insecure_relay: bool,
    /// Enable direct paths or force all peer traffic through the relay.
    pub path_policy: PathPolicy,
    /// Maximum size of one length-delimited QUIC application message.
    pub max_message_bytes: usize,
}

impl Default for RendezvousClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            negotiation_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(25),
            endpoint_online_timeout: Duration::from_secs(15),
            peer_handshake_timeout: Duration::from_secs(20),
            udp_bind_addresses: vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            relay_servers: Vec::new(),
            relay_ca_certificates: Vec::new(),
            allow_insecure_relay: false,
            path_policy: PathPolicy::DirectWithRelayFallback,
            max_message_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum WireEvent {
    Frame(Box<ServerFrame>),
    Closed(String),
}

struct Inner {
    credential: Arc<DeviceCredential>,
    config: RendezvousClientConfig,
    outbound: mpsc::Sender<Outbound>,
    events: broadcast::Sender<WireEvent>,
    incoming: Mutex<mpsc::Receiver<Authenticated<Knock>>>,
    transport: IrohTransport,
    connection_id: Uuid,
    task: JoinHandle<()>,
}

struct Outbound {
    frame: ClientFrame,
    sent: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One authenticated inbound consent request.
#[derive(Debug, Clone)]
pub struct IncomingKnock {
    pub(crate) signed: Authenticated<Knock>,
}

impl IncomingKnock {
    /// Signed knock details.
    #[must_use]
    pub const fn knock(&self) -> &Knock {
        &self.signed.payload
    }
}

/// An authenticated, long-lived connection to one public rendezvous service.
#[derive(Clone)]
pub struct RendezvousClient {
    inner: Arc<Inner>,
}

impl RendezvousClient {
    /// Resolve a target's signed descriptor and connect to the first reachable endpoint by
    /// priority.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery fails or every verified endpoint is unreachable or
    /// rejects registration.
    pub async fn connect_resolved(
        resolver: &dyn DescriptorResolver,
        target_identity: &str,
        credential: DeviceCredential,
        config: RendezvousClientConfig,
    ) -> Result<Self> {
        let descriptor = resolver.resolve(target_identity).await?;
        let mut failures = Vec::new();
        for endpoint in descriptor.ordered_endpoints() {
            match Self::connect(
                endpoint.signaling_url.clone(),
                credential.clone(),
                config.clone(),
            )
            .await
            {
                Ok(client) => return Ok(client),
                Err(error) => failures.push(format!("{}: {error}", endpoint.signaling_url)),
            }
        }
        Err(ClientError::Rendezvous(format!(
            "all descriptor endpoints failed: {}",
            failures.join("; ")
        )))
    }

    /// Connect and authenticate as a root-delegated device.
    ///
    /// # Errors
    ///
    /// Returns an error for an insecure URL, invalid credential, WebSocket/registration
    /// failure, server rejection, or timeout.
    #[allow(clippy::too_many_lines)]
    pub async fn connect(
        url: Url,
        credential: DeviceCredential,
        config: RendezvousClientConfig,
    ) -> Result<Self> {
        validate_url(&url)?;
        if config.heartbeat_interval.is_zero() {
            return Err(ClientError::Rendezvous(
                "heartbeat interval must be non-zero".to_owned(),
            ));
        }
        if config.max_message_bytes == 0 || config.max_message_bytes > u32::MAX as usize {
            return Err(ClientError::Iroh(
                "maximum peer message size must fit a non-zero u32".to_owned(),
            ));
        }
        if config.relay_servers.len() > 8 {
            return Err(ClientError::Iroh(
                "at most eight iroh relays may be configured".to_owned(),
            ));
        }
        if config.path_policy == PathPolicy::DirectWithRelayFallback
            && config.udp_bind_addresses.is_empty()
        {
            return Err(ClientError::Iroh(
                "direct path policy requires a UDP bind address".to_owned(),
            ));
        }
        credential
            .certificate
            .verify(now_seconds(), Some("rendezvous"))?;
        let (mut socket, _) =
            tokio::time::timeout(config.connect_timeout, connect_async(url.as_str()))
                .await
                .map_err(|_| ClientError::Timeout("connecting to rendezvous"))?
                .map_err(|error| ClientError::Rendezvous(error.to_string()))?;

        let now = now_seconds();
        let registration = Authenticated::sign(
            Registration {
                version: PROTOCOL_VERSION,
                identity: credential.identity().to_owned(),
                device_id: credential.device_id().to_owned(),
                nonce: Uuid::new_v4().to_string(),
                issued_at: now,
                expires_at: now + 30,
            },
            &credential,
        )?;
        send_socket(&mut socket, &ClientFrame::Register(registration)).await?;
        let first = tokio::time::timeout(config.connect_timeout, socket.next())
            .await
            .map_err(|_| ClientError::Timeout("registering with rendezvous"))?
            .ok_or_else(|| ClientError::RendezvousClosed("closed during registration".to_owned()))?
            .map_err(|error| ClientError::Rendezvous(error.to_string()))?;
        let frame = decode_server(first)?;
        let connection_id = match frame {
            ServerFrame::Registered {
                connection_id,
                transport,
                ..
            } if transport == IROH_TRANSPORT => connection_id,
            ServerFrame::Error {
                code,
                message,
                session_id,
            } => {
                return Err(ClientError::Server {
                    code,
                    message,
                    session_id,
                });
            }
            ServerFrame::Registered { .. } => {
                return Err(ClientError::Rendezvous(
                    "rendezvous selected an unsupported data transport".to_owned(),
                ));
            }
            _ => {
                return Err(ClientError::Rendezvous(
                    "expected registration response".to_owned(),
                ));
            }
        };

        let transport = IrohTransport::bind(&credential, &config).await?;

        let (mut sink, mut stream) = socket.split();
        let (outbound, mut outbound_rx) = mpsc::channel::<Outbound>(128);
        let (events, _) = broadcast::channel::<WireEvent>(256);
        let events_task = events.clone();
        let (incoming_tx, incoming) = mpsc::channel(64);
        let heartbeat_interval = config.heartbeat_interval;
        let task = tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval_at(
                tokio::time::Instant::now() + heartbeat_interval,
                heartbeat_interval,
            );
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let closed_reason = loop {
                tokio::select! {
                    maybe_frame = outbound_rx.recv() => {
                        let Some(outbound) = maybe_frame else {
                            break "outbound channel closed".to_owned();
                        };
                        let json = match serde_json::to_string(&outbound.frame) {
                            Ok(json) => json,
                            Err(error) => {
                                let reason = format!("could not encode frame: {error}");
                                let _ = outbound.sent.send(Err(reason.clone()));
                                break reason;
                            }
                        };
                        if let Err(error) = sink.send(Message::Text(json.into())).await {
                            let reason = error.to_string();
                            let _ = outbound.sent.send(Err(reason.clone()));
                            break reason;
                        }
                        let _ = outbound.sent.send(Ok(()));
                    }
                    maybe_message = stream.next() => {
                        match maybe_message {
                            Some(Ok(message)) => match decode_server(message) {
                                Ok(frame) => {
                                    if let ServerFrame::Knock(knock) = &frame {
                                        let _ = incoming_tx.try_send(knock.clone());
                                    }
                                    let _ = events_task.send(WireEvent::Frame(Box::new(frame)));
                                }
                                Err(error) => break error.to_string(),
                            },
                            Some(Err(error)) => break error.to_string(),
                            None => break "remote endpoint closed".to_owned(),
                        }
                    }
                    _ = heartbeat.tick() => {
                        let frame = ClientFrame::Ping {
                            nonce: Uuid::new_v4().to_string(),
                        };
                        let json = match serde_json::to_string(&frame) {
                            Ok(json) => json,
                            Err(error) => break format!("could not encode heartbeat: {error}"),
                        };
                        if let Err(error) = sink.send(Message::Text(json.into())).await {
                            break error.to_string();
                        }
                    }
                }
            };
            let _ = events_task.send(WireEvent::Closed(closed_reason));
        });

        debug!(%connection_id, %url, "connected to rendezvous");
        Ok(Self {
            inner: Arc::new(Inner {
                credential: Arc::new(credential),
                config,
                outbound,
                events,
                incoming: Mutex::new(incoming),
                transport,
                connection_id,
                task,
            }),
        })
    }

    /// Server-assigned connection identifier.
    #[must_use]
    pub fn connection_id(&self) -> Uuid {
        self.inner.connection_id
    }

    /// Identity registered on this connection.
    #[must_use]
    pub fn identity(&self) -> &str {
        self.inner.credential.identity()
    }

    /// Dedicated iroh endpoint id certified for this device.
    #[must_use]
    pub fn iroh_endpoint_id(&self) -> &str {
        self.inner.credential.iroh_endpoint_id()
    }

    /// Gracefully close this client's shared iroh endpoint and stop rendezvous I/O.
    ///
    /// All clones of this client and peers using its endpoint are affected.
    pub async fn close(&self) {
        self.inner.transport.close().await;
        self.inner.task.abort();
    }

    /// Wait for the next valid knock targeting this identity/device.
    ///
    /// # Errors
    ///
    /// Returns an error when the rendezvous closes or a delivered knock fails verification.
    pub async fn next_knock(&self) -> Result<IncomingKnock> {
        loop {
            let signed = self
                .inner
                .incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| ClientError::RendezvousClosed("incoming queue closed".to_owned()))?;
            signed.verify(now_seconds())?;
            let knock = &signed.payload;
            if knock.target_identity == self.inner.credential.identity()
                && knock
                    .target_device_id
                    .as_ref()
                    .is_none_or(|device| device == self.inner.credential.device_id())
            {
                return Ok(IncomingKnock { signed });
            }
        }
    }

    /// Reject a pending knock without exchanging any network candidates.
    ///
    /// # Errors
    ///
    /// Returns an error when signing or writing the rejection fails.
    pub async fn reject(&self, incoming: &IncomingKnock, reason: impl Into<String>) -> Result<()> {
        let now = now_seconds();
        let reject = Authenticated::sign(
            Reject {
                version: PROTOCOL_VERSION,
                identity: self.inner.credential.identity().to_owned(),
                device_id: self.inner.credential.device_id().to_owned(),
                session_id: incoming.signed.payload.session_id,
                target_identity: incoming.signed.payload.identity.clone(),
                reason: reason.into(),
                issued_at: now,
                expires_at: now + 30,
            },
            &self.inner.credential,
        )?;
        self.send(ClientFrame::Reject(reject)).await
    }

    pub(crate) async fn send(&self, frame: ClientFrame) -> Result<()> {
        let (sent, delivered) = tokio::sync::oneshot::channel();
        self.inner
            .outbound
            .send(Outbound { frame, sent })
            .await
            .map_err(|_| ClientError::RendezvousClosed("writer stopped".to_owned()))?;
        delivered
            .await
            .map_err(|_| ClientError::RendezvousClosed("writer stopped".to_owned()))?
            .map_err(ClientError::Rendezvous)
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<WireEvent> {
        self.inner.events.subscribe()
    }

    pub(crate) fn credential(&self) -> &DeviceCredential {
        &self.inner.credential
    }

    pub(crate) fn config(&self) -> &RendezvousClientConfig {
        &self.inner.config
    }

    pub(crate) fn transport(&self) -> &IrohTransport {
        &self.inner.transport
    }
}

fn validate_url(url: &Url) -> Result<()> {
    if url.scheme() == "wss" {
        return Ok(());
    }
    if url.scheme() == "ws"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
    {
        return Ok(());
    }
    Err(ClientError::InvalidRendezvousUrl)
}

async fn send_socket<S>(socket: &mut S, frame: &ClientFrame) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    let json =
        serde_json::to_string(frame).map_err(|error| ClientError::Rendezvous(error.to_string()))?;
    socket
        .send(Message::Text(json.into()))
        .await
        .map_err(|error| ClientError::Rendezvous(error.to_string()))
}

fn decode_server(message: Message) -> Result<ServerFrame> {
    let Message::Text(text) = message else {
        return Err(ClientError::Rendezvous(
            "received non-text rendezvous frame".to_owned(),
        ));
    };
    serde_json::from_str(&text).map_err(|error| ClientError::Rendezvous(error.to_string()))
}
