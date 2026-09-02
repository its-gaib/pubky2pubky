use std::{net::IpAddr, sync::Arc, time::Duration};

use futures_util::{SinkExt as _, StreamExt as _};
use hole_punchky_protocol::{
    Authenticated, ClientFrame, DeviceCredential, IceServer, Knock, PROTOCOL_VERSION, Registration,
    Reject, ServerFrame, TurnCredentials, TurnRequest, now_seconds,
};
use tokio::{
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::{ClientError, DescriptorResolver, Result};

/// Connection and negotiation policy for a rendezvous client.
#[derive(Debug, Clone)]
pub struct RendezvousClientConfig {
    /// Timeout for the WebSocket handshake and signed registration.
    pub connect_timeout: Duration,
    /// Overall WebRTC negotiation timeout.
    pub negotiation_timeout: Duration,
    /// Application heartbeat interval used to keep the outbound NAT mapping alive.
    /// Must be non-zero.
    pub heartbeat_interval: Duration,
    /// Maximum time to gather each side's ICE candidates.
    pub ice_gather_timeout: Duration,
    /// Local UDP bind addresses used by WebRTC.
    pub udp_bind_addresses: Vec<String>,
    /// Data-channel label.
    pub data_channel_label: String,
    /// Per-channel outstanding send-byte limit.
    pub send_buffer_limit: usize,
    /// Try to obtain TURN credentials after peer consent.
    pub request_turn: bool,
}

impl Default for RendezvousClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            negotiation_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(25),
            ice_gather_timeout: Duration::from_secs(10),
            udp_bind_addresses: vec!["0.0.0.0:0".to_owned()],
            data_channel_label: "hole-punchky".to_owned(),
            send_buffer_limit: 1024 * 1024,
            request_turn: true,
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
    ice_servers: Vec<IceServer>,
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
        let (connection_id, ice_servers) = match frame {
            ServerFrame::Registered {
                connection_id,
                ice_servers,
                ..
            } => (connection_id, ice_servers),
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
            _ => {
                return Err(ClientError::Rendezvous(
                    "expected registration response".to_owned(),
                ));
            }
        };

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
                ice_servers,
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

    pub(crate) fn public_ice_servers(&self) -> &[IceServer] {
        &self.inner.ice_servers
    }

    pub(crate) async fn request_turn(
        &self,
        session_id: Uuid,
        events: &mut broadcast::Receiver<WireEvent>,
    ) -> Result<Option<TurnCredentials>> {
        let now = now_seconds();
        let request = Authenticated::sign(
            TurnRequest {
                version: PROTOCOL_VERSION,
                identity: self.inner.credential.identity().to_owned(),
                device_id: self.inner.credential.device_id().to_owned(),
                session_id,
                issued_at: now,
                expires_at: now + 30,
            },
            &self.inner.credential,
        )?;
        self.send(ClientFrame::RequestTurnCredentials(request))
            .await?;
        loop {
            match events.recv().await {
                Ok(WireEvent::Frame(frame)) => match *frame {
                    ServerFrame::TurnCredentials(credentials)
                        if credentials.session_id == session_id =>
                    {
                        return Ok(Some(credentials));
                    }
                    ServerFrame::Error {
                        code: hole_punchky_protocol::ErrorCode::TurnUnavailable,
                        session_id: Some(id),
                        ..
                    } if id == session_id => return Ok(None),
                    ServerFrame::Error {
                        code,
                        message,
                        session_id: related,
                    } if related == Some(session_id) => {
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
