use std::{sync::Arc, time::Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use hole_punchky_protocol::{
    Accept, Authenticated, ClientFrame, DeviceCertificate, EncryptedSignal, Knock,
    PROTOCOL_VERSION, ServerFrame, SignalPayload, TurnCredentials, now_seconds,
};
use serde_json::Value;
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, warn};
use uuid::Uuid;
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent},
    peer_connection::{
        MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
        RTCConfigurationBuilder, RTCIceCandidateType, RTCIceGatheringState, RTCIceServer,
        RTCIceTransportPolicy, RTCPeerConnectionIceEvent, RTCPeerConnectionState,
        RTCSessionDescription, RTCStatsReportEntry, Registry, StatsSelector,
        register_default_interceptors,
    },
    runtime::{Runtime, default_runtime},
};

use crate::{ClientError, IncomingKnock, RendezvousClient, Result, signaling::WireEvent};

/// Candidate policy used while establishing a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IcePolicy {
    /// Prefer direct host/server-reflexive candidates and fall back to TURN.
    #[default]
    DirectWithRelayFallback,
    /// Gather only TURN relay candidates, hiding direct addresses from the peer.
    RelayOnly,
}

/// Parameters sent in a consent-first knock.
#[derive(Debug, Clone)]
pub struct DialOptions {
    /// Application protocol expected on the resulting data channel.
    pub application: String,
    /// Route only to this device id instead of fanning out to all online devices.
    pub target_device_id: Option<String>,
    /// Non-secret application hint shown before consent.
    pub metadata: Option<Value>,
    /// ICE candidate policy.
    pub ice_policy: IcePolicy,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            application: "hole-punchky/raw/1".to_owned(),
            target_device_id: None,
            metadata: None,
            ice_policy: IcePolicy::DirectWithRelayFallback,
        }
    }
}

/// Actual network path selected by ICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    /// The local candidate in the selected pair does not use TURN.
    Direct,
    /// The local candidate in the selected pair uses TURN.
    Relayed,
    /// Stats have not exposed the selected local candidate yet.
    Unknown,
}

/// An authenticated WebRTC `DataChannel` connected to a known Pubky identity.
pub struct Peer {
    connection: Arc<dyn PeerConnection>,
    data_channel: Arc<dyn DataChannel>,
    messages: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    event_task: JoinHandle<()>,
    session_id: Uuid,
    remote_identity: String,
    remote_device_id: String,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Peer")
            .field("session_id", &self.session_id)
            .field("peer_identity", &self.remote_identity)
            .field("peer_device_id", &self.remote_device_id)
            .finish_non_exhaustive()
    }
}

impl Peer {
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

    /// Send one binary `DataChannel` message.
    ///
    /// # Errors
    ///
    /// Returns an error when the message exceeds 16 KiB or the channel cannot send it.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > 16 * 1024 {
            return Err(ClientError::WebRtc(
                "message exceeds the portable 16 KiB DataChannel limit".to_owned(),
            ));
        }
        self.data_channel
            .send(BytesMut::from(data))
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))
    }

    /// Send one UTF-8 `DataChannel` message.
    ///
    /// # Errors
    ///
    /// Returns an error when the message exceeds 16 KiB or the channel cannot send it.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        if text.len() > 16 * 1024 {
            return Err(ClientError::WebRtc(
                "message exceeds the portable 16 KiB DataChannel limit".to_owned(),
            ));
        }
        self.data_channel
            .send_text(text)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))
    }

    /// Receive one complete binary `DataChannel` message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ChannelClosed`] when no further message can arrive.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        self.messages
            .lock()
            .await
            .recv()
            .await
            .ok_or(ClientError::ChannelClosed)
    }

    /// Inspect the local candidate in the currently nominated ICE pair.
    pub async fn path(&self) -> ConnectionPath {
        let report = self
            .connection
            .get_stats(Instant::now(), StatsSelector::None)
            .await;
        if let Some(pair) = report.candidate_pairs().find(|pair| pair.nominated) {
            // rtc-rs 0.20 records a raw local candidate id on the pair, while
            // the corresponding report entry uses a W3C local prefix.
            // Try both forms so this also remains compatible if rtc-rs fixes
            // the cross-reference in a later release.
            let local = report
                .get(&pair.local_candidate_id)
                .or_else(|| {
                    report.get(&format!("RTCLocalIceCandidate_{}", pair.local_candidate_id))
                })
                .and_then(|entry| match entry {
                    RTCStatsReportEntry::LocalCandidate(candidate) => {
                        Some(candidate.candidate_type)
                    }
                    _ => None,
                });
            return match local {
                Some(RTCIceCandidateType::Relay) => ConnectionPath::Relayed,
                Some(_) => ConnectionPath::Direct,
                None => ConnectionPath::Unknown,
            };
        }
        ConnectionPath::Unknown
    }

    /// Gracefully close SCTP, DTLS, and ICE.
    ///
    /// # Errors
    ///
    /// Returns an error when either the data channel or peer connection cannot close cleanly.
    pub async fn close(&self) -> Result<()> {
        let channel_result = self.data_channel.close().await;
        let peer_result = self.connection.close().await;
        channel_result
            .and(peer_result)
            .map_err(|error| ClientError::WebRtc(error.to_string()))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.event_task.abort();
    }
}

struct WebRtcHandler {
    gather_complete: mpsc::Sender<()>,
    remote_data_channel: mpsc::Sender<Arc<dyn DataChannel>>,
}

#[async_trait]
impl PeerConnectionEventHandler for WebRtcHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        debug!(
            candidate_type = ?event.candidate.typ,
            "gathered ICE candidate"
        );
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather_complete.try_send(());
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        debug!(?state, "WebRTC connection state changed");
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let _ = self.remote_data_channel.send(channel).await;
    }
}

struct BuiltPeerConnection {
    connection: Arc<dyn PeerConnection>,
    gather_complete: mpsc::Receiver<()>,
    remote_data_channel: mpsc::Receiver<Arc<dyn DataChannel>>,
}

impl RendezvousClient {
    /// Knock a Pubky identity, obtain consent, and establish a WebRTC `DataChannel`.
    ///
    /// # Errors
    ///
    /// Returns an error on discovery-independent rendezvous rejection, authentication failure,
    /// signaling failure, ICE/WebRTC failure, or negotiation timeout.
    pub async fn dial(&self, target_identity: &str, options: DialOptions) -> Result<Peer> {
        let timeout = self.config().negotiation_timeout;
        tokio::time::timeout(timeout, Box::pin(self.dial_inner(target_identity, options)))
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
                application: options.application,
                metadata: options.metadata,
                issued_at: now,
                expires_at: now + 30,
            },
            self.credential(),
        )?;
        self.send(ClientFrame::Knock(knock)).await?;

        let accepted = wait_for_accept(&mut events, session_id).await?;
        accepted.verify(now_seconds())?;
        if accepted.payload.session_id != session_id
            || accepted.payload.identity != target_identity
            || accepted.payload.target_identity != self.credential().identity()
            || options
                .target_device_id
                .as_ref()
                .is_some_and(|device| device != &accepted.payload.device_id)
        {
            return Err(ClientError::UnexpectedPeer);
        }

        let turn = self
            .turn_for_session(session_id, options.ice_policy, &mut events)
            .await?;
        let mut built = Box::pin(build_peer_connection(
            self,
            options.ice_policy,
            turn.as_ref(),
        ))
        .await?;
        let channel = built
            .connection
            .create_data_channel(&self.config().data_channel_label, None)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        let (open, messages, event_task) = activate_data_channel(Arc::clone(&channel));

        let offer = built
            .connection
            .create_offer(None)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        built
            .connection
            .set_local_description(offer)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        wait_for_gathering(self, &mut built.gather_complete).await?;
        let offer = built
            .connection
            .local_description()
            .await
            .ok_or_else(|| ClientError::WebRtc("local offer is unavailable".to_owned()))?;
        let signal = seal_description(self, &accepted.certificate, session_id, 0, offer)?;
        self.send(ClientFrame::Signal(signal)).await?;

        let answer = wait_for_description(
            self,
            &mut events,
            session_id,
            &accepted.certificate,
            "answer",
        )
        .await?;
        built
            .connection
            .set_remote_description(answer)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        open.await.map_err(|_| ClientError::ChannelClosed)??;

        Ok(Peer {
            connection: built.connection,
            data_channel: channel,
            messages: tokio::sync::Mutex::new(messages),
            event_task,
            session_id,
            remote_identity: accepted.payload.identity,
            remote_device_id: accepted.payload.device_id,
        })
    }

    /// Accept a previously returned [`IncomingKnock`] and establish its `DataChannel`.
    ///
    /// # Errors
    ///
    /// Returns an error on an invalid knock, rendezvous/signaling failure, ICE/WebRTC failure,
    /// missing TURN service under relay-only policy, or negotiation timeout.
    pub async fn accept(&self, incoming: IncomingKnock, ice_policy: IcePolicy) -> Result<Peer> {
        let timeout = self.config().negotiation_timeout;
        tokio::time::timeout(timeout, Box::pin(self.accept_inner(incoming, ice_policy)))
            .await
            .map_err(|_| ClientError::Timeout("negotiating inbound peer connection"))?
    }

    async fn accept_inner(&self, incoming: IncomingKnock, ice_policy: IcePolicy) -> Result<Peer> {
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
        let mut events = self.subscribe();
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

        let turn = self
            .turn_for_session(knock.session_id, ice_policy, &mut events)
            .await?;
        let mut built = Box::pin(build_peer_connection(self, ice_policy, turn.as_ref())).await?;
        let offer = wait_for_description(
            self,
            &mut events,
            knock.session_id,
            &incoming.signed.certificate,
            "offer",
        )
        .await?;
        built
            .connection
            .set_remote_description(offer)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        let answer = built
            .connection
            .create_answer(None)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        built
            .connection
            .set_local_description(answer)
            .await
            .map_err(|error| ClientError::WebRtc(error.to_string()))?;
        wait_for_gathering(self, &mut built.gather_complete).await?;
        let answer = built
            .connection
            .local_description()
            .await
            .ok_or_else(|| ClientError::WebRtc("local answer is unavailable".to_owned()))?;
        let signal = seal_description(
            self,
            &incoming.signed.certificate,
            knock.session_id,
            0,
            answer,
        )?;
        self.send(ClientFrame::Signal(signal)).await?;

        let channel = built.remote_data_channel.recv().await.ok_or_else(|| {
            ClientError::WebRtc("remote did not create a data channel".to_owned())
        })?;
        let (open, messages, event_task) = activate_data_channel(Arc::clone(&channel));
        open.await.map_err(|_| ClientError::ChannelClosed)??;
        Ok(Peer {
            connection: built.connection,
            data_channel: channel,
            messages: tokio::sync::Mutex::new(messages),
            event_task,
            session_id: knock.session_id,
            remote_identity: knock.identity.clone(),
            remote_device_id: knock.device_id.clone(),
        })
    }

    async fn turn_for_session(
        &self,
        session_id: Uuid,
        ice_policy: IcePolicy,
        events: &mut broadcast::Receiver<WireEvent>,
    ) -> Result<Option<TurnCredentials>> {
        if !self.config().request_turn && ice_policy != IcePolicy::RelayOnly {
            return Ok(None);
        }
        let credentials = self.request_turn(session_id, events).await?;
        if ice_policy == IcePolicy::RelayOnly && credentials.is_none() {
            return Err(ClientError::WebRtc(
                "relay-only policy requires configured TURN credentials".to_owned(),
            ));
        }
        Ok(credentials)
    }
}

async fn build_peer_connection(
    client: &RendezvousClient,
    policy: IcePolicy,
    turn: Option<&TurnCredentials>,
) -> Result<BuiltPeerConnection> {
    let mut ice_servers = client
        .public_ice_servers()
        .iter()
        .map(|server| RTCIceServer {
            urls: server.urls.clone(),
            username: server.username.clone().unwrap_or_default(),
            credential: server.credential.clone().unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    if let Some(turn) = turn {
        ice_servers.push(RTCIceServer {
            urls: turn.urls.clone(),
            username: turn.username.clone(),
            credential: turn.credential.clone(),
        });
    }
    let transport_policy = match policy {
        IcePolicy::DirectWithRelayFallback => RTCIceTransportPolicy::All,
        IcePolicy::RelayOnly => RTCIceTransportPolicy::Relay,
    };
    let configuration = RTCConfigurationBuilder::new()
        .with_ice_servers(ice_servers)
        .with_ice_transport_policy(transport_policy)
        .build();

    let mut media = MediaEngine::default();
    media
        .register_default_codecs()
        .map_err(|error| ClientError::WebRtc(error.to_string()))?;
    let registry = register_default_interceptors(Registry::new(), &mut media)
        .map_err(|error| ClientError::WebRtc(error.to_string()))?;
    let runtime: Arc<dyn Runtime> = default_runtime()
        .ok_or_else(|| ClientError::WebRtc("Tokio WebRTC runtime is unavailable".to_owned()))?;
    let (gather_tx, gather_complete) = mpsc::channel(1);
    let (data_tx, remote_data_channel) = mpsc::channel(1);
    let handler = Arc::new(WebRtcHandler {
        gather_complete: gather_tx,
        remote_data_channel: data_tx,
    });
    let connection = Box::pin(
        PeerConnectionBuilder::new()
            .with_configuration(configuration)
            .with_media_engine(media)
            .with_interceptor_registry(registry)
            .with_handler(handler)
            .with_runtime(runtime)
            .with_udp_addrs(client.config().udp_bind_addresses.clone())
            .with_data_channel_send_buffer_limit(client.config().send_buffer_limit)
            .build(),
    )
    .await
    .map_err(|error| ClientError::WebRtc(error.to_string()))?;
    Ok(BuiltPeerConnection {
        connection: Arc::new(connection),
        gather_complete,
        remote_data_channel,
    })
}

async fn wait_for_gathering(
    client: &RendezvousClient,
    complete: &mut mpsc::Receiver<()>,
) -> Result<()> {
    tokio::time::timeout(client.config().ice_gather_timeout, complete.recv())
        .await
        .map_err(|_| ClientError::Timeout("gathering ICE candidates"))?
        .ok_or_else(|| ClientError::WebRtc("ICE gatherer stopped".to_owned()))
}

fn seal_description(
    client: &RendezvousClient,
    recipient: &DeviceCertificate,
    session_id: Uuid,
    sequence: u64,
    description: RTCSessionDescription,
) -> Result<EncryptedSignal> {
    let now = now_seconds();
    EncryptedSignal::seal(
        client.credential(),
        recipient,
        session_id,
        sequence,
        &SignalPayload::SessionDescription {
            sdp_type: description.sdp_type.to_string(),
            sdp: description.sdp,
        },
        now,
        now + 30,
    )
    .map_err(Into::into)
}

async fn wait_for_accept(
    events: &mut broadcast::Receiver<WireEvent>,
    session_id: Uuid,
) -> Result<Authenticated<Accept>> {
    loop {
        match events.recv().await {
            Ok(WireEvent::Frame(frame)) => match *frame {
                ServerFrame::Accepted(accepted) if accepted.payload.session_id == session_id => {
                    return Ok(accepted);
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

async fn wait_for_description(
    client: &RendezvousClient,
    events: &mut broadcast::Receiver<WireEvent>,
    session_id: Uuid,
    expected_sender: &DeviceCertificate,
    expected_type: &'static str,
) -> Result<RTCSessionDescription> {
    loop {
        match events.recv().await {
            Ok(WireEvent::Frame(frame)) => match *frame {
                ServerFrame::Signal(signal) if signal.header.session_id == session_id => {
                    if signal.certificate != *expected_sender {
                        return Err(ClientError::UnexpectedPeer);
                    }
                    let payload = signal.open(client.credential(), now_seconds())?;
                    let SignalPayload::SessionDescription { sdp_type, sdp } = payload else {
                        continue;
                    };
                    if sdp_type != expected_type {
                        return Err(ClientError::UnexpectedPeer);
                    }
                    let description = if expected_type == "offer" {
                        RTCSessionDescription::offer(sdp)
                    } else if expected_type == "answer" {
                        RTCSessionDescription::answer(sdp)
                    } else {
                        return Err(ClientError::WebRtc(
                            "unsupported session-description type".to_owned(),
                        ));
                    };
                    return description.map_err(|error| ClientError::WebRtc(error.to_string()));
                }
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

fn activate_data_channel(
    channel: Arc<dyn DataChannel>,
) -> (
    oneshot::Receiver<Result<()>>,
    mpsc::Receiver<Vec<u8>>,
    JoinHandle<()>,
) {
    let (open_tx, open_rx) = oneshot::channel();
    let (message_tx, message_rx) = mpsc::channel(128);
    let task = tokio::spawn(async move {
        let mut open_tx = Some(open_tx);
        while let Some(event) = channel.poll().await {
            match event {
                DataChannelEvent::OnOpen => {
                    if let Some(sender) = open_tx.take() {
                        let _ = sender.send(Ok(()));
                    }
                }
                DataChannelEvent::OnMessage(message) => {
                    if message_tx.send(message.data.to_vec()).await.is_err() {
                        break;
                    }
                }
                DataChannelEvent::OnError => {
                    if let Some(sender) = open_tx.take() {
                        let _ = sender.send(Err(ClientError::WebRtc(
                            "data channel reported an error".to_owned(),
                        )));
                    }
                    warn!("data channel reported an error");
                }
                DataChannelEvent::OnClose => break,
                DataChannelEvent::OnClosing
                | DataChannelEvent::OnBufferedAmountLow
                | DataChannelEvent::OnBufferedAmountHigh => {}
            }
        }
        if let Some(sender) = open_tx {
            let _ = sender.send(Err(ClientError::ChannelClosed));
        }
    });
    (open_rx, message_rx, task)
}
