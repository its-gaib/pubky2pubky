//! Consent-first, payload-blind rendezvous service for Hole Punchky.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use hole_punchky_protocol::{
    Accept, Authenticated, ClientFrame, DeviceCertificate, EncryptedSignal, ErrorCode,
    IROH_TRANSPORT, Knock, MAX_CLOCK_SKEW_SECONDS, PROTOCOL_VERSION, Registration, Reject,
    ServerFrame, SignalKind, now_seconds,
};
use serde::Serialize;
use subtle::ConstantTimeEq as _;
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Runtime policy for a rendezvous deployment.
#[derive(Clone)]
pub struct ServerConfig {
    /// Socket bound by [`serve`].
    pub bind: SocketAddr,
    /// How long a pending or accepted rendezvous session remains routable.
    pub session_ttl: Duration,
    /// Maximum complete WebSocket message size.
    pub max_message_bytes: usize,
    /// Maximum signed control-message validity window.
    pub max_auth_window: Duration,
    /// Knock allowance per authenticated identity per rolling minute.
    pub knocks_per_minute: usize,
    /// Maximum simultaneously connected sockets for one identity.
    pub max_connections_per_identity: usize,
    /// Maximum simultaneously connected sockets across all identities.
    pub max_connections: usize,
    /// Maximum registration nonces retained for replay detection.
    pub max_registration_nonces: usize,
    /// Maximum pending and accepted sessions retained in memory.
    pub max_sessions: usize,
    /// Time allowed to send the first registration frame.
    pub registration_timeout: Duration,
    /// Accepted browser Origin values. Empty permits any origin.
    pub allowed_origins: Vec<String>,
    /// Bearer secret required on the iroh relay's internal authorization callout.
    /// Absent disables the internal endpoint.
    pub relay_auth_secret: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            session_ttl: Duration::from_secs(120),
            max_message_bytes: 64 * 1024,
            max_auth_window: Duration::from_secs(120),
            knocks_per_minute: 30,
            max_connections_per_identity: 16,
            max_connections: 10_000,
            max_registration_nonces: 50_000,
            max_sessions: 10_000,
            registration_timeout: Duration::from_secs(10),
            allowed_origins: Vec::new(),
            relay_auth_secret: None,
        }
    }
}

#[derive(Default)]
struct Metrics {
    connections: AtomicU64,
    registrations_total: AtomicU64,
    knocks_total: AtomicU64,
    accepted_total: AtomicU64,
    signals_total: AtomicU64,
    rejected_total: AtomicU64,
    auth_failures_total: AtomicU64,
    rate_limited_total: AtomicU64,
    relay_auth_allowed_total: AtomicU64,
    relay_auth_denied_total: AtomicU64,
}

#[derive(Clone)]
struct Connection {
    identity: String,
    device_id: String,
    certificate: DeviceCertificate,
    iroh_endpoint_id_hex: String,
    sender: mpsc::Sender<ServerFrame>,
}

#[derive(Clone)]
struct Participant {
    connection_id: Uuid,
    identity: String,
    device_id: String,
}

struct Session {
    initiator: Participant,
    target_identity: String,
    target_device_id: Option<String>,
    eligible_responders: HashMap<Uuid, String>,
    responder: Option<Participant>,
    expires_at: u64,
}

#[derive(Default)]
struct Core {
    connections: HashMap<Uuid, Connection>,
    identities: HashMap<String, HashSet<Uuid>>,
    sessions: HashMap<Uuid, Session>,
    session_ids: HashMap<Uuid, u64>,
    registration_nonces: HashMap<(String, String, String), u64>,
    knock_times: HashMap<String, VecDeque<u64>>,
}

/// Shared state used by the Axum application and test harnesses.
#[derive(Clone)]
pub struct ServerState {
    config: Arc<ServerConfig>,
    core: Arc<Mutex<Core>>,
    metrics: Arc<Metrics>,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ServerState {
    /// Create empty state using the supplied policy.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            core: Arc::new(Mutex::new(Core::default())),
            metrics: Arc::new(Metrics::default()),
        }
    }

    async fn prune(&self, now: u64) {
        let mut core = self.core.lock().await;
        core.sessions.retain(|_, session| session.expires_at >= now);
        core.session_ids.retain(|_, expiry| *expiry >= now);
        core.registration_nonces.retain(|_, expiry| *expiry >= now);
        core.knock_times.retain(|_, times| {
            while times.front().is_some_and(|time| *time + 60 < now) {
                times.pop_front();
            }
            !times.is_empty()
        });
    }

    fn enforce_auth_window(&self, issued_at: u64, expires_at: u64) -> ServiceResult<()> {
        if expires_at.saturating_sub(issued_at) > self.config.max_auth_window.as_secs() {
            return Err(ServiceError::unauthorized(
                "signed message window is too long",
            ));
        }
        Ok(())
    }

    async fn register(
        &self,
        frame: Authenticated<Registration>,
        sender: mpsc::Sender<ServerFrame>,
    ) -> ServiceResult<Uuid> {
        let now = now_seconds();
        frame
            .verify(now)
            .map_err(|_| ServiceError::unauthorized("registration authentication failed"))?;
        self.enforce_auth_window(frame.payload.issued_at, frame.payload.expires_at)?;
        if frame.payload.nonce.len() < 16 || frame.payload.nonce.len() > 256 {
            return Err(ServiceError::bad_request(
                "registration nonce has invalid length",
            ));
        }

        let nonce_key = (
            frame.payload.identity.clone(),
            frame.payload.device_id.clone(),
            frame.payload.nonce.clone(),
        );
        let iroh_endpoint_id_hex = frame
            .certificate
            .iroh_endpoint_id_hex()
            .map_err(|_| ServiceError::unauthorized("invalid certified iroh endpoint id"))?;
        let mut core = self.core.lock().await;
        core.registration_nonces.retain(|_, expiry| *expiry >= now);
        if core.registration_nonces.contains_key(&nonce_key) {
            return Err(ServiceError::unauthorized(
                "registration nonce was already used",
            ));
        }
        if core.registration_nonces.len() >= self.config.max_registration_nonces {
            self.metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ServiceError::rate_limited(
                "registration replay cache capacity reached",
            ));
        }
        if core.connections.len() >= self.config.max_connections {
            self.metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ServiceError::rate_limited(
                "server connection capacity reached",
            ));
        }
        let connected = core
            .identities
            .get(&frame.payload.identity)
            .map_or(0, HashSet::len);
        if connected >= self.config.max_connections_per_identity {
            self.metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ServiceError::rate_limited(
                "too many connections for identity",
            ));
        }

        core.registration_nonces.insert(
            nonce_key,
            frame
                .payload
                .expires_at
                .saturating_add(MAX_CLOCK_SKEW_SECONDS),
        );
        let connection_id = Uuid::new_v4();
        let connection = Connection {
            identity: frame.payload.identity.clone(),
            device_id: frame.payload.device_id.clone(),
            certificate: frame.certificate,
            iroh_endpoint_id_hex,
            sender,
        };
        core.connections.insert(connection_id, connection);
        core.identities
            .entry(frame.payload.identity)
            .or_default()
            .insert(connection_id);
        drop(core);

        self.metrics.connections.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .registrations_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(connection_id)
    }

    async fn disconnect(&self, connection_id: Uuid) {
        let mut core = self.core.lock().await;
        let Some(connection) = core.connections.remove(&connection_id) else {
            return;
        };
        let remove_identity = if let Some(ids) = core.identities.get_mut(&connection.identity) {
            ids.remove(&connection_id);
            ids.is_empty()
        } else {
            false
        };
        if remove_identity {
            core.identities.remove(&connection.identity);
        }

        let mut remove_sessions = Vec::new();
        let mut notify_initiators = Vec::new();
        for (session_id, session) in &mut core.sessions {
            if session.initiator.connection_id == connection_id {
                remove_sessions.push(*session_id);
                continue;
            }
            if session
                .responder
                .as_ref()
                .is_some_and(|peer| peer.connection_id == connection_id)
            {
                notify_initiators.push((session.initiator.connection_id, *session_id));
                remove_sessions.push(*session_id);
                continue;
            }
            if session.responder.is_none()
                && session.eligible_responders.remove(&connection_id).is_some()
                && session.eligible_responders.is_empty()
            {
                notify_initiators.push((session.initiator.connection_id, *session_id));
                remove_sessions.push(*session_id);
            }
        }
        for session_id in remove_sessions {
            core.sessions.remove(&session_id);
        }
        let notifications = notify_initiators
            .into_iter()
            .filter_map(|(initiator_id, session_id)| {
                core.connections
                    .get(&initiator_id)
                    .map(|initiator| (initiator.sender.clone(), session_id))
            })
            .collect::<Vec<_>>();
        drop(core);

        for (sender, session_id) in notifications {
            let _ = sender.try_send(
                ServiceError::unavailable("peer disconnected")
                    .with_session(session_id)
                    .frame(),
            );
        }
        self.metrics.connections.fetch_sub(1, Ordering::Relaxed);
    }

    async fn authenticated_connection(
        &self,
        connection_id: Uuid,
        identity: &str,
        device_id: &str,
        certificate: &DeviceCertificate,
    ) -> ServiceResult<()> {
        let core = self.core.lock().await;
        let connection = core
            .connections
            .get(&connection_id)
            .ok_or_else(|| ServiceError::unauthorized("connection is not registered"))?;
        if connection.identity != identity
            || connection.device_id != device_id
            || connection.certificate != *certificate
        {
            return Err(ServiceError::unauthorized(
                "message credential does not match connection",
            ));
        }
        Ok(())
    }

    fn admit_knock(&self, core: &mut Core, knock: &Knock, now: u64) -> ServiceResult<u64> {
        core.sessions.retain(|_, session| session.expires_at >= now);
        core.session_ids.retain(|_, expiry| *expiry >= now);
        if core.session_ids.contains_key(&knock.session_id)
            || core.sessions.contains_key(&knock.session_id)
        {
            return Err(ServiceError::bad_request("session id was already used")
                .with_session(knock.session_id));
        }
        if core.session_ids.len() >= self.config.max_sessions {
            self.metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(
                ServiceError::rate_limited("server session capacity reached")
                    .with_session(knock.session_id),
            );
        }

        let times = core.knock_times.entry(knock.identity.clone()).or_default();
        while times
            .front()
            .is_some_and(|time| time.saturating_add(60) < now)
        {
            times.pop_front();
        }
        if times.len() >= self.config.knocks_per_minute {
            self.metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ServiceError::rate_limited("knock rate exceeded"));
        }
        times.push_back(now);
        let session_expires_at = now.saturating_add(self.config.session_ttl.as_secs());
        let replay_expires_at = knock
            .expires_at
            .saturating_add(MAX_CLOCK_SKEW_SECONDS)
            .max(session_expires_at);
        core.session_ids.insert(knock.session_id, replay_expires_at);
        Ok(session_expires_at)
    }

    async fn knock(&self, connection_id: Uuid, frame: Authenticated<Knock>) -> ServiceResult<()> {
        let now = now_seconds();
        frame
            .verify(now)
            .map_err(|_| ServiceError::unauthorized("knock authentication failed"))?;
        self.enforce_auth_window(frame.payload.issued_at, frame.payload.expires_at)?;
        self.authenticated_connection(
            connection_id,
            &frame.payload.identity,
            &frame.payload.device_id,
            &frame.certificate,
        )
        .await?;
        if frame.payload.application.is_empty() || frame.payload.application.len() > 128 {
            return Err(ServiceError::bad_request("invalid application protocol"));
        }

        let mut core = self.core.lock().await;
        let session_expires_at = self.admit_knock(&mut core, &frame.payload, now)?;

        let targets = core
            .identities
            .get(&frame.payload.target_identity)
            .into_iter()
            .flatten()
            .filter_map(|id| {
                let connection = core.connections.get(id)?;
                if frame
                    .payload
                    .target_device_id
                    .as_ref()
                    .is_none_or(|device| device == &connection.device_id)
                {
                    Some((*id, connection.device_id.clone(), connection.sender.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Err(
                ServiceError::unavailable("target has no matching online device")
                    .with_session(frame.payload.session_id),
            );
        }

        let eligible_responders = targets
            .into_iter()
            .filter_map(|(target_id, device_id, target)| {
                target
                    .try_send(ServerFrame::Knock(frame.clone()))
                    .is_ok()
                    .then_some((target_id, device_id))
            })
            .collect::<HashMap<_, _>>();
        if eligible_responders.is_empty() {
            return Err(
                ServiceError::unavailable("target connections are congested")
                    .with_session(frame.payload.session_id),
            );
        }

        core.sessions.insert(
            frame.payload.session_id,
            Session {
                initiator: Participant {
                    connection_id,
                    identity: frame.payload.identity.clone(),
                    device_id: frame.payload.device_id.clone(),
                },
                target_identity: frame.payload.target_identity.clone(),
                target_device_id: frame.payload.target_device_id.clone(),
                eligible_responders,
                responder: None,
                expires_at: session_expires_at,
            },
        );
        drop(core);
        self.metrics.knocks_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn accept(&self, connection_id: Uuid, frame: Authenticated<Accept>) -> ServiceResult<()> {
        let now = now_seconds();
        frame
            .verify(now)
            .map_err(|_| ServiceError::unauthorized("accept authentication failed"))?;
        self.enforce_auth_window(frame.payload.issued_at, frame.payload.expires_at)?;
        self.authenticated_connection(
            connection_id,
            &frame.payload.identity,
            &frame.payload.device_id,
            &frame.certificate,
        )
        .await?;

        let mut core = self.core.lock().await;
        let initiator_id = {
            let session = core
                .sessions
                .get_mut(&frame.payload.session_id)
                .ok_or_else(|| {
                    ServiceError::session_not_found().with_session(frame.payload.session_id)
                })?;
            if session.expires_at < now {
                return Err(
                    ServiceError::session_not_found().with_session(frame.payload.session_id)
                );
            }
            if session.target_identity != frame.payload.identity
                || session
                    .target_device_id
                    .as_ref()
                    .is_some_and(|device| device != &frame.payload.device_id)
                || session.initiator.identity != frame.payload.target_identity
                || session.eligible_responders.get(&connection_id) != Some(&frame.payload.device_id)
            {
                return Err(ServiceError::unauthorized(
                    "device did not receive this session's knock",
                )
                .with_session(frame.payload.session_id));
            }
            if let Some(responder) = &session.responder {
                if responder.connection_id == connection_id {
                    return Err(ServiceError::bad_request("session was already accepted")
                        .with_session(frame.payload.session_id));
                }
                return Err(ServiceError::session_claimed().with_session(frame.payload.session_id));
            }
            session.responder = Some(Participant {
                connection_id,
                identity: frame.payload.identity.clone(),
                device_id: frame.payload.device_id.clone(),
            });
            session.initiator.connection_id
        };
        let session_id = frame.payload.session_id;
        let sender = core
            .connections
            .get(&initiator_id)
            .map(|connection| connection.sender.clone());
        let delivery = sender
            .ok_or_else(|| {
                ServiceError::unavailable("initiator disconnected").with_session(session_id)
            })
            .and_then(|sender| {
                sender
                    .try_send(ServerFrame::Accepted(frame))
                    .map_err(|_| ServiceError::unavailable("initiator connection is congested"))
            });
        if let Err(error) = delivery {
            if let Some(session) = core.sessions.get_mut(&session_id)
                && session
                    .responder
                    .as_ref()
                    .is_some_and(|responder| responder.connection_id == connection_id)
            {
                session.responder = None;
            }
            return Err(error.with_session(session_id));
        }
        drop(core);
        self.metrics.accepted_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn reject(&self, connection_id: Uuid, frame: Authenticated<Reject>) -> ServiceResult<()> {
        let now = now_seconds();
        frame
            .verify(now)
            .map_err(|_| ServiceError::unauthorized("reject authentication failed"))?;
        self.enforce_auth_window(frame.payload.issued_at, frame.payload.expires_at)?;
        self.authenticated_connection(
            connection_id,
            &frame.payload.identity,
            &frame.payload.device_id,
            &frame.certificate,
        )
        .await?;

        let mut core = self.core.lock().await;
        let (initiator_id, all_rejected) = {
            let session = core
                .sessions
                .get_mut(&frame.payload.session_id)
                .ok_or_else(|| {
                    ServiceError::session_not_found().with_session(frame.payload.session_id)
                })?;
            if session.expires_at < now {
                return Err(
                    ServiceError::session_not_found().with_session(frame.payload.session_id)
                );
            }
            if session.target_identity != frame.payload.identity
                || session
                    .target_device_id
                    .as_ref()
                    .is_some_and(|device| device != &frame.payload.device_id)
                || session.initiator.identity != frame.payload.target_identity
                || session.eligible_responders.get(&connection_id) != Some(&frame.payload.device_id)
            {
                return Err(ServiceError::unauthorized(
                    "device did not receive this session's knock",
                )
                .with_session(frame.payload.session_id));
            }
            if session.responder.is_some() {
                return Err(ServiceError::session_claimed().with_session(frame.payload.session_id));
            }
            session
                .eligible_responders
                .retain(|_, device_id| device_id != &frame.payload.device_id);
            (
                session.initiator.connection_id,
                session.eligible_responders.is_empty(),
            )
        };
        let sender = all_rejected.then(|| {
            core.connections
                .get(&initiator_id)
                .map(|connection| connection.sender.clone())
        });
        if all_rejected {
            core.sessions.remove(&frame.payload.session_id);
        }
        drop(core);
        if let Some(sender) = sender {
            sender
                .ok_or_else(|| {
                    ServiceError::unavailable("initiator disconnected")
                        .with_session(frame.payload.session_id)
                })?
                .try_send(ServerFrame::Rejected(frame))
                .map_err(|_| ServiceError::unavailable("initiator connection is congested"))?;
        }
        self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn signal(&self, connection_id: Uuid, frame: EncryptedSignal) -> ServiceResult<()> {
        let now = now_seconds();
        frame
            .verify(now)
            .map_err(|_| ServiceError::unauthorized("signal authentication failed"))?;
        self.enforce_auth_window(frame.header.issued_at, frame.header.expires_at)?;
        self.authenticated_connection(
            connection_id,
            &frame.header.from_identity,
            &frame.header.from_device_id,
            &frame.certificate,
        )
        .await?;

        let session_id = frame.header.session_id;
        let kind = frame.header.kind;
        let mut core = self.core.lock().await;
        let destination_id = {
            let session = core
                .sessions
                .get(&session_id)
                .ok_or_else(|| ServiceError::session_not_found().with_session(session_id))?;
            if session.expires_at < now {
                return Err(ServiceError::session_not_found().with_session(session_id));
            }
            let responder = session.responder.as_ref().ok_or_else(|| {
                ServiceError::bad_request("session has not been accepted").with_session(session_id)
            })?;

            let (destination, is_initiator) = if session.initiator.connection_id == connection_id {
                (responder, true)
            } else if responder.connection_id == connection_id {
                (&session.initiator, false)
            } else {
                return Err(
                    ServiceError::unauthorized("connection is not bound to session")
                        .with_session(session_id),
                );
            };
            if frame.header.to_identity != destination.identity
                || frame.header.to_device_id != destination.device_id
            {
                return Err(
                    ServiceError::unauthorized("signal recipient is not the bound peer")
                        .with_session(session_id),
                );
            }
            if frame.header.sequence != 0 {
                return Err(
                    ServiceError::bad_request("signal sequence is not the next value")
                        .with_session(session_id),
                );
            }
            match (is_initiator, kind) {
                (false, SignalKind::IrohEndpoint) | (_, SignalKind::Abort) => {}
                _ => {
                    return Err(
                        ServiceError::bad_request("signal violates negotiation order")
                            .with_session(session_id),
                    );
                }
            }
            destination.connection_id
        };
        let sender = core
            .connections
            .get(&destination_id)
            .map(|connection| connection.sender.clone())
            .ok_or_else(|| {
                ServiceError::unavailable("peer disconnected").with_session(session_id)
            })?;
        sender.try_send(ServerFrame::Signal(frame)).map_err(|_| {
            ServiceError::unavailable("peer connection is congested").with_session(session_id)
        })?;
        core.sessions.remove(&session_id);
        drop(core);
        self.metrics.signals_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

type ServiceResult<T> = std::result::Result<T, ServiceError>;

struct ServiceError {
    code: ErrorCode,
    message: &'static str,
    session_id: Option<Uuid>,
}

impl ServiceError {
    const fn bad_request(message: &'static str) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }
    const fn unauthorized(message: &'static str) -> Self {
        Self::new(ErrorCode::Unauthorized, message)
    }
    const fn unavailable(message: &'static str) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }
    const fn session_not_found() -> Self {
        Self::new(ErrorCode::SessionNotFound, "session does not exist")
    }
    const fn session_claimed() -> Self {
        Self::new(ErrorCode::SessionClaimed, "another device already accepted")
    }
    const fn rate_limited(message: &'static str) -> Self {
        Self::new(ErrorCode::RateLimited, message)
    }
    const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            session_id: None,
        }
    }
    const fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }
    fn frame(&self) -> ServerFrame {
        ServerFrame::Error {
            code: self.code,
            message: self.message.to_owned(),
            session_id: self.session_id,
        }
    }
}

/// Construct the HTTP/WebSocket application.
pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v2/config", get(public_config))
        .route("/v2/ws", get(websocket_upgrade))
        .route("/internal/relay/authorize", post(relay_authorize))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
    protocol_version: u16,
}

async fn health() -> Json<Health<'static>> {
    Json(Health {
        status: "ok",
        protocol_version: PROTOCOL_VERSION,
    })
}

#[derive(Serialize)]
struct PublicConfig {
    protocol_version: u16,
    transport: &'static str,
    consent_required: bool,
    relay_access_managed: bool,
    session_ttl_seconds: u64,
    max_message_bytes: usize,
}

async fn public_config(State(state): State<ServerState>) -> Json<PublicConfig> {
    Json(PublicConfig {
        protocol_version: PROTOCOL_VERSION,
        transport: IROH_TRANSPORT,
        consent_required: true,
        relay_access_managed: state.config.relay_auth_secret.is_some(),
        session_ttl_seconds: state.config.session_ttl.as_secs(),
        max_message_bytes: state.config.max_message_bytes,
    })
}

async fn relay_authorize(State(state): State<ServerState>, headers: HeaderMap) -> Response {
    let Some(expected_secret) = state.config.relay_auth_secret.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let supplied_secret = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token);
    let authenticated = supplied_secret.is_some_and(|supplied| {
        supplied.len() == expected_secret.len()
            && bool::from(supplied.as_bytes().ct_eq(expected_secret.as_bytes()))
    });
    // iroh-relay 1.1 sends X-Iroh-NodeId even though its public documentation names
    // X-Iroh-Endpoint-Id. Accept both during the upstream transition, but never accept
    // ambiguous values when a proxy or caller supplies both names.
    let node_id = headers
        .get("x-iroh-nodeid")
        .and_then(|value| value.to_str().ok());
    let documented_id = headers
        .get("x-iroh-endpoint-id")
        .and_then(|value| value.to_str().ok());
    let endpoint_id = match (node_id, documented_id) {
        (Some(node), Some(documented)) if node == documented => Some(node),
        (Some(node), None) => Some(node),
        (None, Some(documented)) => Some(documented),
        _ => None,
    }
    .filter(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    let allowed = if authenticated {
        if let Some(endpoint_id) = endpoint_id {
            state
                .core
                .lock()
                .await
                .connections
                .values()
                .any(|connection| connection.iroh_endpoint_id_hex == endpoint_id)
        } else {
            false
        }
    } else {
        false
    };
    if allowed {
        state
            .metrics
            .relay_auth_allowed_total
            .fetch_add(1, Ordering::Relaxed);
        (StatusCode::OK, "true").into_response()
    } else {
        state
            .metrics
            .relay_auth_denied_total
            .fetch_add(1, Ordering::Relaxed);
        (StatusCode::FORBIDDEN, "false").into_response()
    }
}

async fn metrics(State(state): State<ServerState>) -> Response {
    let sessions = state.core.lock().await.sessions.len();
    let body = format!(
        concat!(
            "# TYPE hole_punchky_connections gauge\n",
            "hole_punchky_connections {}\n",
            "# TYPE hole_punchky_sessions gauge\n",
            "hole_punchky_sessions {}\n",
            "# TYPE hole_punchky_registrations_total counter\n",
            "hole_punchky_registrations_total {}\n",
            "# TYPE hole_punchky_knocks_total counter\n",
            "hole_punchky_knocks_total {}\n",
            "# TYPE hole_punchky_sessions_accepted_total counter\n",
            "hole_punchky_sessions_accepted_total {}\n",
            "# TYPE hole_punchky_signals_relayed_total counter\n",
            "hole_punchky_signals_relayed_total {}\n",
            "# TYPE hole_punchky_rejected_total counter\n",
            "hole_punchky_rejected_total {}\n",
            "# TYPE hole_punchky_auth_failures_total counter\n",
            "hole_punchky_auth_failures_total {}\n",
            "# TYPE hole_punchky_rate_limited_total counter\n",
            "hole_punchky_rate_limited_total {}\n",
            "# TYPE hole_punchky_relay_auth_allowed_total counter\n",
            "hole_punchky_relay_auth_allowed_total {}\n",
            "# TYPE hole_punchky_relay_auth_denied_total counter\n",
            "hole_punchky_relay_auth_denied_total {}\n"
        ),
        state.metrics.connections.load(Ordering::Relaxed),
        sessions,
        state.metrics.registrations_total.load(Ordering::Relaxed),
        state.metrics.knocks_total.load(Ordering::Relaxed),
        state.metrics.accepted_total.load(Ordering::Relaxed),
        state.metrics.signals_total.load(Ordering::Relaxed),
        state.metrics.rejected_total.load(Ordering::Relaxed),
        state.metrics.auth_failures_total.load(Ordering::Relaxed),
        state.metrics.rate_limited_total.load(Ordering::Relaxed),
        state
            .metrics
            .relay_auth_allowed_total
            .load(Ordering::Relaxed),
        state
            .metrics
            .relay_auth_denied_total
            .load(Ordering::Relaxed),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

async fn websocket_upgrade(
    State(state): State<ServerState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !state.config.allowed_origins.is_empty()
        && let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok())
        && !state
            .config
            .allowed_origins
            .iter()
            .any(|item| item == origin)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    upgrade
        .max_message_size(state.config.max_message_bytes)
        .max_frame_size(state.config.max_message_bytes)
        .on_upgrade(move |socket| websocket(socket, state))
}

async fn websocket(mut socket: WebSocket, state: ServerState) {
    let first = tokio::time::timeout(state.config.registration_timeout, socket.recv()).await;
    let registration = match first {
        Ok(Some(Ok(Message::Text(text)))) if text.len() <= state.config.max_message_bytes => {
            match serde_json::from_str::<ClientFrame>(&text) {
                Ok(ClientFrame::Register(frame)) => frame,
                Ok(_) => {
                    send_error_socket(
                        &mut socket,
                        ServiceError::bad_request("first frame must be registration"),
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    send_error_socket(&mut socket, ServiceError::bad_request("invalid JSON")).await;
                    return;
                }
            }
        }
        _ => {
            send_error_socket(
                &mut socket,
                ServiceError::bad_request("registration timed out"),
            )
            .await;
            return;
        }
    };

    let (sender, mut receiver) = mpsc::channel::<ServerFrame>(64);
    let connection_id = match state.register(registration, sender).await {
        Ok(id) => id,
        Err(error) => {
            if error.code == ErrorCode::Unauthorized {
                state
                    .metrics
                    .auth_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            send_error_socket(&mut socket, error).await;
            return;
        }
    };
    let registered = ServerFrame::Registered {
        connection_id,
        session_ttl_seconds: state.config.session_ttl.as_secs(),
        transport: IROH_TRANSPORT.to_owned(),
    };
    if send_frame_socket(&mut socket, &registered).await.is_err() {
        state.disconnect(connection_id).await;
        return;
    }
    debug!(%connection_id, "device registered");

    loop {
        tokio::select! {
            outbound = receiver.recv() => {
                let Some(outbound) = outbound else { break; };
                if send_frame_socket(&mut socket, &outbound).await.is_err() { break; }
            }
            incoming = socket.recv() => {
                let Some(incoming) = incoming else { break; };
                match incoming {
                    Ok(Message::Text(text)) if text.len() <= state.config.max_message_bytes => {
                        match serde_json::from_str::<ClientFrame>(&text) {
                            Ok(frame) => {
                                if let Err(error) = handle_frame(&state, connection_id, frame).await {
                                    if error.code == ErrorCode::Unauthorized {
                                        state.metrics.auth_failures_total.fetch_add(1, Ordering::Relaxed);
                                    }
                                    if send_frame_socket(&mut socket, &error.frame()).await.is_err() { break; }
                                }
                            }
                            Err(_) => {
                                if send_frame_socket(&mut socket, &ServiceError::bad_request("invalid JSON").frame()).await.is_err() { break; }
                            }
                        }
                    }
                    Ok(Message::Text(_) | Message::Binary(_)) => {
                        if send_frame_socket(&mut socket, &ServiceError::bad_request("unsupported or oversized frame").frame()).await.is_err() { break; }
                    }
                    Ok(Message::Ping(data)) => {
                        if socket.send(Message::Pong(data)).await.is_err() { break; }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(_)) | Err(_) => break,
                }
            }
        }
    }
    state.disconnect(connection_id).await;
    debug!(%connection_id, "device disconnected");
}

async fn handle_frame(
    state: &ServerState,
    connection_id: Uuid,
    frame: ClientFrame,
) -> ServiceResult<()> {
    match frame {
        ClientFrame::Register(_) => Err(ServiceError::bad_request(
            "connection is already registered",
        )),
        ClientFrame::Knock(frame) => state.knock(connection_id, frame).await,
        ClientFrame::Accept(frame) => state.accept(connection_id, frame).await,
        ClientFrame::Reject(frame) => state.reject(connection_id, frame).await,
        ClientFrame::Signal(frame) => state.signal(connection_id, frame).await,
        ClientFrame::Ping { nonce } => {
            if nonce.len() > 256 {
                return Err(ServiceError::bad_request("ping nonce is too long"));
            }
            let core = state.core.lock().await;
            let sender = core
                .connections
                .get(&connection_id)
                .map(|connection| connection.sender.clone())
                .ok_or_else(|| ServiceError::unauthorized("connection is not registered"))?;
            drop(core);
            sender
                .try_send(ServerFrame::Pong { nonce })
                .map_err(|_| ServiceError::unavailable("connection is congested"))
        }
    }
}

async fn send_frame_socket(socket: &mut WebSocket, frame: &ServerFrame) -> Result<(), ()> {
    let text = serde_json::to_string(frame).map_err(|_| ())?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

async fn send_error_socket(socket: &mut WebSocket, error: ServiceError) {
    if send_frame_socket(socket, &error.frame()).await.is_err() {
        warn!("failed to send WebSocket error");
    }
}

/// Serve until the supplied shutdown future resolves.
///
/// # Errors
///
/// Returns an I/O error when the listener address cannot be read or Axum stops serving.
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    state: ServerState,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let address = listener.local_addr()?;
    info!(%address, "Hole Punchky rendezvous listening");
    let maintenance_state = state.clone();
    let _maintenance = AbortOnDrop(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            maintenance_state.prune(now_seconds()).await;
        }
    }));
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
}

/// Bind the configured address and serve until Ctrl-C/SIGTERM.
///
/// # Errors
///
/// Returns an error when the socket cannot be bound or the HTTP server fails.
pub async fn serve(config: ServerConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    serve_with_shutdown(listener, ServerState::new(config), shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            warn!("could not install Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// Spawn an ephemeral loopback server for integration tests and embedders.
///
/// # Errors
///
/// Returns an I/O error if a loopback listener cannot be bound or queried.
pub async fn spawn_ephemeral(
    mut config: ServerConfig,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    config.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = TcpListener::bind(config.bind).await?;
    let address = listener.local_addr()?;
    let state = ServerState::new(config);
    let handle = tokio::spawn(async move {
        if let Err(error) = serve_with_shutdown(listener, state, std::future::pending()).await {
            warn!(%error, "ephemeral rendezvous stopped");
        }
    });
    Ok((address, handle))
}

#[cfg(test)]
mod tests {
    use hole_punchky_protocol::{DeviceCredential, PROTOCOL_VERSION};
    use pubky::Keypair;

    use super::*;

    fn credential(root: &Keypair, device_id: &str, now: u64) -> DeviceCredential {
        DeviceCredential::issue(root, device_id, now.saturating_sub(10), now + 3_600)
            .unwrap_or_else(|error| panic!("issuing credential: {error}"))
    }

    fn registration(
        credential: &DeviceCredential,
        nonce: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Authenticated<Registration> {
        Authenticated::sign(
            Registration {
                version: PROTOCOL_VERSION,
                identity: credential.identity().to_owned(),
                device_id: credential.device_id().to_owned(),
                nonce: nonce.to_owned(),
                issued_at,
                expires_at,
            },
            credential,
        )
        .unwrap_or_else(|error| panic!("signing registration: {error}"))
    }

    #[tokio::test]
    async fn registration_replay_cache_covers_clock_skew_window() {
        let now = now_seconds();
        let device = credential(&Keypair::random(), "device", now);
        let frame = registration(
            &device,
            "replay-window-nonce",
            now.saturating_sub(2),
            now.saturating_sub(1),
        );
        let state = ServerState::new(ServerConfig::default());
        let (sender, _receiver) = mpsc::channel(1);
        let connection_id = state
            .register(frame.clone(), sender)
            .await
            .unwrap_or_else(|error| panic!("first registration failed: {}", error.message));
        state.disconnect(connection_id).await;
        state.prune(now).await;

        let (sender, _receiver) = mpsc::channel(1);
        let Err(error) = state.register(frame, sender).await else {
            panic!("replayed registration was accepted");
        };
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    #[tokio::test]
    async fn session_id_tombstone_survives_active_session_cleanup() {
        let now = now_seconds();
        let alice = credential(&Keypair::random(), "alice", now);
        let bob = credential(&Keypair::random(), "bob", now);
        let state = ServerState::new(ServerConfig::default());
        let (alice_sender, _alice_receiver) = mpsc::channel(4);
        let alice_connection = state
            .register(
                registration(&alice, "alice-registration", now, now + 30),
                alice_sender,
            )
            .await
            .unwrap_or_else(|error| panic!("registering Alice: {}", error.message));
        let (bob_sender, _bob_receiver) = mpsc::channel(4);
        state
            .register(
                registration(&bob, "bob-registration-00", now, now + 30),
                bob_sender,
            )
            .await
            .unwrap_or_else(|error| panic!("registering Bob: {}", error.message));

        let session_id = Uuid::new_v4();
        let knock = Authenticated::sign(
            Knock {
                version: PROTOCOL_VERSION,
                identity: alice.identity().to_owned(),
                device_id: alice.device_id().to_owned(),
                session_id,
                target_identity: bob.identity().to_owned(),
                target_device_id: None,
                application: "replay-test/1".to_owned(),
                metadata: None,
                issued_at: now.saturating_sub(2),
                expires_at: now.saturating_sub(1),
            },
            &alice,
        )
        .unwrap_or_else(|error| panic!("signing knock: {error}"));
        state
            .knock(alice_connection, knock.clone())
            .await
            .unwrap_or_else(|error| panic!("first knock failed: {}", error.message));
        let _ = state.core.lock().await.sessions.remove(&session_id);
        state.prune(now).await;

        let Err(error) = state.knock(alice_connection, knock).await else {
            panic!("replayed knock was accepted");
        };
        assert_eq!(error.code, ErrorCode::BadRequest);
    }
}
