//! End-to-end WebSocket tests for rendezvous authentication and routing.

use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use hole_punchky_protocol::{
    Accept, Authenticated, ClientFrame, DeviceCredential, EncryptedSignal, ErrorCode, Knock,
    PROTOCOL_VERSION, Registration, Reject, ServerFrame, SignalPayload, TurnRequest, now_seconds,
};
use hole_punchky_rendezvous::{ServerConfig, spawn_ephemeral};
use pubky::Keypair;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{self, Message},
};
use uuid::Uuid;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn credential(root: &Keypair, device: &str) -> DeviceCredential {
    let now = now_seconds();
    DeviceCredential::issue(root, device, now.saturating_sub(1), now + 3_600)
        .unwrap_or_else(|error| panic!("issuing device credential: {error}"))
}

fn registration(credential: &DeviceCredential, nonce: String) -> ClientFrame {
    let now = now_seconds();
    let payload = Registration {
        version: PROTOCOL_VERSION,
        identity: credential.identity().to_owned(),
        device_id: credential.device_id().to_owned(),
        nonce,
        issued_at: now,
        expires_at: now + 30,
    };
    ClientFrame::Register(
        Authenticated::sign(payload, credential)
            .unwrap_or_else(|error| panic!("signing registration: {error}")),
    )
}

async fn send(socket: &mut Socket, frame: &ClientFrame) {
    let json = serde_json::to_string(frame)
        .unwrap_or_else(|error| panic!("serializing client frame: {error}"));
    socket
        .send(Message::Text(json.into()))
        .await
        .unwrap_or_else(|error| panic!("sending client frame: {error}"));
}

async fn receive(socket: &mut Socket) -> ServerFrame {
    let item = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for server frame"))
        .unwrap_or_else(|| panic!("WebSocket ended"))
        .unwrap_or_else(|error| panic!("receiving server frame: {error}"));
    let Message::Text(text) = item else {
        panic!("unexpected non-text server frame");
    };
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("decoding server frame: {error}: {text}"))
}

async fn connect_registered(
    address: std::net::SocketAddr,
    credential: &DeviceCredential,
) -> Socket {
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/ws"))
        .await
        .unwrap_or_else(|error| panic!("connecting WebSocket: {error}"));
    send(
        &mut socket,
        &registration(credential, Uuid::new_v4().to_string()),
    )
    .await;
    assert!(matches!(
        receive(&mut socket).await,
        ServerFrame::Registered { .. }
    ));
    socket
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one chronological protocol transcript"
)]
async fn fans_out_binds_first_responder_and_relays_encrypted_signals() {
    let config = ServerConfig {
        stun_urls: Vec::new(),
        turn_urls: vec!["turn:127.0.0.1:3478?transport=udp".to_owned()],
        turn_shared_secret: Some("integration-test-secret".to_owned()),
        ..ServerConfig::default()
    };
    let (address, server) = spawn_ephemeral(config)
        .await
        .unwrap_or_else(|error| panic!("starting server: {error}"));

    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let alice = credential(&alice_root, "alice-phone");
    let bob_laptop = credential(&bob_root, "bob-laptop");
    let bob_phone = credential(&bob_root, "bob-phone");
    let mut alice_socket = connect_registered(address, &alice).await;
    let mut laptop_socket = connect_registered(address, &bob_laptop).await;
    let mut phone_socket = connect_registered(address, &bob_phone).await;

    let session_id = Uuid::new_v4();
    let now = now_seconds();
    let knock = Authenticated::sign(
        Knock {
            version: PROTOCOL_VERSION,
            identity: alice.identity().to_owned(),
            device_id: alice.device_id().to_owned(),
            session_id,
            target_identity: bob_laptop.identity().to_owned(),
            target_device_id: None,
            application: "hole-punchky-test/1".to_owned(),
            metadata: Some(serde_json::json!({"label": "test"})),
            issued_at: now,
            expires_at: now + 30,
        },
        &alice,
    )
    .unwrap_or_else(|error| panic!("signing knock: {error}"));
    send(&mut alice_socket, &ClientFrame::Knock(knock.clone())).await;
    assert_eq!(
        receive(&mut laptop_socket).await,
        ServerFrame::Knock(knock.clone())
    );
    assert_eq!(receive(&mut phone_socket).await, ServerFrame::Knock(knock));

    let accepted = Authenticated::sign(
        Accept {
            version: PROTOCOL_VERSION,
            identity: bob_laptop.identity().to_owned(),
            device_id: bob_laptop.device_id().to_owned(),
            session_id,
            target_identity: alice.identity().to_owned(),
            issued_at: now_seconds(),
            expires_at: now_seconds() + 30,
        },
        &bob_laptop,
    )
    .unwrap_or_else(|error| panic!("signing accept: {error}"));
    send(&mut laptop_socket, &ClientFrame::Accept(accepted.clone())).await;
    assert_eq!(
        receive(&mut alice_socket).await,
        ServerFrame::Accepted(accepted)
    );

    let losing_accept = Authenticated::sign(
        Accept {
            version: PROTOCOL_VERSION,
            identity: bob_phone.identity().to_owned(),
            device_id: bob_phone.device_id().to_owned(),
            session_id,
            target_identity: alice.identity().to_owned(),
            issued_at: now_seconds(),
            expires_at: now_seconds() + 30,
        },
        &bob_phone,
    )
    .unwrap_or_else(|error| panic!("signing second accept: {error}"));
    send(&mut phone_socket, &ClientFrame::Accept(losing_accept)).await;
    assert!(matches!(
        receive(&mut phone_socket).await,
        ServerFrame::Error {
            code: ErrorCode::SessionClaimed,
            session_id: Some(id),
            ..
        } if id == session_id
    ));

    let offer_payload = SignalPayload::SessionDescription {
        sdp_type: "offer".to_owned(),
        sdp: "v=0\r\na=opaque-test-offer\r\n".to_owned(),
    };
    let offer = EncryptedSignal::seal(
        &alice,
        &bob_laptop.certificate,
        session_id,
        0,
        &offer_payload,
        now_seconds(),
        now_seconds() + 30,
    )
    .unwrap_or_else(|error| panic!("sealing offer: {error}"));
    send(&mut alice_socket, &ClientFrame::Signal(offer.clone())).await;
    let ServerFrame::Signal(received) = receive(&mut laptop_socket).await else {
        panic!("expected relayed offer");
    };
    assert_eq!(
        received
            .open(&bob_laptop, now_seconds())
            .unwrap_or_else(|error| panic!("opening offer: {error}")),
        offer_payload
    );

    // The same authenticated ciphertext cannot be replayed: its sequence has been consumed.
    send(&mut alice_socket, &ClientFrame::Signal(offer)).await;
    assert!(matches!(
        receive(&mut alice_socket).await,
        ServerFrame::Error {
            code: ErrorCode::BadRequest,
            session_id: Some(id),
            ..
        } if id == session_id
    ));

    let turn = Authenticated::sign(
        TurnRequest {
            version: PROTOCOL_VERSION,
            identity: alice.identity().to_owned(),
            device_id: alice.device_id().to_owned(),
            session_id,
            issued_at: now_seconds(),
            expires_at: now_seconds() + 30,
        },
        &alice,
    )
    .unwrap_or_else(|error| panic!("signing TURN request: {error}"));
    send(
        &mut alice_socket,
        &ClientFrame::RequestTurnCredentials(turn),
    )
    .await;
    let ServerFrame::TurnCredentials(turn) = receive(&mut alice_socket).await else {
        panic!("expected TURN credentials");
    };
    assert!(turn.username.contains(alice.identity()));
    assert!(!turn.credential.is_empty());
    assert!(turn.expires_at > now_seconds());

    let health: serde_json::Value = reqwest::get(format!("http://{address}/healthz"))
        .await
        .unwrap_or_else(|error| panic!("health request: {error}"))
        .json()
        .await
        .unwrap_or_else(|error| panic!("health JSON: {error}"));
    assert_eq!(health["status"], "ok");
    let metrics = reqwest::get(format!("http://{address}/metrics"))
        .await
        .unwrap_or_else(|error| panic!("metrics request: {error}"))
        .text()
        .await
        .unwrap_or_else(|error| panic!("metrics body: {error}"));
    assert!(metrics.contains("hole_punchky_signals_relayed_total 1"));

    server.abort();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one chronological multi-device protocol transcript"
)]
async fn fanout_waits_for_every_device_rejection_and_excludes_late_connections() {
    let (address, server) = spawn_ephemeral(ServerConfig::default())
        .await
        .unwrap_or_else(|error| panic!("starting server: {error}"));

    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let alice = credential(&alice_root, "alice-phone");
    let bob_laptop = credential(&bob_root, "bob-laptop");
    let bob_phone = credential(&bob_root, "bob-phone");
    let bob_late = credential(&bob_root, "bob-late");
    let mut alice_socket = connect_registered(address, &alice).await;
    let mut laptop_socket = connect_registered(address, &bob_laptop).await;
    let mut phone_socket = connect_registered(address, &bob_phone).await;

    let session_id = Uuid::new_v4();
    let now = now_seconds();
    let knock = Authenticated::sign(
        Knock {
            version: PROTOCOL_VERSION,
            identity: alice.identity().to_owned(),
            device_id: alice.device_id().to_owned(),
            session_id,
            target_identity: bob_laptop.identity().to_owned(),
            target_device_id: None,
            application: "hole-punchky-test/1".to_owned(),
            metadata: None,
            issued_at: now,
            expires_at: now + 30,
        },
        &alice,
    )
    .unwrap_or_else(|error| panic!("signing knock: {error}"));
    send(&mut alice_socket, &ClientFrame::Knock(knock.clone())).await;
    assert_eq!(
        receive(&mut laptop_socket).await,
        ServerFrame::Knock(knock.clone())
    );
    assert_eq!(receive(&mut phone_socket).await, ServerFrame::Knock(knock));

    // A device that came online after fan-out cannot claim a session it never received.
    let mut late_socket = connect_registered(address, &bob_late).await;
    let late_accept = Authenticated::sign(
        Accept {
            version: PROTOCOL_VERSION,
            identity: bob_late.identity().to_owned(),
            device_id: bob_late.device_id().to_owned(),
            session_id,
            target_identity: alice.identity().to_owned(),
            issued_at: now_seconds(),
            expires_at: now_seconds() + 30,
        },
        &bob_late,
    )
    .unwrap_or_else(|error| panic!("signing late accept: {error}"));
    send(&mut late_socket, &ClientFrame::Accept(late_accept)).await;
    assert!(matches!(
        receive(&mut late_socket).await,
        ServerFrame::Error {
            code: ErrorCode::Unauthorized,
            session_id: Some(id),
            ..
        } if id == session_id
    ));

    let phone_reject = Authenticated::sign(
        Reject {
            version: PROTOCOL_VERSION,
            identity: bob_phone.identity().to_owned(),
            device_id: bob_phone.device_id().to_owned(),
            session_id,
            target_identity: alice.identity().to_owned(),
            reason: "not on this device".to_owned(),
            issued_at: now_seconds(),
            expires_at: now_seconds() + 30,
        },
        &bob_phone,
    )
    .unwrap_or_else(|error| panic!("signing rejection: {error}"));
    send(&mut phone_socket, &ClientFrame::Reject(phone_reject)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(150), receive(&mut alice_socket))
            .await
            .is_err(),
        "one device's rejection must not end a fan-out session"
    );

    let laptop_accept = Authenticated::sign(
        Accept {
            version: PROTOCOL_VERSION,
            identity: bob_laptop.identity().to_owned(),
            device_id: bob_laptop.device_id().to_owned(),
            session_id,
            target_identity: alice.identity().to_owned(),
            issued_at: now_seconds(),
            expires_at: now_seconds() + 30,
        },
        &bob_laptop,
    )
    .unwrap_or_else(|error| panic!("signing laptop accept: {error}"));
    send(
        &mut laptop_socket,
        &ClientFrame::Accept(laptop_accept.clone()),
    )
    .await;
    assert_eq!(
        receive(&mut alice_socket).await,
        ServerFrame::Accepted(laptop_accept)
    );

    server.abort();
}

#[tokio::test]
async fn enforces_global_session_capacity() {
    let (address, server) = spawn_ephemeral(ServerConfig {
        max_sessions: 1,
        ..ServerConfig::default()
    })
    .await
    .unwrap_or_else(|error| panic!("starting server: {error}"));
    let alice = credential(&Keypair::random(), "alice");
    let bob = credential(&Keypair::random(), "bob");
    let mut alice_socket = connect_registered(address, &alice).await;
    let mut bob_socket = connect_registered(address, &bob).await;

    let first_session = Uuid::new_v4();
    let now = now_seconds();
    let first = Authenticated::sign(
        Knock {
            version: PROTOCOL_VERSION,
            identity: alice.identity().to_owned(),
            device_id: alice.device_id().to_owned(),
            session_id: first_session,
            target_identity: bob.identity().to_owned(),
            target_device_id: None,
            application: "capacity-test/1".to_owned(),
            metadata: None,
            issued_at: now,
            expires_at: now + 30,
        },
        &alice,
    )
    .unwrap_or_else(|error| panic!("signing first knock: {error}"));
    send(&mut alice_socket, &ClientFrame::Knock(first.clone())).await;
    assert_eq!(receive(&mut bob_socket).await, ServerFrame::Knock(first));

    let second_session = Uuid::new_v4();
    let second = Authenticated::sign(
        Knock {
            version: PROTOCOL_VERSION,
            identity: alice.identity().to_owned(),
            device_id: alice.device_id().to_owned(),
            session_id: second_session,
            target_identity: bob.identity().to_owned(),
            target_device_id: None,
            application: "capacity-test/1".to_owned(),
            metadata: None,
            issued_at: now,
            expires_at: now + 30,
        },
        &alice,
    )
    .unwrap_or_else(|error| panic!("signing second knock: {error}"));
    send(&mut alice_socket, &ClientFrame::Knock(second)).await;
    assert!(matches!(
        receive(&mut alice_socket).await,
        ServerFrame::Error {
            code: ErrorCode::RateLimited,
            session_id: Some(id),
            ..
        } if id == second_session
    ));

    server.abort();
}

#[tokio::test]
async fn refuses_bad_registration_and_replayed_nonce() {
    let (address, server) = spawn_ephemeral(ServerConfig::default())
        .await
        .unwrap_or_else(|error| panic!("starting server: {error}"));
    let root = Keypair::random();
    let device = credential(&root, "desktop");
    let nonce = Uuid::new_v4().to_string();
    let valid = registration(&device, nonce);

    let (mut first, _) = connect_async(format!("ws://{address}/v1/ws"))
        .await
        .unwrap_or_else(|error| panic!("first connection: {error}"));
    send(&mut first, &valid).await;
    assert!(matches!(
        receive(&mut first).await,
        ServerFrame::Registered { .. }
    ));
    first
        .close(None)
        .await
        .unwrap_or_else(|error| panic!("closing first socket: {error}"));

    let (mut replay, _) = connect_async(format!("ws://{address}/v1/ws"))
        .await
        .unwrap_or_else(|error| panic!("replay connection: {error}"));
    send(&mut replay, &valid).await;
    assert!(matches!(
        receive(&mut replay).await,
        ServerFrame::Error {
            code: ErrorCode::Unauthorized,
            ..
        }
    ));

    let (mut bad, _) = connect_async(format!("ws://{address}/v1/ws"))
        .await
        .unwrap_or_else(|error| panic!("bad connection: {error}"));
    let mut tampered = registration(&device, Uuid::new_v4().to_string());
    if let ClientFrame::Register(frame) = &mut tampered {
        frame.payload.device_id = "not-this-device".to_owned();
    }
    send(&mut bad, &tampered).await;
    assert!(matches!(
        receive(&mut bad).await,
        ServerFrame::Error {
            code: ErrorCode::Unauthorized,
            ..
        }
    ));
    server.abort();
}

#[allow(dead_code)]
fn assert_tungstenite_error_is_send_sync(error: tungstenite::Error) {
    fn check<T: Send + Sync>(_: T) {}
    check(error);
}
