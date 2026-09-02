//! Real in-process WebSocket + ICE/DTLS/SCTP/DataChannel integration tests.

use std::time::Duration;

use hole_punchky_client::{
    ConnectionPath, DialOptions, IcePolicy, RendezvousClient, RendezvousClientConfig,
    StaticResolver,
};
use hole_punchky_protocol::{
    DeviceCredential, RendezvousDescriptor, RendezvousEndpoint, now_seconds,
};
use hole_punchky_rendezvous::{ServerConfig, spawn_ephemeral};
use pubky::Keypair;
use url::Url;

fn credential(root: &Keypair, device: &str) -> DeviceCredential {
    let now = now_seconds();
    DeviceCredential::issue(root, device, now.saturating_sub(1), now + 3_600)
        .unwrap_or_else(|error| panic!("issuing credential: {error}"))
}

fn client_config() -> RendezvousClientConfig {
    RendezvousClientConfig {
        negotiation_timeout: Duration::from_secs(20),
        heartbeat_interval: Duration::from_millis(50),
        ice_gather_timeout: Duration::from_secs(5),
        udp_bind_addresses: vec!["127.0.0.1:0".to_owned()],
        // Exercise the production default: request optional TURN credentials, then continue
        // with direct ICE when this test's rendezvous has no TURN service configured.
        request_turn: true,
        ..RendezvousClientConfig::default()
    }
}

#[tokio::test]
async fn falls_back_to_the_next_signed_rendezvous_endpoint() {
    let (address, server) = spawn_ephemeral(ServerConfig::default())
        .await
        .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let unused_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("reserving unused address: {error}"));
    let unreachable = unused_listener
        .local_addr()
        .unwrap_or_else(|error| panic!("reading unused address: {error}"));
    drop(unused_listener);

    let target_root = Keypair::random();
    let descriptor = RendezvousDescriptor::sign(
        &target_root,
        vec![
            RendezvousEndpoint {
                signaling_url: Url::parse(&format!("ws://{unreachable}/v1/ws"))
                    .unwrap_or_else(|error| panic!("unreachable URL: {error}")),
                priority: 0,
                region: Some("unreachable".to_owned()),
            },
            RendezvousEndpoint {
                signaling_url: Url::parse(&format!("ws://{address}/v1/ws"))
                    .unwrap_or_else(|error| panic!("reachable URL: {error}")),
                priority: 1,
                region: Some("fallback".to_owned()),
            },
        ],
        now_seconds() + 300,
    )
    .unwrap_or_else(|error| panic!("signing descriptor: {error}"));
    let resolver = StaticResolver::new(true);
    resolver.insert(descriptor).await;
    let local = credential(&Keypair::random(), "local-device");
    let expected_local_identity = local.identity().to_owned();

    let client = RendezvousClient::connect_resolved(
        &resolver,
        &target_root.public_key().z32(),
        local,
        client_config(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting through fallback: {error}"));
    assert_eq!(client.identity(), expected_local_identity);

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creates_direct_authenticated_data_channel_and_echoes() {
    let server_config = ServerConfig {
        stun_urls: Vec::new(),
        ..ServerConfig::default()
    };
    let (address, server) = spawn_ephemeral(server_config)
        .await
        .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let url = Url::parse(&format!("ws://{address}/v1/ws"))
        .unwrap_or_else(|error| panic!("rendezvous URL: {error}"));

    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let alice = RendezvousClient::connect(
        url.clone(),
        credential(&alice_root, "alice-laptop"),
        client_config(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Alice: {error}"));
    let bob = RendezvousClient::connect(url, credential(&bob_root, "bob-phone"), client_config())
        .await
        .unwrap_or_else(|error| panic!("connecting Bob: {error}"));

    // Exercise multiple application heartbeats before any rendezvous operation.
    tokio::time::sleep(Duration::from_millis(125)).await;

    let bob_identity = bob.identity().to_owned();
    let alice_identity = alice.identity().to_owned();
    let responder = tokio::spawn(async move {
        let knock = bob
            .next_knock()
            .await
            .unwrap_or_else(|error| panic!("receiving knock: {error}"));
        assert_eq!(knock.knock().identity, alice_identity);
        assert_eq!(knock.knock().application, "integration/echo/1");
        let peer = bob
            .accept(knock, IcePolicy::DirectWithRelayFallback)
            .await
            .unwrap_or_else(|error| panic!("accepting connection: {error}"));
        let message = peer
            .recv()
            .await
            .unwrap_or_else(|error| panic!("receiving request: {error}"));
        assert_eq!(message, b"hello through NAT traversal");
        peer.send(b"echo: hello through NAT traversal")
            .await
            .unwrap_or_else(|error| panic!("sending response: {error}"));
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving completion ack: {error}")),
            b"ack"
        );
        let path = peer.path().await;
        peer.close()
            .await
            .unwrap_or_else(|error| panic!("closing responder: {error}"));
        path
    });

    let peer = alice
        .dial(
            &bob_identity,
            DialOptions {
                application: "integration/echo/1".to_owned(),
                ..DialOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("dialing Bob: {error}"));
    assert_eq!(peer.peer_identity(), bob_identity);
    assert_eq!(peer.peer_device_id(), "bob-phone");
    peer.send(b"hello through NAT traversal")
        .await
        .unwrap_or_else(|error| panic!("sending request: {error}"));
    assert_eq!(
        peer.recv()
            .await
            .unwrap_or_else(|error| panic!("receiving response: {error}")),
        b"echo: hello through NAT traversal"
    );
    peer.send(b"ack")
        .await
        .unwrap_or_else(|error| panic!("sending completion ack: {error}"));
    assert_eq!(peer.path().await, ConnectionPath::Direct);
    let responder_path = responder
        .await
        .unwrap_or_else(|error| panic!("responder task: {error}"));
    assert_eq!(responder_path, ConnectionPath::Direct);
    peer.close()
        .await
        .unwrap_or_else(|error| panic!("closing initiator: {error}"));
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_returns_before_any_webrtc_negotiation() {
    let (address, server) = spawn_ephemeral(ServerConfig {
        stun_urls: Vec::new(),
        ..ServerConfig::default()
    })
    .await
    .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let url = Url::parse(&format!("ws://{address}/v1/ws"))
        .unwrap_or_else(|error| panic!("rendezvous URL: {error}"));
    let alice = RendezvousClient::connect(
        url.clone(),
        credential(&Keypair::random(), "alice"),
        client_config(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Alice: {error}"));
    let bob =
        RendezvousClient::connect(url, credential(&Keypair::random(), "bob"), client_config())
            .await
            .unwrap_or_else(|error| panic!("connecting Bob: {error}"));
    let bob_identity = bob.identity().to_owned();
    let rejector = tokio::spawn(async move {
        let knock = bob
            .next_knock()
            .await
            .unwrap_or_else(|error| panic!("receiving knock: {error}"));
        bob.reject(&knock, "not now")
            .await
            .unwrap_or_else(|error| panic!("rejecting: {error}"));
    });
    let Err(error) = alice.dial(&bob_identity, DialOptions::default()).await else {
        panic!("dial should be rejected");
    };
    assert!(error.to_string().contains("not now"), "{error:?}");
    rejector
        .await
        .unwrap_or_else(|error| panic!("rejector task: {error}"));
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires HPK_TEST_TURN_URL and a coturn instance with HPK_TEST_TURN_SECRET"]
async fn forced_turn_path_relays_data_channel() {
    let turn_url = std::env::var("HPK_TEST_TURN_URL")
        .unwrap_or_else(|_| "turn:127.0.0.1:3478?transport=udp".to_owned());
    let turn_secret = std::env::var("HPK_TEST_TURN_SECRET")
        .unwrap_or_else(|_| "hole-punchky-integration-secret".to_owned());
    let (address, server) = spawn_ephemeral(ServerConfig {
        stun_urls: Vec::new(),
        turn_urls: vec![turn_url],
        turn_shared_secret: Some(turn_secret),
        ..ServerConfig::default()
    })
    .await
    .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let url = Url::parse(&format!("ws://{address}/v1/ws"))
        .unwrap_or_else(|error| panic!("rendezvous URL: {error}"));
    let relay_config = RendezvousClientConfig {
        negotiation_timeout: Duration::from_secs(45),
        ice_gather_timeout: Duration::from_secs(25),
        udp_bind_addresses: vec!["0.0.0.0:0".to_owned()],
        request_turn: true,
        ..RendezvousClientConfig::default()
    };
    let alice = RendezvousClient::connect(
        url.clone(),
        credential(&Keypair::random(), "alice-relay"),
        relay_config.clone(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Alice: {error}"));
    let bob = RendezvousClient::connect(
        url,
        credential(&Keypair::random(), "bob-relay"),
        relay_config,
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Bob: {error}"));
    let target = bob.identity().to_owned();
    let responder = tokio::spawn(async move {
        let knock = bob
            .next_knock()
            .await
            .unwrap_or_else(|error| panic!("receiving relay knock: {error}"));
        let peer = bob
            .accept(knock, IcePolicy::RelayOnly)
            .await
            .unwrap_or_else(|error| panic!("accepting relay connection: {error}"));
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving relay data: {error}")),
            b"through-turn"
        );
        peer.send(b"relay-ack")
            .await
            .unwrap_or_else(|error| panic!("sending relay response: {error}"));
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving relay close ack: {error}")),
            b"done"
        );
        let path = peer.path().await;
        peer.close()
            .await
            .unwrap_or_else(|error| panic!("closing relay responder: {error}"));
        path
    });
    let peer = alice
        .dial(
            &target,
            DialOptions {
                application: "integration/turn/1".to_owned(),
                ice_policy: IcePolicy::RelayOnly,
                ..DialOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("dialing through TURN: {error}"));
    peer.send(b"through-turn")
        .await
        .unwrap_or_else(|error| panic!("sending relay data: {error}"));
    assert_eq!(
        peer.recv()
            .await
            .unwrap_or_else(|error| panic!("receiving relay response: {error}")),
        b"relay-ack"
    );
    assert_eq!(peer.path().await, ConnectionPath::Relayed);
    peer.send(b"done")
        .await
        .unwrap_or_else(|error| panic!("sending relay close ack: {error}"));
    assert_eq!(
        responder
            .await
            .unwrap_or_else(|error| panic!("relay responder task: {error}")),
        ConnectionPath::Relayed
    );
    peer.close()
        .await
        .unwrap_or_else(|error| panic!("closing relay initiator: {error}"));
    server.abort();
}
