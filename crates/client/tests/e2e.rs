//! Real WebSocket consent plus iroh QUIC integration tests.

use std::{net::Ipv4Addr, time::Duration};

use hole_punchky_client::{
    ConnectionPath, DialOptions, IrohRelayConfig, PathPolicy, RendezvousClient,
    RendezvousClientConfig, StaticResolver,
};
use hole_punchky_protocol::{
    DeviceCredential, RendezvousDescriptor, RendezvousEndpoint, now_seconds,
};
use hole_punchky_rendezvous::{ServerConfig, spawn_ephemeral};
use iroh_relay::server::{
    RelayConfig as RelayServerConfig, Server as RelayServer, ServerConfig as RelayServerConfigSet,
};
use pubky::Keypair;
use url::Url;

fn credential(root: &Keypair, device: &str) -> DeviceCredential {
    let now = now_seconds();
    DeviceCredential::issue(root, device, now.saturating_sub(1), now + 3_600)
        .unwrap_or_else(|error| panic!("issuing device credential: {error}"))
}

fn direct_config() -> RendezvousClientConfig {
    RendezvousClientConfig {
        negotiation_timeout: Duration::from_secs(20),
        heartbeat_interval: Duration::from_millis(50),
        peer_handshake_timeout: Duration::from_secs(10),
        udp_bind_addresses: vec![
            "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|error| panic!("bind address: {error}")),
        ],
        ..RendezvousClientConfig::default()
    }
}

fn rendezvous_url(address: std::net::SocketAddr) -> Url {
    Url::parse(&format!("ws://{address}/v2/ws"))
        .unwrap_or_else(|error| panic!("rendezvous URL: {error}"))
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
                signaling_url: rendezvous_url(unreachable),
                priority: 0,
                region: Some("unreachable".to_owned()),
            },
            RendezvousEndpoint {
                signaling_url: rendezvous_url(address),
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
        direct_config(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting through fallback: {error}"));
    assert_eq!(client.identity(), expected_local_identity);
    assert_eq!(client.iroh_endpoint_id().len(), 52);
    client.close().await;

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn creates_direct_authenticated_quic_stream_and_echoes_large_message() {
    let (address, server) = spawn_ephemeral(ServerConfig::default())
        .await
        .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let url = rendezvous_url(address);

    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let alice = RendezvousClient::connect(
        url.clone(),
        credential(&alice_root, "alice-laptop"),
        direct_config(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Alice: {error}"));
    let bob = RendezvousClient::connect(url, credential(&bob_root, "bob-phone"), direct_config())
        .await
        .unwrap_or_else(|error| panic!("connecting Bob: {error}"));

    tokio::time::sleep(Duration::from_millis(125)).await;
    let bob_identity = bob.identity().to_owned();
    let alice_identity = alice.identity().to_owned();
    let payload = vec![0x5a; 128 * 1024];
    let expected_payload = payload.clone();
    let responder = tokio::spawn(async move {
        let knock = bob
            .next_knock()
            .await
            .unwrap_or_else(|error| panic!("receiving knock: {error}"));
        assert_eq!(knock.knock().identity, alice_identity);
        assert_eq!(knock.knock().application, "integration/echo/2");
        let peer = bob
            .accept(knock)
            .await
            .unwrap_or_else(|error| panic!("accepting connection: {error}"));
        assert_eq!(peer.peer_identity(), alice_identity);
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving request: {error}")),
            expected_payload
        );
        peer.send(b"large-message-ok")
            .await
            .unwrap_or_else(|error| panic!("sending response: {error}"));
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving completion ack: {error}")),
            b"ack"
        );
        let path = peer.path();
        peer.finish(Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("finishing responder: {error}"));
        peer.wait_for_peer_finish(Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("waiting for initiator finish: {error}"));
        peer.close()
            .await
            .unwrap_or_else(|error| panic!("closing responder: {error}"));
        bob.close().await;
        path
    });

    let peer = alice
        .dial(
            &bob_identity,
            DialOptions {
                application: "integration/echo/2".to_owned(),
                ..DialOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("dialing Bob: {error}"));
    assert_eq!(peer.peer_identity(), bob_identity);
    assert_eq!(peer.peer_device_id(), "bob-phone");
    peer.send(&payload)
        .await
        .unwrap_or_else(|error| panic!("sending request: {error}"));
    assert_eq!(
        peer.recv()
            .await
            .unwrap_or_else(|error| panic!("receiving response: {error}")),
        b"large-message-ok"
    );
    peer.send(b"ack")
        .await
        .unwrap_or_else(|error| panic!("sending completion ack: {error}"));
    peer.finish(Duration::from_secs(2))
        .await
        .unwrap_or_else(|error| panic!("finishing completion ack: {error}"));
    peer.wait_for_peer_finish(Duration::from_secs(2))
        .await
        .unwrap_or_else(|error| panic!("waiting for responder finish: {error}"));
    assert_eq!(peer.path(), ConnectionPath::Direct);
    assert_eq!(
        responder
            .await
            .unwrap_or_else(|error| panic!("responder task: {error}")),
        ConnectionPath::Direct
    );
    peer.close()
        .await
        .unwrap_or_else(|error| panic!("closing initiator: {error}"));
    alice.close().await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_finishes_without_releasing_a_peer_address() {
    let (address, server) = spawn_ephemeral(ServerConfig::default())
        .await
        .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let url = rendezvous_url(address);
    let alice = RendezvousClient::connect(
        url.clone(),
        credential(&Keypair::random(), "alice"),
        direct_config(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Alice: {error}"));
    let bob =
        RendezvousClient::connect(url, credential(&Keypair::random(), "bob"), direct_config())
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
        bob.close().await;
    });
    let Err(error) = alice.dial(&bob_identity, DialOptions::default()).await else {
        panic!("dial should be rejected");
    };
    assert!(error.to_string().contains("not now"), "{error:?}");
    rejector
        .await
        .unwrap_or_else(|error| panic!("rejector task: {error}"));
    alice.close().await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "chronological relay integration transcript"
)]
async fn forced_iroh_relay_path_carries_authenticated_quic() {
    let mut relay_server_config = RelayServerConfigSet::default();
    relay_server_config.relay = Some(RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_server_config)
        .await
        .unwrap_or_else(|error| panic!("starting iroh relay: {error}"));
    let relay_address = relay
        .http_addr()
        .unwrap_or_else(|| panic!("iroh relay did not expose HTTP"));
    let relay_url = Url::parse(&format!("http://{relay_address}"))
        .unwrap_or_else(|error| panic!("relay URL: {error}"));

    let (address, rendezvous) = spawn_ephemeral(ServerConfig::default())
        .await
        .unwrap_or_else(|error| panic!("starting rendezvous: {error}"));
    let config = RendezvousClientConfig {
        negotiation_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_millis(50),
        endpoint_online_timeout: Duration::from_secs(10),
        peer_handshake_timeout: Duration::from_secs(15),
        udp_bind_addresses: Vec::new(),
        relay_servers: vec![IrohRelayConfig::new(relay_url)],
        allow_insecure_relay: true,
        path_policy: PathPolicy::RelayOnly,
        ..RendezvousClientConfig::default()
    };
    let url = rendezvous_url(address);
    let alice = RendezvousClient::connect(
        url.clone(),
        credential(&Keypair::random(), "alice-relay"),
        config.clone(),
    )
    .await
    .unwrap_or_else(|error| panic!("connecting Alice: {error}"));
    let bob = RendezvousClient::connect(url, credential(&Keypair::random(), "bob-relay"), config)
        .await
        .unwrap_or_else(|error| panic!("connecting Bob: {error}"));
    let target = bob.identity().to_owned();
    let responder = tokio::spawn(async move {
        let knock = bob
            .next_knock()
            .await
            .unwrap_or_else(|error| panic!("receiving relay knock: {error}"));
        let peer = bob
            .accept(knock)
            .await
            .unwrap_or_else(|error| panic!("accepting relay connection: {error}"));
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving relay data: {error}")),
            b"through-iroh-relay"
        );
        peer.send(b"relay-ack")
            .await
            .unwrap_or_else(|error| panic!("sending relay response: {error}"));
        assert_eq!(
            peer.recv()
                .await
                .unwrap_or_else(|error| panic!("receiving relay completion: {error}")),
            b"done"
        );
        let path = peer.path();
        peer.finish(Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("finishing relay responder: {error}"));
        peer.wait_for_peer_finish(Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("waiting for relay initiator finish: {error}"));
        peer.close()
            .await
            .unwrap_or_else(|error| panic!("closing relay responder: {error}"));
        bob.close().await;
        path
    });
    let peer = alice
        .dial(
            &target,
            DialOptions {
                application: "integration/iroh-relay/1".to_owned(),
                ..DialOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("dialing through iroh relay: {error}"));
    peer.send(b"through-iroh-relay")
        .await
        .unwrap_or_else(|error| panic!("sending relay data: {error}"));
    assert_eq!(
        peer.recv()
            .await
            .unwrap_or_else(|error| panic!("receiving relay response: {error}")),
        b"relay-ack"
    );
    assert_eq!(peer.path(), ConnectionPath::Relayed);
    peer.send(b"done")
        .await
        .unwrap_or_else(|error| panic!("sending relay completion: {error}"));
    peer.finish(Duration::from_secs(2))
        .await
        .unwrap_or_else(|error| panic!("finishing relay completion: {error}"));
    peer.wait_for_peer_finish(Duration::from_secs(2))
        .await
        .unwrap_or_else(|error| panic!("waiting for relay responder finish: {error}"));
    assert_eq!(
        responder
            .await
            .unwrap_or_else(|error| panic!("relay responder task: {error}")),
        ConnectionPath::Relayed
    );
    peer.close()
        .await
        .unwrap_or_else(|error| panic!("closing relay initiator: {error}"));
    alice.close().await;
    rendezvous.abort();
    relay
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("stopping iroh relay: {error}"));
}
