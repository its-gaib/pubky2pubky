//! Cryptographic protocol round-trip and tamper tests.

use hole_punchky_protocol::{
    Authenticated, DESCRIPTOR_PATH, DeviceCredential, EncryptedSignal, IROH_TRANSPORT,
    IrohEndpointAddress, Knock, PROTOCOL_VERSION, ProtocolError, RendezvousDescriptor,
    RendezvousEndpoint, SignalPayload,
};
use pubky_common::crypto::Keypair;
use url::Url;
use uuid::Uuid;

fn credential(root: &Keypair, device: &str, now: u64) -> DeviceCredential {
    DeviceCredential::issue(root, device, now - 1, now + 3_600)
        .unwrap_or_else(|error| panic!("credential: {error}"))
}

#[test]
fn delegated_message_round_trip_and_tampering() {
    let now = 1_800_000_000;
    let root = Keypair::random();
    let device = credential(&root, "phone", now);
    let payload = Knock {
        version: PROTOCOL_VERSION,
        identity: device.identity().to_owned(),
        device_id: device.device_id().to_owned(),
        session_id: Uuid::new_v4(),
        target_identity: Keypair::random().public_key().z32(),
        target_device_id: None,
        application: "test/1".to_owned(),
        metadata: None,
        issued_at: now,
        expires_at: now + 30,
    };
    let signed =
        Authenticated::sign(payload, &device).unwrap_or_else(|error| panic!("signing: {error}"));
    assert!(signed.verify(now).is_ok());

    let mut tampered = signed;
    tampered.payload.application = "different/1".to_owned();
    assert!(matches!(
        tampered.verify(now),
        Err(ProtocolError::BadSignature)
    ));
}

#[test]
fn rejects_wrong_device_and_expired_certificate() {
    let now = 1_800_000_000;
    let root = Keypair::random();
    let mut device = credential(&root, "laptop", now);
    device.certificate.claims.device_id = "attacker".to_owned();
    assert!(matches!(
        device.certificate.verify(now, None),
        Err(ProtocolError::BadSignature)
    ));

    let expired = DeviceCredential::issue(&root, "old", now - 4_000, now - 2_000)
        .unwrap_or_else(|error| panic!("credential: {error}"));
    assert!(matches!(
        expired.certificate.verify(now, None),
        Err(ProtocolError::Expired)
    ));

    let mut noncanonical = credential(&root, "desktop", now).certificate.clone();
    noncanonical.claims.identity = format!("https://{}", noncanonical.claims.identity);
    assert!(matches!(
        noncanonical.verify(now, None),
        Err(ProtocolError::InvalidEncoding("canonical public key"))
    ));

    let mut wrong_iroh_key = credential(&root, "tablet", now).certificate.clone();
    wrong_iroh_key.claims.iroh_endpoint_id = Keypair::random().public_key().z32();
    assert!(matches!(
        wrong_iroh_key.verify(now, Some("iroh")),
        Err(ProtocolError::BadSignature)
    ));
}

#[test]
fn hpke_signal_is_private_authenticated_and_recipient_bound() {
    let now = 1_800_000_000;
    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let mallory_root = Keypair::random();
    let alice = credential(&alice_root, "alice-phone", now);
    let bob = credential(&bob_root, "bob-laptop", now);
    let mallory = credential(&mallory_root, "mallory", now);
    let payload = SignalPayload::IrohEndpoint {
        endpoint: IrohEndpointAddress {
            endpoint_id: alice.iroh_endpoint_id().to_owned(),
            relay_urls: vec![
                Url::parse("https://relay.example")
                    .unwrap_or_else(|error| panic!("relay URL: {error}")),
            ],
            direct_addresses: vec![
                "192.0.2.8:4242"
                    .parse()
                    .unwrap_or_else(|error| panic!("socket address: {error}")),
            ],
        },
    };
    let signal = EncryptedSignal::seal(
        &alice,
        &bob.certificate,
        Uuid::new_v4(),
        0,
        &payload,
        now,
        now + 30,
    )
    .unwrap_or_else(|error| panic!("encrypting: {error}"));

    let encoded =
        serde_json::to_string(&signal).unwrap_or_else(|error| panic!("serializing: {error}"));
    assert!(!encoded.contains("192.0.2.8"));
    assert!(!encoded.contains("relay.example"));
    assert_eq!(
        signal
            .open(&bob, now)
            .unwrap_or_else(|error| panic!("decrypting: {error}")),
        payload
    );
    assert!(matches!(
        signal.open(&mallory, now),
        Err(ProtocolError::IdentityMismatch)
    ));

    let invalid_endpoint = SignalPayload::IrohEndpoint {
        endpoint: IrohEndpointAddress {
            endpoint_id: alice.iroh_endpoint_id().to_owned(),
            relay_urls: Vec::new(),
            direct_addresses: Vec::new(),
        },
    };
    assert!(matches!(
        EncryptedSignal::seal(
            &alice,
            &bob.certificate,
            Uuid::new_v4(),
            0,
            &invalid_endpoint,
            now,
            now + 30,
        ),
        Err(ProtocolError::InvalidEncoding("iroh endpoint address"))
    ));

    let wrong_endpoint = SignalPayload::IrohEndpoint {
        endpoint: IrohEndpointAddress {
            endpoint_id: bob.iroh_endpoint_id().to_owned(),
            relay_urls: vec![
                Url::parse("https://relay.example")
                    .unwrap_or_else(|error| panic!("relay URL: {error}")),
            ],
            direct_addresses: Vec::new(),
        },
    };
    assert!(matches!(
        EncryptedSignal::seal(
            &alice,
            &bob.certificate,
            Uuid::new_v4(),
            0,
            &wrong_endpoint,
            now,
            now + 30,
        ),
        Err(ProtocolError::DeviceMismatch)
    ));

    let mut tampered = signal;
    tampered.header.sequence += 1;
    assert!(matches!(
        tampered.open(&bob, now),
        Err(ProtocolError::BadSignature)
    ));
}

#[test]
fn signed_descriptor_enforces_identity_expiry_and_tls() {
    assert_eq!(DESCRIPTOR_PATH, "/pub/hole-punchky/v2/descriptor.json");
    let now = 1_800_000_000;
    let root = Keypair::random();
    let descriptor = RendezvousDescriptor::sign(
        &root,
        vec![RendezvousEndpoint {
            signaling_url: Url::parse("wss://rendezvous.example/ws")
                .unwrap_or_else(|error| panic!("URL: {error}")),
            priority: 10,
            region: Some("eu".to_owned()),
        }],
        now + 600,
    )
    .unwrap_or_else(|error| panic!("descriptor: {error}"));
    assert!(
        descriptor
            .verify(&root.public_key().z32(), now, false)
            .is_ok()
    );
    assert_eq!(descriptor.claims.transports, vec![IROH_TRANSPORT]);
    assert!(matches!(
        descriptor.verify(&Keypair::random().public_key().z32(), now, false),
        Err(ProtocolError::IdentityMismatch)
    ));

    let insecure = RendezvousDescriptor::sign(
        &root,
        vec![RendezvousEndpoint {
            signaling_url: Url::parse("ws://public.example/ws")
                .unwrap_or_else(|error| panic!("URL: {error}")),
            priority: 0,
            region: None,
        }],
        now + 600,
    )
    .unwrap_or_else(|error| panic!("descriptor: {error}"));
    assert!(matches!(
        insecure.verify(&root.public_key().z32(), now, true),
        Err(ProtocolError::InvalidEncoding(_))
    ));
}
