//! Version 3 discovery, delegation, and direct-iroh handshake tests.

use std::fmt::Display;

use hole_punchky_protocol::{
    ProtocolError, V3_DEVICE_CAPABILITIES, V3_DIRECTORY_PATH, V3_IROH_ALPN, V3_IROH_ALPN_TEXT,
    V3_LOCATOR_PATH_PREFIX, V3_MAX_CERTIFICATES, V3_MAX_DIRECTORY_LIFETIME_SECONDS,
    V3_MAX_HANDSHAKE_LIFETIME_SECONDS, V3_MAX_LOCATOR_LIFETIME_SECONDS, V3_MAX_RELAY_URLS,
    V3_PROTOCOL_VERSION, V3DeviceCertificate, V3DeviceCredential, V3DeviceDirectory, V3SignedAck,
    V3SignedHello, V3SignedLocator, v3_locator_path, v3_random_nonce,
};
use pubky_common::crypto::Keypair;
use url::Url;

const NOW: u64 = 1_900_000_000;

fn ok<T, E: Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("unexpected error: {error}"))
}

fn url(value: &str) -> Url {
    ok(Url::parse(value))
}

fn credential(root: &Keypair, device_id: &str) -> V3DeviceCredential {
    ok(V3DeviceCredential::issue(
        root,
        device_id,
        NOW - 10,
        NOW + 7_200,
    ))
}

fn locator(credential: &V3DeviceCredential, sequence: u64) -> V3SignedLocator {
    ok(V3SignedLocator::sign(
        credential,
        vec![url("https://relay.example/")],
        v3_random_nonce(),
        sequence,
        NOW,
        NOW + 600,
    ))
}

#[test]
fn constants_credentials_and_secrets_are_v3_specific() {
    assert_eq!(V3_PROTOCOL_VERSION, 3);
    assert_eq!(V3_DIRECTORY_PATH, "/pub/pubky2pubky/v3/directory.json");
    assert_eq!(V3_LOCATOR_PATH_PREFIX, "/pub/pubky2pubky/v3/locators/");
    assert_eq!(V3_IROH_ALPN, b"pubky2pubky/iroh/v3");
    assert_eq!(V3_IROH_ALPN_TEXT, "pubky2pubky/iroh/v3");

    let root = Keypair::random();
    let device = credential(&root, "Alice's laptop");
    let identity = root.public_key().z32();
    assert!(device.certificate.verify(&identity, NOW).is_ok());
    assert_eq!(
        device.certificate.claims.capabilities,
        V3_DEVICE_CAPABILITIES.map(str::to_owned)
    );
    assert_ne!(device.control_signing_key(), device.iroh_endpoint_id());
    assert_ne!(device.control_signing_key(), identity);
    assert_ne!(device.iroh_endpoint_id(), identity);
    assert_eq!(ok(device.iroh_secret_key_bytes()).len(), 32);

    let serialized = ok(serde_json::to_value(&device));
    let control_secret = serialized["control_signing_secret"]
        .as_str()
        .unwrap_or_else(|| panic!("control secret must serialize as a string"));
    let iroh_secret = serialized["iroh_secret"]
        .as_str()
        .unwrap_or_else(|| panic!("iroh secret must serialize as a string"));
    let debug = format!("{device:?}");
    assert!(!debug.contains(control_secret));
    assert!(!debug.contains(iroh_secret));
    assert!(debug.contains("[REDACTED]"));
    assert!(serialized.get("encryption_secret").is_none());
    assert!(serialized.get("encryption_key").is_none());
}

#[test]
fn certificate_rejects_tampering_bad_capabilities_and_cross_identity() {
    let root = Keypair::random();
    let other_root = Keypair::random();
    let certificate = credential(&root, "phone").certificate.clone();

    assert!(matches!(
        certificate.verify(&other_root.public_key().z32(), NOW),
        Err(ProtocolError::IdentityMismatch)
    ));

    let mut capabilities = certificate.clone();
    capabilities.claims.capabilities.reverse();
    assert!(matches!(
        capabilities.verify(&root.public_key().z32(), NOW),
        Err(ProtocolError::InvalidEncoding("v3 device capabilities"))
    ));

    let mut endpoint = certificate.clone();
    endpoint.claims.iroh_endpoint_id = Keypair::random().public_key().z32();
    assert!(matches!(
        endpoint.verify(&root.public_key().z32(), NOW),
        Err(ProtocolError::BadSignature)
    ));

    let too_long = V3DeviceCredential::issue(&root, "long-lived", NOW, NOW + 90 * 24 * 60 * 60 + 1);
    assert!(matches!(
        too_long,
        Err(ProtocolError::InvalidEncoding("v3 certificate lifetime"))
    ));
    assert!(matches!(
        V3DeviceCredential::issue(&root, "\n", NOW, NOW + 60),
        Err(ProtocolError::InvalidEncoding("v3 device id"))
    ));
}

#[test]
fn directory_is_bounded_sorted_root_signed_and_rollback_aware() {
    let root = Keypair::random();
    let identity = root.public_key().z32();
    let alpha = credential(&root, "alpha");
    let beta = credential(&root, "beta");
    let directory = ok(V3DeviceDirectory::sign(
        &root,
        7,
        vec![beta.certificate.clone(), alpha.certificate.clone()],
        NOW,
        NOW + 1_800,
    ));

    assert!(directory.verify(&identity, NOW, None).is_ok());
    assert!(directory.verify(&identity, NOW, Some(7)).is_ok());
    assert!(matches!(
        directory.verify(&identity, NOW, Some(8)),
        Err(ProtocolError::InvalidEncoding("v3 directory generation"))
    ));
    assert!(
        directory.claims.devices[0].claims.control_signing_key
            < directory.claims.devices[1].claims.control_signing_key
    );
    assert!(
        directory
            .device_by_control_key(alpha.control_signing_key())
            .is_some()
    );

    let empty = ok(V3DeviceDirectory::sign(
        &root,
        8,
        Vec::new(),
        NOW,
        NOW + 300,
    ));
    assert!(empty.verify(&identity, NOW, Some(8)).is_ok());

    let devices: Vec<V3DeviceCertificate> = (0..=V3_MAX_CERTIFICATES)
        .map(|index| {
            credential(&root, &format!("device-{index}"))
                .certificate
                .clone()
        })
        .collect();
    assert!(matches!(
        V3DeviceDirectory::sign(&root, 9, devices, NOW, NOW + 300),
        Err(ProtocolError::InvalidEncoding("v3 device directory size"))
    ));
    assert!(matches!(
        V3DeviceDirectory::sign(
            &root,
            9,
            Vec::new(),
            NOW,
            NOW + V3_MAX_DIRECTORY_LIFETIME_SECONDS + 1,
        ),
        Err(ProtocolError::InvalidEncoding("v3 directory lifetime"))
    ));

    let mut tampered = directory.clone();
    tampered.claims.generation += 1;
    assert!(matches!(
        tampered.verify(&identity, NOW, None),
        Err(ProtocolError::BadSignature)
    ));

    let foreign = credential(&Keypair::random(), "foreign")
        .certificate
        .clone();
    assert!(matches!(
        V3DeviceDirectory::sign(&root, 10, vec![foreign], NOW, NOW + 300),
        Err(ProtocolError::IdentityMismatch)
    ));
}

#[test]
fn locator_path_uses_only_a_canonical_control_key() {
    let root = Keypair::random();
    let device = credential(&root, "../../not-a-path");
    let path = ok(v3_locator_path(device.control_signing_key()));
    assert_eq!(
        path,
        format!(
            "/pub/pubky2pubky/v3/locators/{}.json",
            device.control_signing_key()
        )
    );
    assert!(!path.contains(device.device_id()));
    assert_eq!(ok(locator(&device, 1).path()), path);
    assert!(v3_locator_path("../../directory.json").is_err());
    assert!(v3_locator_path(&device.control_signing_key().to_uppercase()).is_err());
}

#[test]
fn locator_is_relay_only_short_lived_signed_and_sequence_bound() {
    let root = Keypair::random();
    let device = credential(&root, "desktop");
    let identity = root.public_key().z32();
    let locator = locator(&device, 41);

    assert!(
        locator
            .verify(&device.certificate, &identity, NOW, false, None)
            .is_ok()
    );
    assert!(
        locator
            .verify(&device.certificate, &identity, NOW, false, Some(41))
            .is_ok()
    );
    assert!(matches!(
        locator.verify(&device.certificate, &identity, NOW, false, Some(42)),
        Err(ProtocolError::InvalidEncoding("v3 locator sequence"))
    ));
    let encoded = ok(serde_json::to_string(&locator));
    assert!(!encoded.contains("direct"));
    assert!(!encoded.contains("192.0.2."));

    let mut endpoint_tamper = locator.clone();
    endpoint_tamper.claims.iroh_endpoint_id = Keypair::random().public_key().z32();
    assert!(matches!(
        endpoint_tamper.verify(&device.certificate, &identity, NOW, false, None),
        Err(ProtocolError::DeviceMismatch)
    ));

    let mut relay_tamper = locator.clone();
    relay_tamper.claims.relay_urls = vec![url("https://other-relay.example/")];
    assert!(matches!(
        relay_tamper.verify(&device.certificate, &identity, NOW, false, None),
        Err(ProtocolError::BadSignature)
    ));
    assert!(matches!(
        locator.verify(&device.certificate, &identity, NOW + 1_000, false, None,),
        Err(ProtocolError::Expired)
    ));

    assert!(matches!(
        V3SignedLocator::sign(
            &device,
            vec![url("https://relay.example/")],
            v3_random_nonce(),
            1,
            NOW,
            NOW + V3_MAX_LOCATOR_LIFETIME_SECONDS + 1,
        ),
        Err(ProtocolError::InvalidEncoding("v3 locator lifetime"))
    ));
}

#[test]
fn relay_url_nonce_and_count_policy_is_strict_with_explicit_loopback_dev() {
    let root = Keypair::random();
    let device = credential(&root, "local-dev");
    let identity = root.public_key().z32();

    assert!(
        V3SignedLocator::sign(
            &device,
            vec![url("http://127.0.0.1:3340/")],
            v3_random_nonce(),
            1,
            NOW,
            NOW + 60,
        )
        .is_err()
    );
    let local = ok(V3SignedLocator::sign_for_local_development(
        &device,
        vec![url("http://127.0.0.1:3340/")],
        v3_random_nonce(),
        1,
        NOW,
        NOW + 60,
    ));
    assert!(
        local
            .verify(&device.certificate, &identity, NOW, true, None)
            .is_ok()
    );
    assert!(matches!(
        local.verify(&device.certificate, &identity, NOW, false, None),
        Err(ProtocolError::InvalidEncoding("v3 relay URL"))
    ));

    let invalid_relays = [
        "http://relay.example/",
        "https://user@relay.example/",
        "https://relay.example/path",
        "https://relay.example/?query=yes",
        "https://relay.example/#fragment",
    ];
    for invalid in invalid_relays {
        assert!(
            V3SignedLocator::sign(
                &device,
                vec![url(invalid)],
                v3_random_nonce(),
                2,
                NOW,
                NOW + 60,
            )
            .is_err()
        );
    }
    assert!(
        V3SignedLocator::sign(&device, Vec::new(), v3_random_nonce(), 2, NOW, NOW + 60,).is_err()
    );
    assert!(
        V3SignedLocator::sign(
            &device,
            vec![url("https://relay.example/"); V3_MAX_RELAY_URLS + 1],
            v3_random_nonce(),
            2,
            NOW,
            NOW + 60,
        )
        .is_err()
    );
    assert!(
        V3SignedLocator::sign(
            &device,
            vec![url("https://relay.example/"), url("https://relay.example/"),],
            v3_random_nonce(),
            2,
            NOW,
            NOW + 60,
        )
        .is_err()
    );

    for bad_nonce in ["too-short", "AAAAAAAAAAAAAAAAAAAAAA=="] {
        assert!(
            V3SignedLocator::sign(
                &device,
                vec![url("https://relay.example/")],
                bad_nonce,
                2,
                NOW,
                NOW + 60,
            )
            .is_err()
        );
    }
}

#[test]
fn hello_and_ack_bind_every_identity_device_endpoint_application_and_locator() {
    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let alice = credential(&alice_root, "alice-phone");
    let bob = credential(&bob_root, "bob-laptop");
    let bob_locator = locator(&bob, 9);
    let hello = ok(V3SignedHello::sign(
        &alice,
        &bob.certificate,
        &bob_locator,
        "chat/1",
        v3_random_nonce(),
        NOW + 1,
        NOW + 61,
    ));

    assert!(
        hello
            .verify(
                &alice.certificate,
                &bob.certificate,
                &bob_locator,
                "chat/1",
                NOW + 1,
                false,
            )
            .is_ok()
    );
    assert_eq!(hello.claims.from_identity, alice.identity());
    assert_eq!(hello.claims.to_identity, bob.identity());
    assert_eq!(hello.claims.from_iroh_endpoint_id, alice.iroh_endpoint_id());
    assert_eq!(hello.claims.to_iroh_endpoint_id, bob.iroh_endpoint_id());
    assert_eq!(hello.claims.target_locator_digest, ok(bob_locator.digest()));

    let ack = ok(V3SignedAck::sign(
        &bob,
        &hello,
        &alice.certificate,
        &bob_locator,
        v3_random_nonce(),
        NOW + 2,
        NOW + 60,
    ));
    assert!(
        ack.verify(
            &bob.certificate,
            &alice.certificate,
            &hello,
            "chat/1",
            NOW + 2,
        )
        .is_ok()
    );
    assert_eq!(ack.claims.from_identity, bob.identity());
    assert_eq!(ack.claims.to_identity, alice.identity());
    assert_eq!(ack.claims.hello_digest, ok(hello.digest()));
    assert_eq!(ack.claims.session_nonce, hello.claims.session_nonce);
    assert_ne!(ack.claims.responder_nonce, ack.claims.session_nonce);
}

#[test]
fn hello_rejects_tamper_substitution_cross_identity_and_bad_bounds() {
    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let mallory_root = Keypair::random();
    let alice = credential(&alice_root, "alice");
    let bob = credential(&bob_root, "bob");
    let mallory = credential(&mallory_root, "mallory");
    let bob_locator = locator(&bob, 1);
    let hello = ok(V3SignedHello::sign(
        &alice,
        &bob.certificate,
        &bob_locator,
        "chat/1",
        v3_random_nonce(),
        NOW,
        NOW + 60,
    ));

    let mut tampered = hello.clone();
    tampered.claims.application = "files/1".to_owned();
    assert!(
        tampered
            .verify(
                &alice.certificate,
                &bob.certificate,
                &bob_locator,
                "files/1",
                NOW,
                false,
            )
            .is_err()
    );
    assert!(
        hello
            .verify(
                &mallory.certificate,
                &bob.certificate,
                &bob_locator,
                "chat/1",
                NOW,
                false,
            )
            .is_err()
    );

    let replacement_locator = locator(&bob, 2);
    assert!(matches!(
        hello.verify(
            &alice.certificate,
            &bob.certificate,
            &replacement_locator,
            "chat/1",
            NOW,
            false,
        ),
        Err(ProtocolError::DeviceMismatch)
    ));
    assert!(
        V3SignedHello::sign(
            &alice,
            &bob.certificate,
            &bob_locator,
            "chat/1",
            "short",
            NOW,
            NOW + 60,
        )
        .is_err()
    );
    assert!(
        V3SignedHello::sign(
            &alice,
            &bob.certificate,
            &bob_locator,
            "chat/1",
            v3_random_nonce(),
            NOW,
            NOW + V3_MAX_HANDSHAKE_LIFETIME_SECONDS + 1,
        )
        .is_err()
    );
    assert!(matches!(
        hello.verify(
            &alice.certificate,
            &bob.certificate,
            &bob_locator,
            "chat/1",
            NOW + 300,
            false,
        ),
        Err(ProtocolError::Expired)
    ));
}

#[test]
fn ack_rejects_nonce_endpoint_and_hello_substitution() {
    let alice_root = Keypair::random();
    let bob_root = Keypair::random();
    let mallory_root = Keypair::random();
    let alice = credential(&alice_root, "alice");
    let bob = credential(&bob_root, "bob");
    let mallory = credential(&mallory_root, "mallory");
    let bob_locator = locator(&bob, 1);
    let hello = ok(V3SignedHello::sign(
        &alice,
        &bob.certificate,
        &bob_locator,
        "chat/1",
        v3_random_nonce(),
        NOW,
        NOW + 60,
    ));

    assert!(
        V3SignedAck::sign(
            &bob,
            &hello,
            &alice.certificate,
            &bob_locator,
            hello.claims.session_nonce.clone(),
            NOW + 1,
            NOW + 59,
        )
        .is_err()
    );

    let mut ack = ok(V3SignedAck::sign(
        &bob,
        &hello,
        &alice.certificate,
        &bob_locator,
        v3_random_nonce(),
        NOW + 1,
        NOW + 59,
    ));
    ack.claims.to_iroh_endpoint_id = mallory.iroh_endpoint_id().to_owned();
    assert!(
        ack.verify(
            &bob.certificate,
            &alice.certificate,
            &hello,
            "chat/1",
            NOW + 1,
        )
        .is_err()
    );
}

#[test]
fn v3_json_rejects_unknown_fields_and_jcs_survives_field_reordering() {
    let root = Keypair::random();
    let device = credential(&root, "json-test");
    let locator = locator(&device, 1);
    let mut value = ok(serde_json::to_value(&locator));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("locator must be an object"))
        .insert("unsigned_extension".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<V3SignedLocator>(value).is_err());

    let encoded = ok(serde_json::to_string_pretty(&locator));
    let decoded: V3SignedLocator = ok(serde_json::from_str(&encoded));
    assert!(
        decoded
            .verify(
                &device.certificate,
                &root.public_key().z32(),
                NOW,
                false,
                None,
            )
            .is_ok()
    );
}
