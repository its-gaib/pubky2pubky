//! Version 4 Grant authorization, device publication, handshake, and currentness tests.

use std::fmt::Display;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hole_punchky_protocol::{
    ProtocolError, V4_CURRENTNESS_PATH_PREFIX, V4_DEVICE_RECORD_PATH_PREFIX, V4_IROH_ALPN,
    V4_IROH_ALPN_TEXT, V4_MAX_CURRENTNESS_LIFETIME_SECONDS,
    V4_MAX_DEVICE_CERTIFICATE_LIFETIME_SECONDS, V4_MAX_DEVICE_RECORD_BYTES,
    V4_MAX_GRANT_CAPABILITIES, V4_MAX_GRANT_JWS_BYTES, V4_MAX_GRANT_LIFETIME_SECONDS,
    V4_MAX_HANDSHAKE_LIFETIME_SECONDS, V4_MAX_LOCATOR_LIFETIME_SECONDS, V4_MAX_RELAY_URLS,
    V4_PROTOCOL_VERSION, V4_REQUIRED_STORAGE_SCOPE, V4CurrentnessRole, V4DeviceCredential,
    V4DeviceRecord, V4GrantAuthorization, V4SignedAck, V4SignedCurrentnessProof, V4SignedHello,
    V4SignedLocator, v4_currentness_path, v4_device_record_path, v4_random_challenge,
};
use pubky_common::{
    auth::{
        grant::GrantClaims,
        jws::{ClientId, GrantId},
    },
    capabilities::Capability,
    crypto::Keypair,
};
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

const NOW: u64 = 1_900_000_000;

fn ok<T, E: Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("unexpected error: {error}"))
}

fn url(value: &str) -> Url {
    ok(Url::parse(value))
}

fn client_id(value: &str) -> ClientId {
    ok(ClientId::new(value))
}

fn capability(value: &str) -> Capability {
    ok(value.parse())
}

fn grant_claims(
    root: &Keypair,
    cnf: &Keypair,
    caps: Vec<Capability>,
    issued_at: u64,
    expires_at: u64,
) -> GrantClaims {
    GrantClaims {
        iss: root.public_key(),
        client_id: client_id("chat.example"),
        caps,
        cnf: cnf.public_key(),
        jti: GrantId::generate(),
        iat: issued_at,
        exp: expires_at,
    }
}

fn authorization_with_window(
    root: &Keypair,
    cnf: &Keypair,
    issued_at: u64,
    expires_at: u64,
) -> V4GrantAuthorization {
    let claims = grant_claims(
        root,
        cnf,
        vec![capability("/pub/pubky2pubky/:rw")],
        issued_at,
        expires_at,
    );
    let jws = claims.sign(root, "pubky-grant");
    ok(V4GrantAuthorization::from_jws(
        jws,
        &root.public_key().z32(),
        NOW,
    ))
}

fn authorization(root: &Keypair, cnf: &Keypair) -> V4GrantAuthorization {
    authorization_with_window(root, cnf, NOW - 60, NOW + 86_400)
}

fn credential(root: &Keypair, cnf: &Keypair, device_id: &str) -> V4DeviceCredential {
    ok(V4DeviceCredential::issue(
        authorization(root, cnf),
        &root.public_key().z32(),
        cnf,
        device_id,
        NOW - 10,
        NOW + 7_200,
    ))
}

fn locator(credential: &V4DeviceCredential, sequence: u64) -> V4SignedLocator {
    ok(V4SignedLocator::sign(
        credential,
        vec![url("https://relay.example/")],
        v4_random_challenge(),
        sequence,
        NOW,
        NOW + 600,
    ))
}

fn record(credential: &V4DeviceCredential, sequence: u64) -> V4DeviceRecord {
    ok(V4DeviceRecord::new(
        credential,
        locator(credential, sequence),
        NOW,
        false,
    ))
}

fn signed_json_jws(root: &Keypair, header: &[u8], payload: &[u8]) -> String {
    let header = URL_SAFE_NO_PAD.encode(header);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let input = format!("{header}.{payload}");
    let signature = root.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn signed_claims_jws(root: &Keypair, claims: &impl Serialize) -> String {
    signed_json_jws(
        root,
        br#"{"alg":"EdDSA","typ":"pubky-grant"}"#,
        &ok(serde_json::to_vec(claims)),
    )
}

#[test]
fn constants_and_standard_pubky_grant_round_trip() {
    assert_eq!(V4_PROTOCOL_VERSION, 4);
    assert_eq!(V4_IROH_ALPN, b"pubky2pubky/iroh/v4");
    assert_eq!(V4_IROH_ALPN_TEXT, "pubky2pubky/iroh/v4");
    assert_eq!(V4_REQUIRED_STORAGE_SCOPE, "/pub/pubky2pubky/");
    assert_eq!(V4_DEVICE_RECORD_PATH_PREFIX, "/pub/pubky2pubky/v4/devices/");
    assert_eq!(
        V4_CURRENTNESS_PATH_PREFIX,
        "/pub/pubky2pubky/v4/currentness/"
    );

    let root = Keypair::random();
    let cnf = Keypair::random();
    let authorization = authorization(&root, &cnf);
    let claims = ok(authorization.verify(&root.public_key().z32(), NOW));
    assert_eq!(claims.iss, root.public_key());
    assert_eq!(claims.cnf, cnf.public_key());
    assert_eq!(claims.client_id.as_str(), "chat.example");
    assert_eq!(ok(authorization.digest()).len(), 43);
}

#[test]
fn grant_jws_requires_exact_canonical_header_payload_and_three_parts() {
    let root = Keypair::random();
    let cnf = Keypair::random();
    let claims = grant_claims(
        &root,
        &cnf,
        vec![capability("/pub/pubky2pubky/:w")],
        NOW - 10,
        NOW + 600,
    );
    let identity = root.public_key().z32();

    for header in [
        br#"{"typ":"pubky-grant","alg":"EdDSA"}"#.as_slice(),
        br#"{"alg":"EdDSA", "typ":"pubky-grant"}"#.as_slice(),
        br#"{"alg":"EdDSA","typ":"wrong"}"#.as_slice(),
        br#"{"alg":"HS256","typ":"pubky-grant"}"#.as_slice(),
        br#"{"alg":"EdDSA","typ":"pubky-grant","kid":"x"}"#.as_slice(),
    ] {
        let jws = signed_json_jws(&root, header, &ok(serde_json::to_vec(&claims)));
        assert!(V4GrantAuthorization::from_jws(jws, &identity, NOW).is_err());
    }

    let mut payload = ok(serde_json::to_value(&claims));
    payload
        .as_object_mut()
        .unwrap_or_else(|| panic!("Grant claims must encode as an object"))
        .insert("extra".to_owned(), json!(true));
    let jws = signed_claims_jws(&root, &payload);
    assert!(V4GrantAuthorization::from_jws(jws, &identity, NOW).is_err());

    let valid = claims.sign(&root, "pubky-grant");
    assert!(V4GrantAuthorization::from_jws(format!("{valid}.extra"), &identity, NOW).is_err());
    assert!(V4GrantAuthorization::from_jws("only.two", &identity, NOW).is_err());

    let mut segments: Vec<String> = valid.split('.').map(str::to_owned).collect();
    segments[0].push('=');
    assert!(V4GrantAuthorization::from_jws(segments.join("."), &identity, NOW).is_err());

    let oversized = "a".repeat(V4_MAX_GRANT_JWS_BYTES + 1);
    assert!(V4GrantAuthorization::from_jws(oversized, &identity, NOW).is_err());
}

#[test]
fn grant_rejects_tamper_wrong_signer_identity_and_bad_time() {
    let root = Keypair::random();
    let other = Keypair::random();
    let cnf = Keypair::random();
    let identity = root.public_key().z32();
    let claims = grant_claims(
        &root,
        &cnf,
        vec![capability("/pub/pubky2pubky/:rw")],
        NOW - 10,
        NOW + 600,
    );

    let wrong_signer = claims.sign(&other, "pubky-grant");
    assert!(matches!(
        V4GrantAuthorization::from_jws(wrong_signer, &identity, NOW),
        Err(ProtocolError::BadSignature)
    ));
    assert!(matches!(
        V4GrantAuthorization::from_jws(
            claims.sign(&root, "pubky-grant"),
            &other.public_key().z32(),
            NOW,
        ),
        Err(ProtocolError::IdentityMismatch)
    ));

    let mut tampered = claims.sign(&root, "pubky-grant");
    let replacement = if tampered.ends_with('A') { 'B' } else { 'A' };
    tampered.pop();
    tampered.push(replacement);
    assert!(V4GrantAuthorization::from_jws(tampered, &identity, NOW).is_err());

    let expired = grant_claims(
        &root,
        &cnf,
        vec![capability("/pub/pubky2pubky/:w")],
        NOW - 100,
        NOW,
    );
    assert!(matches!(
        V4GrantAuthorization::from_jws(expired.sign(&root, "pubky-grant"), &identity, NOW),
        Err(ProtocolError::Expired)
    ));
    let future = grant_claims(
        &root,
        &cnf,
        vec![capability("/pub/pubky2pubky/:w")],
        NOW + 121,
        NOW + 600,
    );
    assert!(matches!(
        V4GrantAuthorization::from_jws(future.sign(&root, "pubky-grant"), &identity, NOW),
        Err(ProtocolError::NotYetValid)
    ));
    let too_long = grant_claims(
        &root,
        &cnf,
        vec![capability("/pub/pubky2pubky/:w")],
        NOW,
        NOW + V4_MAX_GRANT_LIFETIME_SECONDS + 1,
    );
    assert!(
        V4GrantAuthorization::from_jws(too_long.sign(&root, "pubky-grant"), &identity, NOW,)
            .is_err()
    );
}

#[test]
fn grant_capability_and_count_policy_requires_covering_write() {
    let root = Keypair::random();
    let cnf = Keypair::random();
    let identity = root.public_key().z32();
    for caps in [
        vec![capability("/pub/pubky2pubky/:r")],
        vec![capability("/pub/pubky2pubky:w")],
        vec![capability("/pub/pubky2pubky-evil/:rw")],
        vec![capability("/pub/other/:rw")],
    ] {
        let claims = grant_claims(&root, &cnf, caps, NOW, NOW + 600);
        assert!(matches!(
            V4GrantAuthorization::from_jws(claims.sign(&root, "pubky-grant"), &identity, NOW,),
            Err(ProtocolError::MissingCapability(_))
        ));
    }

    for covering in ["/:w", "/:rw", "/pub/:w", "/pub/pubky2pubky/:w"] {
        let claims = grant_claims(&root, &cnf, vec![capability(covering)], NOW, NOW + 600);
        assert!(
            V4GrantAuthorization::from_jws(claims.sign(&root, "pubky-grant"), &identity, NOW,)
                .is_ok()
        );
    }

    let duplicate = grant_claims(
        &root,
        &cnf,
        vec![
            capability("/pub/pubky2pubky/:w"),
            capability("/pub/pubky2pubky/:w"),
        ],
        NOW,
        NOW + 600,
    );
    assert!(
        V4GrantAuthorization::from_jws(duplicate.sign(&root, "pubky-grant"), &identity, NOW,)
            .is_err()
    );

    let many = grant_claims(
        &root,
        &cnf,
        (0..=V4_MAX_GRANT_CAPABILITIES)
            .map(|index| capability(&format!("/pub/app-{index}/:w")))
            .chain(std::iter::once(capability("/pub/pubky2pubky/:w")))
            .collect(),
        NOW,
        NOW + 600,
    );
    assert!(
        V4GrantAuthorization::from_jws(many.sign(&root, "pubky-grant"), &identity, NOW,).is_err()
    );

    let mut bad_client = grant_claims(
        &root,
        &cnf,
        vec![capability("/pub/pubky2pubky/:w")],
        NOW,
        NOW + 600,
    );
    bad_client.client_id = client_id("bad\nclient");
    assert!(
        V4GrantAuthorization::from_jws(bad_client.sign(&root, "pubky-grant"), &identity, NOW,)
            .is_err()
    );
}

#[test]
fn device_certificate_supports_nonextractable_cnf_finalize_and_binds_everything() {
    let root = Keypair::random();
    let cnf = Keypair::random();
    let authorization = authorization(&root, &cnf);
    let identity = root.public_key().z32();
    let draft = ok(V4DeviceCredential::prepare(
        authorization.clone(),
        &identity,
        "browser",
        NOW,
        NOW + 3_600,
    ));
    assert_eq!(draft.certificate_claims().identity, identity);
    assert_eq!(
        draft.certificate_claims().grant_cnf_key,
        cnf.public_key().z32()
    );
    let signing_bytes = ok(draft.certificate_signing_bytes());
    let signature = cnf.sign(&signing_bytes);
    let credential = ok(draft.finalize(signature.to_bytes()));
    assert!(credential.verify(NOW).is_ok());
    assert_ne!(
        credential.control_signing_key(),
        credential.iroh_endpoint_id()
    );
    assert_ne!(credential.control_signing_key(), cnf.public_key().z32());
    assert_eq!(ok(credential.iroh_secret_key_bytes()).len(), 32);

    let bad_draft = ok(V4DeviceCredential::prepare(
        authorization,
        &identity,
        "browser-2",
        NOW,
        NOW + 3_600,
    ));
    let bad_signature = Keypair::random().sign(&ok(bad_draft.certificate_signing_bytes()));
    assert!(matches!(
        bad_draft.finalize(bad_signature.to_bytes()),
        Err(ProtocolError::BadSignature)
    ));

    let debug = format!("{credential:?}");
    let serialized = ok(serde_json::to_value(&credential));
    for field in ["control_signing_secret", "iroh_secret"] {
        let secret = serialized[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} must serialize as a string"));
        assert!(!debug.contains(secret));
    }
}

#[test]
fn certificate_rejects_wrong_cnf_tamper_and_lifetime_escape() {
    let root = Keypair::random();
    let cnf = Keypair::random();
    let wrong_cnf = Keypair::random();
    let identity = root.public_key().z32();
    let authorization = authorization_with_window(
        &root,
        &cnf,
        NOW - 60,
        NOW + V4_MAX_GRANT_LIFETIME_SECONDS - 60,
    );
    assert!(matches!(
        V4DeviceCredential::issue(
            authorization.clone(),
            &identity,
            &wrong_cnf,
            "wrong",
            NOW,
            NOW + 600,
        ),
        Err(ProtocolError::DeviceMismatch)
    ));
    assert!(
        V4DeviceCredential::prepare(
            authorization.clone(),
            &identity,
            "too-long",
            NOW,
            NOW + V4_MAX_DEVICE_CERTIFICATE_LIFETIME_SECONDS + 1,
        )
        .is_err()
    );
    assert!(
        V4DeviceCredential::prepare(authorization.clone(), &identity, "\n", NOW, NOW + 600,)
            .is_err()
    );

    let credential = ok(V4DeviceCredential::issue(
        authorization.clone(),
        &identity,
        &cnf,
        "desktop",
        NOW,
        NOW + 600,
    ));
    let mut certificate = credential.certificate.clone();
    certificate.claims.grant_jti.push('x');
    assert!(certificate.verify(&authorization, &identity, NOW).is_err());
    let mut certificate = credential.certificate.clone();
    certificate.claims.control_signing_key = Keypair::random().public_key().z32();
    assert!(matches!(
        certificate.verify(&authorization, &identity, NOW),
        Err(ProtocolError::BadSignature)
    ));
    assert!(matches!(
        credential
            .certificate
            .verify(&authorization, &Keypair::random().public_key().z32(), NOW),
        Err(ProtocolError::IdentityMismatch)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven policy test keeps all locator rejection cases together"
)]
fn locator_and_self_contained_device_record_enforce_relay_and_path_policy() {
    let root = Keypair::random();
    let cnf = Keypair::random();
    let device = credential(&root, &cnf, "desktop");
    let identity = root.public_key().z32();
    let locator = locator(&device, 7);
    let record = ok(V4DeviceRecord::new(&device, locator.clone(), NOW, false));
    assert!(record.verify(&identity, NOW, false, Some(7)).is_ok());
    assert!(matches!(
        record.verify(&identity, NOW, false, Some(8)),
        Err(ProtocolError::InvalidEncoding("v4 locator sequence"))
    ));
    assert_eq!(
        ok(record.path()),
        ok(v4_device_record_path(
            &device.certificate.claims.grant_cnf_key,
            device.control_signing_key(),
        ))
    );
    assert!(ok(record.path()).starts_with(V4_DEVICE_RECORD_PATH_PREFIX));
    assert!(!ok(record.path()).contains(device.device_id()));
    assert!(v4_device_record_path("../bad", device.control_signing_key()).is_err());

    let encoded = ok(serde_json::to_vec(&record));
    assert!(encoded.len() <= V4_MAX_DEVICE_RECORD_BYTES);
    assert!(V4DeviceRecord::decode_and_verify(&encoded, &identity, NOW, false, None).is_ok());
    let mut value = ok(serde_json::to_value(&record));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("record must be an object"))
        .insert("unknown".to_owned(), json!(true));
    assert!(serde_json::from_value::<V4DeviceRecord>(value).is_err());
    assert!(
        V4DeviceRecord::decode_and_verify(
            &vec![b' '; V4_MAX_DEVICE_RECORD_BYTES + 1],
            &identity,
            NOW,
            false,
            None,
        )
        .is_err()
    );

    let local = ok(V4SignedLocator::sign_for_local_development(
        &device,
        vec![url("http://127.0.0.1:3340/")],
        v4_random_challenge(),
        8,
        NOW,
        NOW + 60,
    ));
    assert!(
        local
            .verify(
                &device.authorization,
                &device.certificate,
                &identity,
                NOW,
                true,
                None,
            )
            .is_ok()
    );
    assert!(
        local
            .verify(
                &device.authorization,
                &device.certificate,
                &identity,
                NOW,
                false,
                None,
            )
            .is_err()
    );

    for invalid in [
        "http://relay.example/",
        "https://user@relay.example/",
        "https://relay.example/path",
        "https://relay.example/?query=yes",
        "https://relay.example/#fragment",
    ] {
        assert!(
            V4SignedLocator::sign(
                &device,
                vec![url(invalid)],
                v4_random_challenge(),
                9,
                NOW,
                NOW + 60,
            )
            .is_err()
        );
    }
    assert!(
        V4SignedLocator::sign(
            &device,
            vec![url("https://relay.example/"); V4_MAX_RELAY_URLS + 1],
            v4_random_challenge(),
            9,
            NOW,
            NOW + 60,
        )
        .is_err()
    );
    assert!(
        V4SignedLocator::sign(
            &device,
            vec![url("https://relay.example/"), url("https://relay.example/")],
            v4_random_challenge(),
            9,
            NOW,
            NOW + 60,
        )
        .is_err()
    );
    assert!(
        V4SignedLocator::sign(
            &device,
            vec![url("https://relay.example/")],
            "short",
            9,
            NOW,
            NOW + 60,
        )
        .is_err()
    );
    assert!(
        V4SignedLocator::sign(
            &device,
            vec![url("https://relay.example/")],
            v4_random_challenge(),
            9,
            NOW,
            NOW + V4_MAX_LOCATOR_LIFETIME_SECONDS + 1,
        )
        .is_err()
    );

    let mut tampered = locator;
    tampered.claims.relay_urls = vec![url("https://other.example/")];
    assert!(matches!(
        tampered.verify(
            &device.authorization,
            &device.certificate,
            &identity,
            NOW,
            false,
            None,
        ),
        Err(ProtocolError::BadSignature)
    ));
}

#[test]
fn hello_and_ack_bind_both_complete_grant_authorized_records() {
    let alice_root = Keypair::random();
    let alice_cnf = Keypair::random();
    let bob_root = Keypair::random();
    let bob_cnf = Keypair::random();
    let alice = credential(&alice_root, &alice_cnf, "alice-phone");
    let bob = credential(&bob_root, &bob_cnf, "bob-laptop");
    let alice_record = record(&alice, 3);
    let bob_record = record(&bob, 5);
    let hello = ok(V4SignedHello::sign(
        &alice,
        &alice_record,
        &bob_record,
        "chat/1",
        v4_random_challenge(),
        (NOW + 1, NOW + 61),
    ));
    assert!(
        hello
            .verify(&alice_record, &bob_record, "chat/1", NOW + 1, false,)
            .is_ok()
    );
    assert_eq!(hello.claims.from_device_record, alice_record);
    assert_eq!(hello.claims.to_identity, bob.identity());
    assert_eq!(
        hello.claims.target_device_record_digest,
        ok(bob_record.digest())
    );

    let ack = ok(V4SignedAck::sign(
        &bob,
        &hello,
        &alice_record,
        &bob_record,
        v4_random_challenge(),
        NOW + 2,
        NOW + 60,
    ));
    assert!(
        ack.verify(&bob_record, &alice_record, &hello, "chat/1", NOW + 2, false,)
            .is_ok()
    );
    assert_eq!(ack.claims.hello_digest, ok(hello.digest()));
    assert_eq!(
        ack.claims.responder_device_record_digest,
        ok(bob_record.digest())
    );
    assert_ne!(ack.claims.session_nonce, ack.claims.responder_nonce);

    assert!(
        V4SignedAck::sign(
            &bob,
            &hello,
            &alice_record,
            &bob_record,
            hello.claims.session_nonce.clone(),
            NOW + 2,
            NOW + 60,
        )
        .is_err()
    );

    let mut tampered_hello = hello.clone();
    tampered_hello.claims.application = "files/1".to_owned();
    assert!(
        tampered_hello
            .verify(&alice_record, &bob_record, "files/1", NOW + 1, false,)
            .is_err()
    );
    let replacement_bob = record(&bob, 6);
    assert!(
        hello
            .verify(&alice_record, &replacement_bob, "chat/1", NOW + 1, false,)
            .is_err()
    );
    let mut tampered_ack = ack;
    tampered_ack.claims.hello_digest = ok(replacement_bob.digest());
    assert!(
        tampered_ack
            .verify(&bob_record, &alice_record, &hello, "chat/1", NOW + 2, false,)
            .is_err()
    );

    assert!(
        V4SignedHello::sign(
            &alice,
            &alice_record,
            &bob_record,
            "chat/1",
            v4_random_challenge(),
            (NOW, NOW + V4_MAX_HANDSHAKE_LIFETIME_SECONDS + 1),
        )
        .is_err()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end mutual proof test keeps both roles and all bindings together"
)]
fn mutual_currentness_is_short_lived_hash_pathed_and_omits_peer_pubky() {
    let alice_root = Keypair::random();
    let alice_cnf = Keypair::random();
    let bob_root = Keypair::random();
    let bob_cnf = Keypair::random();
    let alice = credential(&alice_root, &alice_cnf, "alice");
    let bob = credential(&bob_root, &bob_cnf, "bob");
    let alice_record = record(&alice, 1);
    let bob_record = record(&bob, 1);
    let hello = ok(V4SignedHello::sign(
        &alice,
        &alice_record,
        &bob_record,
        "chat/1",
        v4_random_challenge(),
        (NOW, NOW + 90),
    ));
    let challenge = v4_random_challenge();
    let alice_proof = ok(V4SignedCurrentnessProof::sign(
        &alice,
        &alice_record,
        &bob_record,
        &hello,
        V4CurrentnessRole::Initiator,
        challenge.clone(),
        NOW + 1,
        NOW + 30,
        false,
    ));
    let bob_proof = ok(V4SignedCurrentnessProof::sign(
        &bob,
        &bob_record,
        &alice_record,
        &hello,
        V4CurrentnessRole::Responder,
        challenge.clone(),
        NOW + 1,
        NOW + 30,
        false,
    ));
    assert!(
        alice_proof
            .verify(
                &alice_record,
                &bob_record,
                &hello,
                V4CurrentnessRole::Initiator,
                &challenge,
                NOW + 1,
                false,
            )
            .is_ok()
    );
    assert!(
        bob_proof
            .verify(
                &bob_record,
                &alice_record,
                &hello,
                V4CurrentnessRole::Responder,
                &challenge,
                NOW + 1,
                false,
            )
            .is_ok()
    );
    let alice_path = ok(alice_proof.path());
    let bob_path = ok(bob_proof.path());
    assert_eq!(
        alice_path,
        ok(v4_currentness_path(
            V4CurrentnessRole::Initiator,
            &challenge,
            &ok(hello.digest()),
            &ok(alice_record.digest()),
            &ok(alice_record.authorization.digest()),
            &ok(alice_record.locator.digest()),
        ))
    );
    assert!(alice_path.starts_with(V4_CURRENTNESS_PATH_PREFIX));
    assert!(bob_path.starts_with(V4_CURRENTNESS_PATH_PREFIX));
    assert_ne!(alice_path, bob_path);
    let alice_json = ok(serde_json::to_string(&alice_proof));
    let bob_json = ok(serde_json::to_string(&bob_proof));
    assert!(!alice_json.contains(bob.identity()));
    assert!(!bob_json.contains(alice.identity()));
    assert_eq!(alice_proof.claims.hello_digest, ok(hello.digest()));
    assert_eq!(
        alice_proof.claims.device_record_digest,
        ok(alice_record.digest())
    );
    assert_eq!(
        alice_proof.claims.grant_digest,
        ok(alice_record.authorization.digest())
    );
    assert_eq!(
        alice_proof.claims.locator_digest,
        ok(alice_record.locator.digest())
    );

    assert!(
        alice_proof
            .verify(
                &alice_record,
                &bob_record,
                &hello,
                V4CurrentnessRole::Responder,
                &challenge,
                NOW + 1,
                false,
            )
            .is_err()
    );
    assert!(
        alice_proof
            .verify(
                &alice_record,
                &bob_record,
                &hello,
                V4CurrentnessRole::Initiator,
                &v4_random_challenge(),
                NOW + 1,
                false,
            )
            .is_err()
    );
    assert!(matches!(
        alice_proof.verify(
            &alice_record,
            &bob_record,
            &hello,
            V4CurrentnessRole::Initiator,
            &challenge,
            NOW + 30,
            false,
        ),
        Err(ProtocolError::Expired)
    ));

    let future_proof = ok(V4SignedCurrentnessProof::sign(
        &alice,
        &alice_record,
        &bob_record,
        &hello,
        V4CurrentnessRole::Initiator,
        v4_random_challenge(),
        NOW + 60,
        NOW + 89,
        false,
    ));
    assert!(matches!(
        future_proof.verify(
            &alice_record,
            &bob_record,
            &hello,
            V4CurrentnessRole::Initiator,
            &future_proof.claims.challenge,
            NOW,
            false,
        ),
        Err(ProtocolError::NotYetValid)
    ));

    assert!(
        V4SignedCurrentnessProof::sign(
            &alice,
            &alice_record,
            &bob_record,
            &hello,
            V4CurrentnessRole::Initiator,
            v4_random_challenge(),
            NOW + 1,
            NOW + 1 + V4_MAX_CURRENTNESS_LIFETIME_SECONDS + 1,
            false,
        )
        .is_err()
    );
    assert!(
        V4SignedCurrentnessProof::sign(
            &alice,
            &alice_record,
            &bob_record,
            &hello,
            V4CurrentnessRole::Initiator,
            hello.claims.session_nonce.clone(),
            NOW + 1,
            NOW + 20,
            false,
        )
        .is_err()
    );

    let mut tampered = bob_proof;
    tampered.claims.locator_digest = ok(alice_record.locator.digest());
    assert!(
        tampered
            .verify(
                &bob_record,
                &alice_record,
                &hello,
                V4CurrentnessRole::Responder,
                &challenge,
                NOW + 1,
                false,
            )
            .is_err()
    );
}

#[test]
fn v4_json_rejects_unknown_fields_at_nested_signed_boundaries() {
    let root = Keypair::random();
    let cnf = Keypair::random();
    let device = credential(&root, &cnf, "json");
    let locator = locator(&device, 1);

    let mut value = ok(serde_json::to_value(&locator));
    value["claims"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("claims must be an object"))
        .insert("direct_addresses".to_owned(), Value::Array(Vec::new()));
    assert!(serde_json::from_value::<V4SignedLocator>(value).is_err());

    let device_record = record(&device, 1);
    let other_root = Keypair::random();
    let other_cnf = Keypair::random();
    let other = credential(&other_root, &other_cnf, "other");
    let other_record = record(&other, 1);
    let hello = ok(V4SignedHello::sign(
        &device,
        &device_record,
        &other_record,
        "chat/1",
        v4_random_challenge(),
        (NOW, NOW + 60),
    ));
    let mut value = ok(serde_json::to_value(&hello));
    value["claims"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("claims must be an object"))
        .insert("extension".to_owned(), json!(true));
    assert!(serde_json::from_value::<V4SignedHello>(value).is_err());
}
