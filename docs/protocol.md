# Hole Punchky protocol v1

This document is normative for v1. The Rust types in `hole-punchky-protocol` are the executable reference implementation.

## Conventions

- Identity strings are bare 52-character z-base-32 Pubky/PKARR Ed25519 public keys.
- Time fields are unsigned Unix seconds in UTC.
- UUIDs are canonical lowercase UUID strings.
- Binary values are unpadded base64url, except TURN REST passwords, which use padded standard base64 as required by coturn.
- JSON signatures use RFC 8785 JSON Canonicalization Scheme (JCS).
- The signable bytes are the JCS encoding of `{"domain": DOMAIN, "payload": VALUE}`.
- Implementations must reject unknown protocol versions. JSON decoders may ignore unknown object fields for forward compatibility.
- Signed control objects are accepted with at most 120 seconds of clock skew. The reference server additionally limits each control object's validity window to 120 seconds.

## Cryptographic suites

| Purpose | Suite |
| --- | --- |
| Pubky root and device signatures | Ed25519 |
| Signable representation | RFC 8785 JCS |
| Signaling encryption | RFC 9180 HPKE base mode |
| HPKE KEM | DHKEM(X25519, HKDF-SHA-256), `0x0020` |
| HPKE KDF | HKDF-SHA-256, `0x0001` |
| HPKE AEAD | ChaCha20-Poly1305, `0x0003` |
| HPKE `info` | UTF-8 `hole-punchky/hpke-signal/v1` |

Ed25519 and X25519 keys are generated independently. Converting or reusing a Pubky Ed25519 secret as an X25519 key is not permitted.

## Root-to-device delegation

Applications should not keep the Pubky root key in a long-running network process. The root signs a `DeviceCertificateClaims` object:

```json
{
  "version": 1,
  "identity": "<root-z32>",
  "device_id": "laptop",
  "signing_key": "<device-ed25519-z32>",
  "encryption_key": "<device-x25519-base64url>",
  "issued_at": 1788360000,
  "expires_at": 1788446400,
  "capabilities": ["rendezvous", "signal"]
}
```

The enclosing certificate has `claims` and `signature`. Its signature domain is `hole-punchky/device-certificate/v1`. The reference implementation accepts a maximum certificate lifetime of 90 days; deployments should issue much shorter credentials where root-key access permits.

Every authenticated control object has:

```json
{
  "payload": { "...": "message-specific claims" },
  "certificate": { "claims": {}, "signature": "..." },
  "signature": "<device signature>"
}
```

The device signature uses the message-specific domain. The payload identity and device id must equal the certificate claims.

## Pubky discovery

The target publishes JSON at `/pub/hole-punchky/v1/descriptor.json`. The complete Pubky URI is:

```text
pubky://<root-z32>/pub/hole-punchky/v1/descriptor.json
```

Claims contain `version`, `identity`, `endpoints`, and `expires_at`. Each endpoint has `signaling_url`, numeric `priority` (lower wins), and optional `region`. The root-signature domain is `hole-punchky/rendezvous-descriptor/v1`.

Clients must:

1. resolve the URI through the standard Pubky SDK (thereby using PKARR homeserver discovery);
2. require `claims.identity` to equal the requested key;
3. verify the root signature and expiry;
4. require `wss://`, except explicit loopback development;
5. try endpoints in ascending priority order.

The record is root-signed even though Pubky storage already authenticates the account. This permits caching/mirroring without inheriting transport trust.

## WebSocket transport

The endpoint path is `/v1/ws`. Frames are UTF-8 JSON. The default maximum message is 65,536 bytes. A frame is an externally tagged object with `type` and `data`, for example:

```json
{"type":"ping","data":{"nonce":"abc"}}
```

The first frame must be `register`. Its payload includes `version`, `identity`, `device_id`, a fresh nonce, `issued_at`, and `expires_at`. Its signing domain is `hole-punchky/register/v1`. A registration nonce cannot be reused during its validity period.

The server answers `registered` with a connection UUID, public STUN configuration, and the session TTL. TURN credentials are never included before consent.

An idle native client sends an application `ping` on its authenticated socket every 25 seconds by default; the server answers `pong`. Deployments should keep their proxy idle timeout above this interval. Implementations may choose another non-zero interval appropriate to their network.

## Consent and session binding

The initiator chooses a random UUIDv4 session id and sends `knock`. A knock contains no SDP, IP address, or ICE candidate. It contains the target identity, optional target device id, application protocol, and optional non-secret metadata. Domain: `hole-punchky/knock/v1`.

The rendezvous server fans a valid knock out to all matching online devices. Only device connections to which that knock was successfully queued may answer; a device that connects later cannot guess and claim the session UUID. The first valid `accept` atomically binds that exact responder connection to the session. Later accepts receive `session_claimed`. Domain: `hole-punchky/accept/v1`.

A target can send `reject` with a reason. Domain: `hole-punchky/reject/v1`. For a fan-out knock, the server reports rejection to the initiator only after every device that received the knock has rejected; one rejection does not prevent another target device from accepting. For an exact-device knock, rejection terminates the session.

The server enforces a two-minute default session TTL and deletes sessions when a bound socket disconnects. It retains a bounded session-ID tombstone through the signed knock's clock-skew acceptance window, so an ended session cannot be recreated by replaying its original knock.

## Encrypted signaling

After acceptance, each side knows the other's root-signed device certificate. An `EncryptedSignal` has a public header, sender certificate, HPKE encapsulated key, ciphertext, and device signature.

The public header contains:

- version and session UUID;
- exact sender and recipient identity/device pairs;
- a strictly increasing sequence beginning at zero independently in each direction;
- kind: `offer`, `answer`, `candidate`, `end_of_candidates`, or `abort`;
- issued and expiry times.

The JCS header bytes are HPKE associated data. The plaintext is one `SignalPayload`. The device signs a structure containing the header, encoded encapsulated key, and encoded ciphertext with domain `hole-punchky/encrypted-signal/v1`.

The rendezvous verifies the certificate, signature, bound sender/recipient, sequence, expiry, and negotiation order. It cannot decrypt the payload. The recipient repeats every verification before HPKE decryption and checks that the plaintext variant agrees with the public `kind`.

Allowed order is:

1. initiator `offer` at sequence 0;
2. responder `answer` at sequence 0;
3. either side may send candidates/end markers after its own description;
4. either side may abort.

The reference native client places gathered candidates inside encrypted SDP, so only offer and answer are normally emitted.

## TURN fallback

After a session is accepted, either bound peer may send a signed `request_turn_credentials` (domain `hole-punchky/turn-request/v1`). The server creates a short-lived coturn REST username:

```text
<expiry-unix>:<identity>:<session-uuid>
```

The credential is `base64(HMAC-SHA1(static-auth-secret, username))`. Default validity is five minutes. The response includes the session id to disambiguate concurrent negotiations.

TURN-only ICE is a privacy mode. Normal ICE includes host, server-reflexive, and relay candidates; it prefers a direct pair and automatically falls back to TURN.

## Server errors

Errors contain a stable `code`, safe `message`, and optional `session_id`. Codes are `bad_request`, `unauthorized`, `unavailable`, `session_not_found`, `session_claimed`, `rate_limited`, `too_large`, `turn_unavailable`, and `internal`.

Clients must treat authentication, identity, sequence, and HPKE failures as terminal for that session. They may retry `unavailable` with endpoint backoff and a new session UUID.

## Application data

After ICE nomination, WebRTC authenticates and encrypts the path with DTLS and carries reliable ordered messages over SCTP. Hole Punchky does not define application payloads. Applications identify their protocol in the knock and should add their own versioning, authorization, and flow control. The reference wrapper caps individual messages at 16 KiB for portable DataChannel interoperability.
