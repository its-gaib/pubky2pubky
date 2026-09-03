# Hole Punchky protocol v2

This document is normative for v2. The Rust types in `hole-punchky-protocol` and the state machine in `hole-punchky-rendezvous` are the executable reference implementation.

Protocol v3 has separate storage paths, signing domains, credentials, and QUIC ALPN and is
documented in [v3.md](v3.md). A v3 failure must never trigger implicit v2 fallback.

## Conventions

- Identity and endpoint strings are bare, canonical 52-character z-base-32 Ed25519 public keys.
- Time fields are unsigned Unix seconds in UTC.
- Session IDs are canonical UUID strings generated with UUIDv4 entropy.
- Binary values are unpadded base64url.
- Signatures cover RFC 8785 JSON Canonicalization Scheme (JCS) bytes.
- A signable value is `JCS({"domain": DOMAIN, "payload": VALUE})`.
- Implementations reject unknown protocol versions. JSON decoders may ignore unknown object fields for forward compatibility within a version.
- Signed messages allow at most 120 seconds of clock skew. The reference server also caps each signed control validity window at 120 seconds.
- Protocol v2 is not wire-compatible with the former WebRTC protocol v1. There is no downgrade path.

## Cryptography and transport

| Purpose | Construction |
| --- | --- |
| Pubky root, control, and iroh keys | Independent Ed25519 keypairs |
| Signable representation | RFC 8785 JCS |
| Address encryption | RFC 9180 HPKE base mode |
| HPKE KEM | DHKEM(X25519, HKDF-SHA-256), `0x0020` |
| HPKE KDF | HKDF-SHA-256, `0x0001` |
| HPKE AEAD | ChaCha20-Poly1305, `0x0003` |
| HPKE `info` | `hole-punchky/hpke-signal/v2` |
| Peer transport | iroh 1.1 authenticated QUIC |
| QUIC ALPN | `hole-punchky/iroh/2` |
| Application framing | Four-byte unsigned big-endian length followed by bytes |

Root, control-signing, HPKE, and iroh secrets must not be derived from or reused as one another.

## Root-to-device delegation

The Pubky root signs these claims using domain `hole-punchky/device-certificate/v2`:

```json
{
  "version": 2,
  "identity": "<pubky-root-z32>",
  "device_id": "laptop",
  "signing_key": "<control-ed25519-z32>",
  "encryption_key": "<hpke-x25519-base64url>",
  "iroh_endpoint_id": "<iroh-ed25519-z32>",
  "issued_at": 1788360000,
  "expires_at": 1788446400,
  "capabilities": ["rendezvous", "signal", "iroh"]
}
```

The enclosing `DeviceCertificate` has `claims` and a root `signature`. The reference implementation permits at most a 90-day certificate lifetime. Operators should use shorter lifetimes and reissue a device after loss or suspected compromise.

An `Authenticated<T>` control frame contains `payload`, `certificate`, and a signature by `signing_key`. Its payload identity and device ID must match the certificate. Registration, knock, accept, and reject use distinct signing domains.

## Pubky discovery

B publishes a `RendezvousDescriptor` at:

```text
pubky://<root-z32>/pub/hole-punchky/v2/descriptor.json
```

Claims contain:

- `version: 2`;
- the root `identity`;
- one to eight `endpoints`, each with `signaling_url`, `priority`, and optional `region`;
- `transports`, which must include `iroh-quic-v1`;
- `expires_at`.

The root signature domain is `hole-punchky/rendezvous-descriptor/v2`. A client resolves the URI with the Pubky SDK, which performs PKARR homeserver discovery, and then independently verifies identity, signature, version, expiry, transport support, and URL policy. It tries endpoints by ascending priority.

Public signaling URLs must use `wss://`. The reference permits `ws://localhost` or a loopback literal only for explicit local development. Relay coordinates are deliberately absent from this public descriptor; B releases its current address only after consent.

## WebSocket registration

The path is `/v2/ws`; frames are UTF-8 JSON tagged with `type` and `data`. The first frame must be `register`, signed with domain `hole-punchky/register/v2`. It contains version, identity, device ID, a fresh 16-to-256-character nonce, issue time, and expiry.

The server verifies the root delegation and control signature before inserting presence. It binds the socket to the complete device certificate; later signed frames using another certificate are rejected even if the root identity and device label match. A tuple of identity, device ID, and nonce cannot be reused through its signed validity plus accepted clock skew.

The response is:

```json
{
  "type": "registered",
  "data": {
    "connection_id": "<uuid>",
    "session_ttl_seconds": 120,
    "transport": "iroh-quic-v1"
  }
}
```

Clients send application `ping` frames by default every 25 seconds; the server returns `pong`. Proxies must have a longer idle timeout.

## Consent and session binding

The initiator sends a signed `knock` using domain `hole-punchky/knock/v2`. It includes a new session UUID, B's identity, optional exact B device ID, requested application string, optional non-secret metadata, and validity times. It contains no IP address, relay URL, or QUIC traffic.

The server records exactly which connected B devices successfully received the fan-out. A later connection cannot claim the session. The first eligible signed `accept` atomically selects one responder and is forwarded to A; its domain is `hole-punchky/accept/v2`. Later acceptances receive `session_claimed`.

A signed `reject` uses domain `hole-punchky/reject/v2`. With fan-out, A receives a rejection only when every eligible device rejects. An acceptance by another device can still win.

Pending and accepted sessions expire after 120 seconds by default. The server retains a bounded session-ID tombstone long enough to reject replay of the original signed knock.

## Encrypted endpoint release

After acceptance, only the selected responder may send `iroh_endpoint`, at sequence zero. Either bound side may instead send `abort`, also at sequence zero. Any other direction, kind, sequence, sender, recipient, or session is rejected.

An `EncryptedSignal` exposes only:

- protocol version and session UUID;
- exact sender and recipient identity/device pairs;
- sequence, kind, issue time, and expiry;
- the sender device certificate;
- HPKE encapsulated key, ciphertext, and control-key signature.

The header JCS bytes are HPKE associated data. The device signs the complete opaque envelope with domain `hole-punchky/encrypted-signal/v2`. The rendezvous authenticates and routes it but cannot decrypt its payload.

For `iroh_endpoint`, the decrypted payload is:

```json
{
  "type": "iroh_endpoint",
  "endpoint": {
    "endpoint_id": "<responder-iroh-z32>",
    "relay_urls": ["https://relay.example.com/"],
    "direct_addresses": ["192.0.2.10:49152"]
  }
}
```

There may be at most eight relay URLs and 32 direct addresses, and at least one address is required. Relay schemes are HTTP or HTTPS at the wire-type layer; native production clients require HTTPS and allow HTTP only for an explicitly enabled loopback development host. Direct addresses cannot have port zero or an unspecified/multicast IP.

The recipient repeats envelope verification, HPKE decryption, kind validation, and address validation. `endpoint_id` must equal the sender certificate's `iroh_endpoint_id`. The accept and signal certificates must also be identical. Successful forwarding of an endpoint or abort ends the rendezvous session.

## Iroh QUIC binding

Each client constructs iroh using the `Minimal` preset, its certified dedicated secret, the fixed ALPN, no n0 address lookup, and only explicitly configured relays. Direct mode enables configured IP sockets and port mapping; relay-only mode removes all IP transports.

A dials B only after processing both acceptance and endpoint ciphertext. Iroh authenticates B's endpoint ID in the QUIC certificate. B continuously accepts the ALPN but exposes a connection to the application only after receiving this stream hello:

```json
{
  "version": 2,
  "session_id": "<accepted-uuid>",
  "from_identity": "<A-root-z32>",
  "from_device_id": "alice-laptop",
  "to_identity": "<B-root-z32>",
  "to_device_id": "bob-phone",
  "application": "example/1"
}
```

The JSON is length-prefixed and capped at 16 KiB. B requires a locally pending accepted session and exact matches for A's QUIC endpoint ID, both identity/device pairs, session, protocol version, and application. It atomically consumes that pending entry and responds with a length-prefixed `{"version":2,"session_id":"..."}` acknowledgement. A exposes the peer only after validating the acknowledgement.

This second binding prevents a valid iroh endpoint from substituting another accepted Pubky session or application. Unknown and replayed connections are closed.

Subsequent frames are opaque application bytes with a four-byte big-endian length. The reference cap is 16 MiB and is configurable downwards. Hole Punchky guarantees an authenticated reliable ordered byte-message channel but does not define application payload semantics, authorization, or flow control above QUIC.

## Relay access

The supplied deployment configures the official iroh relay's HTTP access mode. For each relay connection the pinned 1.1 binary posts an `X-Iroh-NodeId` hexadecimal key to `/internal/relay/authorize`. (Its documentation calls this `X-Iroh-Endpoint-Id`; the callback also accepts that spelling for forward compatibility and rejects conflicting duplicates.) The call is authenticated by a bearer secret shared only between relay and rendezvous. The rendezvous returns exactly `true` only if that endpoint ID belongs to a currently connected, successfully authenticated Pubky device.

This admission is not peer consent: it merely makes the device reachable at the relay. The target's address and any peer handshake remain blocked until accept. The internal endpoint must not be exposed through the public reverse proxy.

## Errors

WebSocket errors contain a stable `code`, safe `message`, and optional `session_id`. Codes are `bad_request`, `unauthorized`, `unavailable`, `session_not_found`, `session_claimed`, `rate_limited`, `too_large`, and `internal`.

Authentication, identity, endpoint binding, HPKE, or stream-hello failures are terminal for that session. A caller may retry `unavailable` against another signed rendezvous endpoint with a new UUID and fresh signed messages.
