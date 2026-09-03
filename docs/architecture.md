# Architecture and homeserver integration

This document specifies the deployed protocol v2 architecture. Protocol v3 is additive and removes
the custom rendezvous in favor of root-authorized device records and short-lived signed iroh
locators in Pubky public storage. See [v3.md](v3.md). Neither version requires a homeserver fork,
and clients must not silently downgrade between them.

## V2 decision

Use Pubky as the control and identity plane and iroh as the native data plane. Do not fork `pubky-homeserver` for protocol v2.

The existing homeserver already provides the durable operation this protocol needs: PKARR maps a Pubky key to a homeserver, and public storage serves a small root-signed descriptor. Real-time presence, consent, and encrypted address delivery belong in a stateless sidecar. NAT traversal and relay transport belong in the independently scalable official iroh relay.

This split avoids coupling long-lived sockets and high-bandwidth relaying to the homeserver release cycle. A homeserver operator can deploy all three services behind the same TLS/logging infrastructure, but users remain free to select another rendezvous or relay operator.

## Components

| Component | Responsibility | Trust received | Persistent state |
| --- | --- | --- | --- |
| PKARR | Locate the identity's current homeserver | Availability only | Existing signed packet |
| Pubky homeserver | Serve a signed rendezvous descriptor | Availability and storage integrity | One JSON file per identity |
| Rendezvous sidecar | Authenticate devices, route knocks, record consent, bind one responder, forward one ciphertext | Sees identities, device IDs, timing, application label, and signal kind | None in v2 |
| Official iroh relay | Admit registered endpoint IDs, assist discovery/hole punching, relay encrypted QUIC when necessary | Sees endpoint IDs, IPs, timing, and byte volume | Connection state only |
| Native client | Hold keys, enforce consent, decrypt coordinates, authenticate QUIC, frame application messages | Trusted endpoint | Device credential |

Authenticity does not come from DNS, the homeserver, the rendezvous, or the relay. The Pubky root signature authenticates both the descriptor and a short-lived device certificate. That certificate binds a dedicated iroh endpoint ID. Iroh's QUIC certificate proves possession of the corresponding secret key.

## Key separation

One device credential contains three independent online secrets:

- Ed25519 for signed rendezvous control frames;
- X25519 for recipient-specific HPKE address encryption;
- Ed25519 for iroh's QUIC endpoint identity.

The Pubky root key signs these public values and should remain offline except during device issuance and descriptor updates. Reusing the Pubky root or control-signing key as an iroh endpoint key would turn an online transport compromise into a broader identity compromise, so the implementation generates them independently.

## Connection lifecycle

1. B authenticates its rendezvous WebSocket, then starts its certified iroh endpoint and maintains the outbound relay connection. This order lets the relay authorize B's endpoint ID by calling the rendezvous; the registered Pubky device certificate supplies the binding.
2. A resolves B's `v2` descriptor through the normal Pubky SDK, verifies B's root signature and expiry, and connects to a listed rendezvous endpoint.
3. A registers its own root-delegated certificate. It then starts its iroh endpoint and receives the same relay admission as B.
4. A sends a signed knock containing the requested application and optional non-secret UI metadata. It contains no IP address, relay URL, or QUIC handshake.
5. The rendezvous fans the knock out only to B's currently connected matching devices. A rejecting device does not override another device; the first valid acceptance wins.
6. The selected B sends a signed acceptance, then exactly one HPKE-encrypted address signal. Its plaintext contains B's certified iroh endpoint ID, current relay URL, and direct socket addresses.
7. A verifies that the acceptance certificate, signal certificate, and decrypted endpoint ID are identical. Only then does A initiate iroh QUIC.
8. The QUIC handshake authenticates both endpoint IDs. A opens one bidirectional stream and sends a bounded hello naming the rendezvous session, both Pubky identity/device pairs, and the requested application. B accepts it only if it matches a locally pending accepted knock, then replies with an acknowledgement.
9. Iroh uses the relay as an immediately reachable encrypted path and probes direct UDP paths. QUIC migrates to a direct path when possible; otherwise the stream continues through the relay.

The rendezvous deletes the session immediately after forwarding the endpoint address or abort. Its bounded session-ID tombstone prevents recreation with a replayed knock.

## Relay admission

The supplied deployment uses iroh's official HTTP access-control callout instead of distributing a global client bearer token:

```text
iroh relay --X-Iroh-NodeId--> rendezvous internal endpoint
           <-- true only for an online, authenticated device --
```

The relay authenticates this internal request with `HPK_RELAY_AUTH_SECRET`. Keep the internal endpoint private at the network layer as well. Admission happens before peer consent because a receiver must already be reachable at the relay; peer addresses and data connections still do not happen until acceptance.

An operator may instead use iroh's allowlist, denylist, shared-token, or custom HTTP authorization modes. The client supports relay bearer tokens. Shared tokens are operationally simple but are not session-scoped and should not be embedded in Pubky descriptors.

## Comparison: pure iroh, custom traversal, and the hybrid

The selected design does use iroh, but only as its transport engine. “Pure iroh” here means giving peers an iroh `EndpointAddr` through an application-specific directory or iroh discovery without Pubky-root discovery and the consent rendezvous.

| Option | Advantages | Costs or missing properties |
| --- | --- | --- |
| Pure iroh | Least code; mature authenticated QUIC, relays, hole punching, path migration, port mapping, and address lookup | Does not by itself map a Pubky root to the intended device, publish through that identity's homeserver, hide B's address until explicit consent, or bind an application request to a Pubky session |
| Custom UDP + STUN/relay over Pubky | Full wire-format and infrastructure control; no iroh dependency | Must build and maintain NAT classification, simultaneous-open timing, retries, authenticated encryption, congestion control, path migration, TCP/TLS fallback, relay protocol, and years of edge-case interoperability |
| WebRTC + TURN over Pubky | Strong browser interoperability and standardized ICE/TURN ecosystem | Large SDP/ICE/DTLS/SCTP surface for native code, separate TURN credentials, awkward identity binding, and browser-shaped message/channel constraints |
| Chosen Pubky + consent + iroh | Keeps Pubky identity/homeserver semantics and delayed disclosure while reusing iroh's native transport, relay, and QUIC security | More control-plane code than pure iroh, a self-hosted iroh relay instead of generic TURN, upstream format/version dependency, and limited direct browser support |

The client disables iroh's n0 address lookup and configures only operator-selected relays, so Pubky remains the discovery authority. It also adds the stream hello/ack because possession of an iroh address proves a transport key, not the accepted Pubky session or requested application. This is the narrow layer that pure iroh would leave to the application.

## Why iroh instead of the former WebRTC data plane

For native-to-native applications, iroh removes the SDP/ICE/DTLS/SCTP state machine from this project and provides a smaller public API centered on endpoint keys and QUIC. Its relay gives a TCP/TLS-capable fallback, while multipath QUIC can migrate an established stream to direct UDP. QUIC also supports large streams and multiple future application streams without DataChannel's portable 16 KiB message constraint.

The tradeoffs are material:

- Iroh endpoint/address formats and relay protocol are an additional upstream dependency.
- Browser iroh endpoints currently use relay transport rather than direct browser hole punching. A browser-first product may still need WebRTC as a separate negotiated transport.
- An iroh relay is not TURN and cannot be substituted by generic TURN infrastructure.
- The relay sees connection metadata even though it cannot decrypt QUIC application bytes.

Protocol v2 therefore advertises `iroh-quic-v1` explicitly and rejects v1 credentials or WebRTC signals rather than attempting unsafe downgrade compatibility.

## Optional homeserver improvements

No upstream change is required. Future homeserver features could improve operations without changing the trust model:

- provision or rotate the descriptor during signup;
- advertise a recommended rendezvous origin;
- issue a signed device-revocation epoch checked by rendezvous nodes;
- let relay admission require an active homeserver account in addition to a valid root delegation;
- share account-level abuse limits and observability.

Cross-homeserver callers must not be required to create an account on B's homeserver merely to send a knock.

## Scaling and availability

The v2 rendezvous keeps presence and sessions in memory. A single instance is complete. Multiple instances need sticky WebSocket routing plus shared identity/session presence, or an authenticated message bus that routes only ciphertext and signed control objects. The relay authorization callback must consult the same shared presence view.

Scale relay bandwidth independently from rendezvous JSON traffic. Deploy multiple signed rendezvous endpoints for control-plane failover and configure multiple trusted relays on clients. A responder currently advertises the relay iroh selected as its home relay; clients should reconnect and repeat consent if all advertised coordinates become stale.
