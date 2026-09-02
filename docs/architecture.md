# Architecture and homeserver integration

## Decision

Do not fork `pubky-homeserver` for protocol v1. Run Hole Punchky as a sidecar and use the unmodified homeserver for exactly what Pubky already provides:

1. PKARR resolves a Pubky identity to its homeserver.
2. Public storage on that homeserver contains a root-signed rendezvous descriptor.
3. The descriptor points at one or more public Hole Punchky WebSocket services.

This keeps storage/account compatibility with upstream, lets users choose a different rendezvous operator, and avoids coupling real-time sockets and UDP relay operations to the homeserver release cycle. The sidecar may share DNS, TLS termination, logging, and deployment infrastructure with a homeserver.

## Components

| Component | Trust and responsibility | Persistent state |
| --- | --- | --- |
| PKARR | Resolves identity to current homeserver | Existing PKARR packet |
| Pubky homeserver | Serves the signed public descriptor | One JSON file per user |
| Rendezvous sidecar | Authenticates frames, asks for consent, binds two sockets, routes ciphertext | None in v1 |
| STUN | Reports server-reflexive UDP addresses | None |
| TURN/coturn | Relays packets when direct ICE fails | Short-lived allocation state |
| Client | Holds device keys, verifies the remote identity, encrypts signaling, runs ICE/DTLS/SCTP | Device credential |

The rendezvous service need not be operated by the target homeserver. Authenticity comes from the root signature in the descriptor and device certificates, not from trusting DNS or the rendezvous operator.

## Client lifecycle

Each receiving device maintains an outbound `wss://` connection to every rendezvous endpoint it wants to be reachable through. A 25-second default application heartbeat keeps the NAT mapping and proxy connection active without an inbound firewall rule. The current implementation keeps one endpoint connection per `RendezvousClient`; applications can connect to multiple descriptor endpoints for redundancy.

To dial B, A resolves B's descriptor through Pubky, verifies it against B's root public key, connects to the preferred endpoint, and registers its own signed device certificate. A does not need an account on B's homeserver or rendezvous service.

## Why WebRTC

WebRTC already supplies the difficult, interoperable pieces:

- ICE candidate gathering, prioritization, connectivity checks, and nomination.
- UDP hole punching with host and server-reflexive candidates.
- TURN fallback for symmetric NAT, carrier-grade NAT, and strict firewalls when UDP can reach the relay.
- DTLS peer transport authentication and encryption.
- SCTP reliable, ordered DataChannels with browser compatibility.

The application-level Pubky signatures bind the WebRTC offer and answer to the intended identities. DTLS then protects the established packet path. The native client gathers candidates before sending its encrypted offer/answer (non-trickle ICE); the wire protocol also defines encrypted candidate frames so browser or future native clients may trickle.

The current native WebRTC dependency implements TURN over UDP only. Browser clients can use the advertised TCP/TLS alternatives, but native TCP/TLS relay fallback requires upstream transport support or a separate implementation; blocking all UDP currently produces a bounded negotiation error.

## When an upstream homeserver change could help

None is required for interoperability. An optional upstream `pubky-connect-v1` capability could later improve ergonomics by:

- advertising a default sidecar URL from a homeserver information endpoint;
- provisioning the descriptor during signup;
- tying receiver registration to a homeserver session in addition to its root delegation;
- exposing a signed device-revocation epoch;
- sharing per-account abuse controls and observability.

These are optimizations. They must not make cross-homeserver callers obtain an account or bearer token from the receiver's homeserver.

## Availability and scaling

The v1 server keeps connections and sessions in memory. Multiple instances therefore require sticky routing by WebSocket connection and by target identity. A production multi-node version should place presence/session routing on an authenticated message bus (for example NATS) while keeping payloads opaque. Do not put unencrypted SDP or candidates into that bus.

TURN bandwidth is usually the dominant cost. Scale coturn independently and publish several TURN URLs. Rendezvous traffic is small JSON control data and can scale separately.
