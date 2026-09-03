# Threat model

## Scope and security goals

Hole Punchky v2 aims to provide these properties:

- asking for Pubky identity B can yield a connection only to a device delegated by B's root key;
- B's device makes an explicit consent decision before its relay URL or direct socket addresses are disclosed to A;
- the rendezvous can authenticate and route a session but cannot decrypt the endpoint address or QUIC application data;
- the relay can forward QUIC but cannot impersonate either endpoint or decrypt application data;
- identities, device IDs, application label, session UUID, responder choice, and both iroh endpoint keys are bound again inside authenticated QUIC;
- replayed registration, knock, acceptance, address signal, or stream hello cannot create a second valid session within retained state;
- inputs and in-memory state have explicit size, time, and cardinality bounds.

Availability, anonymity, proof of personhood, offline messaging, content semantics, group membership, and guaranteed direct connectivity are not goals. The receiver or its application must decide whether an authenticated Pubky identity is authorized for the requested application.

## Trust boundaries

The Pubky root secret and local device credential are trusted endpoint secrets. The root is used to sign device delegations and rendezvous descriptors; it does not participate in online QUIC. Each device independently generates a control-signing key, HPKE key, and iroh endpoint key.

The following implementations are in the trusted computing base for confidentiality and authenticity:

- Pubky/PKARR public-key parsing and signature verification;
- Ed25519, X25519, HPKE, JCS, TLS, QUIC, and random-number crates in the locked Rust graph;
- iroh's endpoint, NAT traversal, relay client, and QUIC certificate implementation;
- the local application that decides consent and handles the resulting `Peer`.

DNS, the Pubky homeserver, rendezvous, reverse proxy, and relay are trusted for some degree of availability. None is an authority for B's root identity. Public TLS protects transport metadata and bearer credentials on their respective hops, while root/device signatures and QUIC keys provide end-to-end peer authenticity.

## Discovery and homeserver attacker

A malicious PKARR participant, homeserver, cache, or network intermediary can suppress, delay, replay, or replace the descriptor response. A replacement or cross-identity descriptor fails the Pubky root signature; an expired descriptor fails local time validation. The client then fails closed or tries another endpoint that was already present in the same signed descriptor.

The homeserver sees descriptor access, IP addresses, account activity, and the fact that an identity uses Hole Punchky. The descriptor itself is public and reveals rendezvous operator choices and expiry. It deliberately contains no device key, current IP address, relay URL, presence, or peer relationship.

A signed descriptor URL is controlled by the target identity, not globally vouched for. Dialing an arbitrary identity causes outbound WSS connections. Applications running in sensitive networks should enforce an egress/host policy in addition to signature validation so federation discovery cannot become an internal-network probe. The reference client requires WSS except for an explicit loopback development case.

## Malicious rendezvous

The rendezvous observes both Pubky identities, device IDs, root-signed certificates, certified iroh endpoint IDs, online presence, source IPs, requested application, optional knock metadata, timing, session UUIDs, accept/reject choice, signal kind, and ciphertext length. It can correlate callers and receivers. Hole Punchky is not an anonymity system.

The rendezvous can drop, delay, reorder, selectively route, deny, or falsely report availability. It can refuse to forward an acceptance or ciphertext and cause a timeout. It cannot produce a valid root delegation, signed acceptance, HPKE plaintext, iroh QUIC certificate, or session hello for an uncompromised device.

Signed headers and HPKE associated data prevent the service from changing sender, recipient, device, session, sequence, kind, or validity without detection. Each WebSocket is bound to the exact certificate used at registration, not only its root identity and device label. The server independently enforces that only the selected responder can send the one sequence-zero endpoint signal. The initiator independently requires the same certificate on acceptance and signal, and the decrypted endpoint ID must equal that certificate.

The rendezvous could collude with a relay to map Pubky identities to relay connections. In the supplied deployment that mapping is already inferable because the authorization callback checks the certified endpoint ID. Address encryption protects coordinates from a separately operated honest-but-curious rendezvous; it does not hide the target's network address from a relay carrying its traffic or from the accepted peer.

## Malicious or compromised relay

An iroh relay observes endpoint IDs, client IP addresses, connection timing, destinations within that relay, traffic volume, and encrypted packet sizes. It may drop, delay, reorder, throttle, or retain packets. It cannot authenticate as a peer because iroh QUIC verifies possession of the certified endpoint key, and it cannot read or modify authenticated QUIC application bytes without detection.

Relay admission is an abuse-control gate, not peer consent. A device is admitted after its signed WebSocket registration so it can be reachable before a knock. The target's relay coordinate remains HPKE-encrypted until acceptance, and the QUIC stream hello must match an accepted local session.

The official relay's HTTP callback is authenticated with a machine-to-machine bearer secret and should also be network-private. Secret compromise enables unauthorized membership queries against an exposed callback and disrupts admission policy; rotate it on both services and close public access. It does not reveal device private keys or decrypt QUIC. The callback returns only `true` or `false` and uses constant-time secret comparison.

Admission is evaluated at relay-connection time. It is not continuous revocation: a relay connection established while its device WebSocket was valid may remain alive after that WebSocket disappears. It still cannot generate a fresh receiver acceptance, and session state expires. Operators needing immediate relay disconnection must add an authenticated revocation channel to the relay.

Relay-only mode hides direct socket addresses from the peer and local path observers beyond the relay, but it gives the relay all traffic metadata and costs bandwidth/latency. Direct mode reveals the selected public and possibly local interface addresses to the accepted peer.

## Malicious peer

Any party can create Pubky identities cheaply and send knocks unless the deployment/application adds an allowlist. A signature proves key control, not a human identity or benign intent. Non-secret knock metadata and application names must be treated as attacker-controlled input before consent.

Before consent, a caller may infer online status from delivery outcome or timing. Multi-device fan-out also lets the rendezvous observe how many devices are reachable. Uniform external errors, randomized response timing, application allowlists, edge IP controls, and conservative rate limits can reduce enumeration but cannot eliminate it.

After consent, A learns B's iroh endpoint ID and current relay/direct coordinates and can send QUIC connection attempts. B accepts only the expected remote iroh key and a single locally pending session/application binding. Unknown, mismatched, and replayed hellos are closed. Consent for one application is not authorization for another, and applications should add their own capability or user policy after connection.

The reference `Peer` provides bounded length-prefixed messages over one reliable ordered QUIC stream. A connected peer can still send slowly, stop reading, send semantically malicious data, or consume the configured 16 MiB maximum repeatedly. Applications need concurrency, rate, idle, aggregate-memory, and schema limits appropriate to their payloads.

## Compromised endpoint

A stolen device credential contains all three online secrets and allows that device to sign rendezvous frames, decrypt endpoint signals addressed to it, and authenticate as its iroh endpoint until the root-signed certificate expires. It does not expose the Pubky root or another device because keys are independently random.

V2 has no online device-revocation list. Use short certificate lifetimes, OS-backed key storage, minimal file permissions, and replacement credentials after loss. A future root-signed device epoch/revocation document in Pubky storage could reduce this window. Deleting a descriptor or disabling an account improves availability control but is not cryptographic revocation of an already-issued device certificate.

Root-key compromise is identity compromise: the attacker can issue arbitrary device certificates and descriptors. Move the root offline, minimize its use, and migrate to a new Pubky identity if it is exposed.

System clock manipulation can cause valid messages to be rejected or extend local acceptance within the fixed skew. Use authenticated time synchronization and alert on clock jumps. Random-number failure threatens every generated key, nonce, and UUID and belongs in the platform threat model.

## Denial of service and availability

No hole-punching protocol can promise a direct path. Endpoint-dependent/symmetric NAT, carrier policy, captive portals, or firewalls may prevent direct UDP. The iroh relay provides a TLS/WebSocket-style fallback on networks that permit outbound HTTPS; a network or proxy can still block that protocol. Every phase has bounded timeouts and should surface failure rather than hang.

The in-memory rendezvous bounds frame size, auth windows, identities per connection, global connections, active/tombstoned sessions, registration nonces, and knocks per identity. These do not replace a production edge because attackers can generate identities and consume TLS/WebSocket handshakes before authentication. Add per-source and global limits, DDoS protection, relay connection/bandwidth quotas, and capacity alerts.

The relay authorization callback depends on rendezvous availability. If it is down, slow, or has a mismatched secret, new relay connections fail closed. Existing direct paths and already-authorized relay sockets may continue. A rendezvous restart intentionally loses presence and sessions; clients must reconnect with fresh nonces and repeat consent.

Multiple rendezvous replicas require consistent atomic first-accept and replay state. A split-brain deployment could select two responder devices even though each signature remains valid. Do not load-balance v2 arbitrarily without sticky routing and a shared state design.

## Privacy summary

| Observer | Learns before consent | Learns after consent |
| --- | --- | --- |
| Homeserver/PKARR path | Descriptor reads and public rendezvous choices | No additional protocol plaintext |
| Rendezvous | Identities/devices, certified endpoint IDs, presence, app label, timing, consent result, ciphertext size | Connection timing; not endpoint coordinates or application bytes |
| Relay | Registered endpoint ID, source IP, timing | Both relayed endpoint IDs/IPs, byte counts, encrypted QUIC |
| Initiating peer | Signed target identity and consent outcome | Target device, endpoint/relay addresses, application data |
| Passive local/WAN observer | Service IPs, timing, sizes; TLS/QUIC ciphertext | Direct peer IP when selected, or relay traffic pattern |

Padding, cover traffic, rotating unlinkable transport keys, oblivious rendezvous, Tor, or mixnets would be separate privacy layers. Stable certified endpoint IDs are intentionally linkable for device authentication during their certificate lifetime.

## Dependency review

Run `cargo audit` against every lockfile change and before release. Treat informational unmaintained/unsound advisories separately from remotely exploitable vulnerabilities, document the exact transitive path and reachable preconditions, and upgrade promptly when the Pubky or iroh dependency graph permits it. Also review the pinned official relay release notes and artifact checksums; Cargo auditing does not cover the downloaded relay binary or container base image.

On 2026-09-03, `cargo audit` reported no vulnerability-class advisories and three allowed warnings:

- `RUSTSEC-2026-0253` affects `lru` 0.16.4 through `pubky`/`pkarr`/`mainline`. It requires `LruCache::pop()`, unwinding, and a key whose `Drop` can panic. Mainline 8.0.0 does not call `pop()` and uses a copyable byte-array ID as its cache key, so the known trigger is not reachable here. Upgrade when that dependency moves to a fixed `lru`.
- `RUSTSEC-2024-0436` marks `paste` 1.0.15 unmaintained. It is a compile-time procedural macro reached through iroh's Linux `netwatch`/netlink dependencies and is not runtime code in the produced binary.
- `RUSTSEC-2023-0089` marks `atomic-polyfill` 1.0.3 unmaintained. It is reached through `postcard`/`heapless` for targets without native pointer-width atomics and is not selected in the x86_64 Linux build.

These are accepted observations, not blanket audit ignores: CI leaves the audit output visible so a severity or dependency-path change must be reviewed.
