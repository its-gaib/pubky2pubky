# Threat model

## Security goals

- A peer that asks for Pubky identity B connects only to a device delegated by B's root key.
- A rendezvous operator cannot read SDP, ICE candidates, or post-connection application data.
- A target reveals network candidates only after one of its devices explicitly accepts.
- Replayed registrations and signaling frames are rejected within the server's state window.
- A caller cannot redirect a bound session to another identity, device, or WebSocket.
- TURN credentials are short-lived, session-gated, and do not expose the coturn shared secret.

## Trusted inputs

The local device credential and Pubky root secret are trusted. The root secret is used only to issue a device certificate and sign the public descriptor. PKARR and homeserver lookup may be observed or disrupted, but a modified descriptor fails its root signature.

WebRTC's DTLS/ICE implementation and the cryptographic crates are part of the trusted computing base. coturn sees relayed packet metadata and encrypted DTLS datagrams.

## Malicious rendezvous

A malicious service can observe identities, device ids, online presence, knock timing, application labels, ciphertext sizes, TURN requests, and connection timing. It can drop, delay, reorder, or deny traffic. It cannot forge a valid device acceptance or decrypt signaling without a recipient device secret.

It can correlate A and B. This design does not provide rendezvous anonymity. Padding, oblivious relays, or Tor would be separate layers.

The service is prevented from changing recipient routing by signed headers and HPKE associated data. It cannot silently force local TURN use: the client reports its nominated local path, though the service may block direct signaling/connectivity and cause a visible failure or relay selection.

## Malicious peer

Any Pubky identity may knock unless an application applies an allowlist. A valid identity proves control of a key, not a real-world identity or benevolent intent. The receiver must apply application authorization after inspecting the signed caller identity.

Before consent, a caller learns that an identity has at least one reachable device only through success/timing. Deployments can deliberately return uniform errors to reduce enumeration. The reference service rate-limits knocks per identity, bounds connections and frames, and expires state. A public service still needs edge IP limits and DDoS protection because attackers can create unlimited Pubky keys.

A descriptor is signed by the target, not vouched for as a generally trusted URL. Dialing it causes an outbound WSS request. Applications that accept arbitrary target identities should also enforce an endpoint/egress policy appropriate to their environment to avoid turning federation discovery into an internal-network probe.

After consent, direct ICE reveals the selected IP addresses to the peer. Use `RelayOnly` to hide direct addresses behind TURN.

## Compromised device

A stolen device credential permits impersonation until its certificate expires. v1 has no online certificate-revocation check. Issue short-lived credentials, protect files with OS keystores/permissions, and rotate the root-signed credential after loss. A future signed device epoch in Pubky storage can provide immediate revocation without changing the transport.

Compromise of one device key does not reveal the Pubky root secret or another device's HPKE secret because keys are generated independently.

## Compromised TURN

TURN sees both public endpoints, allocation timing, and byte counts, but only forwards DTLS-encrypted packets. A stolen TURN shared secret allows arbitrary relay credential minting and bandwidth theft, not Pubky identity forgery. Rotate it, limit allocation quotas, and never publish it in a descriptor or client binary.

## Denial of service

No NAT traversal system can guarantee a direct connection. Symmetric NAT, endpoint-dependent filtering, or enterprise policy may require TURN; some networks block that too. The v1 native client reaches TURN over UDP, so a network that blocks all UDP produces a bounded failure (browser implementations may use TCP/TLS TURN). The API exposes timeouts and explicit failure.

The in-memory v1 rendezvous is not by itself a complete DDoS perimeter. Production deployments should add:

- TLS termination and per-source connection/request limits at the edge;
- global and per-identity quotas backed by shared storage for multi-node deployments;
- coturn per-user/realm quotas and bandwidth capacity alerts;
- metrics alerts on authentication failures, rate limits, session counts, and relay bandwidth;
- bounded logs that never include full signed frames, SDP, candidates, secrets, or TURN passwords.

## Residual metadata and non-goals

Hole Punchky is not an anonymity network, proof-of-personhood system, content protocol, offline message queue, or guaranteed traversal mechanism. It provides authenticated rendezvous and the best available ICE path between online devices.

## Dependency audit baseline

On 2026-09-02, `cargo audit` found no vulnerability-class advisories in the locked dependency graph. It reported two upstream informational warnings that cannot currently be removed by upgrading Pubky's published crates:

- [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253) affects `lru` 0.16.4 through the client-only `pubky` → `pkarr` → `mainline` path; the rendezvous release does not link it. The issue requires `LruCache::pop()`, unwinding, and a key whose `Drop` implementation can panic. `mainline` does not call `pop()` and uses its `Copy` byte-array `Id` as every affected cache key, so those preconditions are absent here. Upgrade when `mainline` moves to `lru` 0.18.2 or later.
- [RUSTSEC-2023-0089](https://rustsec.org/advisories/RUSTSEC-2023-0089) marks `atomic-polyfill` unmaintained. It arrives through `pubky-common` → `postcard` → `heapless` only for targets without native pointer-width atomics and is not present in the x86_64 Linux build. Re-evaluate it before supporting embedded targets.

The CI audit remains unfiltered so new advisories and changes to either upstream warning stay visible. Re-run it whenever `Cargo.lock` changes.
