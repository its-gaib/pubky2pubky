# Operations

## Protocol v3 topology

V3 uses the unmodified Pubky homeserver and an official iroh relay. It has no pubky2pubky
rendezvous service or relay-admission callback:

```text
PKARR -> Pubky homeserver -> /pub/pubky2pubky/v3/directory.json
                           -> /pub/pubky2pubky/v3/locators/<device-control-key>.json

relay.example.com:443      -> TLS proxy -> iroh-relay:3340
relay.example.com:7842/udp             -> iroh-relay QUIC address discovery
```

The checked-in Docker Compose topology is the compatibility v2 deployment: its relay calls the v2
rendezvous presence endpoint and will reject a v3-only device. Do not use that admission callback
for v3. Configure a v3 relay with the official relay's shared-token or explicit endpoint-allowlist
policy, or operate a separate bounded authorization service designed for v3. Relay bearer tokens
are local client configuration and must never appear in Pubky locators, logs, command history, or
frontend bundles.

For the v3 probe CLI, inject an optional bearer token only through the
`PUBKY2PUBKY_IROH_RELAY_TOKEN` environment variable. V3 deliberately exposes no plaintext token
argument. The CLI bounds and validates the value, zeroizes its temporary validation buffer, and
does not log it; the transport retains only the copy needed for authenticated relay requests. A
production service should obtain the same local-only value from its secret manager and avoid
exposing its process environment to unrelated users or diagnostics.

The device directory is root-signed and changes only when issuing, replacing, or retiring a
device. Each listener signs short-lived locator updates using its delegated online key. Run root
signing offline. A listener must never receive the Pubky recovery phrase or root secret.

Publication is a separate authority boundary. Library integrations pass an already-authorized,
least-privilege `PubkySession` to the publish functions. The file-backed CLI's short-lived
publisher signs in with a development root file, writes the already-signed object, and exits; do
not copy that shortcut into a listener service. Scope the session to the v3 public-storage prefix
when the account/auth layer supports scoped capabilities.

Persist the next directory generation and each device's next locator sequence atomically. Back up
that small state with the device credential. A crash or restore must not reset either counter.
Publish locator updates before the old locator expires and whenever the selected home relay
changes. Letting a locator expire is the clean offline signal; it does not queue messages.

Treat loss differently for the two counters. A device that loses its locator publisher state must
be removed and reissued with a new control key; never restart its old key at sequence one.
Directory generation belongs to the offline root procedure. Record it before publication and keep
independent backups; if no trustworthy last generation can be recovered, migrate the Pubky
identity instead of guessing a lower value.

Configure every client with an exact trusted-relay allowlist. The relay URL is attacker-controlled
input even after the target signs it: the signature authenticates the target's choice, not the
safety of connecting from the caller's network. Production policy should permit only normalized
HTTPS origins operated or explicitly trusted by the application, reject off-allowlist redirects
and unsafe DNS results, and fail closed when no advertised relay is allowed.

Monitor locator publication age, expiry margin, sequence rollback rejections, directory generation
rollback rejections, QUIC authentication failures, unsolicited inbound handshakes, relay health,
relay traffic, and observed direct-versus-relayed paths. Apply per-source and per-identity
connection/hello limits at the listener because v3 has no pre-QUIC consent gate.

After authenticating a signed Hello, the listener surfaces an `IncomingV3` request. The application
must make an explicit bounded accept/reject decision. Only acceptance sends the signed Ack and
exposes the `Peer` to application payload handlers; dropping or rejecting the request closes it.
Bounded encrypted transport input can be buffered before the decision, but is not surfaced or
processed as application payload. This content gate does not undo the earlier network contact or
address disclosure.

Native clients need outbound TCP 443 for relay fallback and outbound UDP for direct QUIC. A public
locator lets arbitrary readers probe liveness and initiate iroh; direct-capable iroh may expose
address candidates before application authentication. The reference native v3 client currently
provides direct-with-relay-fallback only; it does not expose a peer-address-hiding relay-only
policy. Do not publish a privacy-sensitive identity until that mode exists, or retain v2's consent
service. Browser/Wasm iroh is relay-only today and must never be reported as a direct path.

## Protocol v2 production topology

Run the unmodified Pubky homeserver, Hole Punchky rendezvous, and official iroh relay as separate services. They may share a host and reverse proxy, but they do not share a database or signing key.

```text
PKARR -> Pubky homeserver -> /pub/hole-punchky/v2/descriptor.json

connect.example.com:443 -> TLS proxy -> rendezvous:8080
relay.example.com:443   -> TLS proxy -> iroh-relay:3340
                                    -> rendezvous:8080/internal/relay/authorize
relay.example.com:7842/udp          -> iroh-relay QUIC address discovery
```

The relay-to-rendezvous callback stays on the private container network. The example [Caddyfile](../deploy/Caddyfile.example) returns `404` for every public `/internal/*` rendezvous path. Apply an equivalent rule in any other proxy and restrict port 8080 at the host firewall.

Clients need outbound TCP 443 for WSS and relay fallback plus outbound UDP for direct QUIC. No fixed inbound client port is required. A network that blocks UDP should continue over the TLS relay path.

## V2 deployment checklist

1. Create DNS records for separate rendezvous and relay names. Terminate valid public TLS for both; clients require `wss://` and `https://` outside explicit loopback development mode. Expose the relay's standard UDP 7842 QUIC address-discovery port alongside its HTTPS/relay port.
2. Copy `deploy/.env.example` to `deploy/.env` and generate `HPK_RELAY_AUTH_SECRET` with at least 32 random bytes. This secret is machine-to-machine authentication, not a client credential.
3. Keep `HPK_RENDEZVOUS_BIND` and `HPK_IROH_RELAY_BIND` on `127.0.0.1` when the reverse proxy runs on the Docker host. On another network, expose only to that proxy and firewall the ports.
4. Configure `HPK_ALLOWED_ORIGINS` if browser code may open the rendezvous WebSocket. Native clients normally omit `Origin`.
5. Start the pinned images:

   ```bash
   docker compose -f deploy/docker-compose.yml up --build --detach --wait
   ```

6. Verify rendezvous `/healthz` and `/v2/config`, relay `/healthz`, UDP 7842 reachability, metrics, the forced-relay integration test, and the two-NAT direct-path lab.
7. Publish a root-signed descriptor containing `wss://connect.example.com/v2/ws`. Configure native clients with `https://relay.example.com/`; relay URLs are not stored in the public Pubky descriptor.
8. Confirm that public requests to `https://connect.example.com/internal/relay/authorize` return `404`.

The supplied iroh image downloads the official v1.1.0 release archive and verifies its architecture-specific SHA-256 checksum. Review and update the version and checksum together. The rendezvous image builds with the locked Cargo graph.

## V2 relay admission

The relay performs an HTTP authorization call for every connecting endpoint. It includes its observed endpoint ID and the shared bearer secret. The rendezvous returns exactly `200 true` only when that endpoint ID appears in a successfully authenticated WebSocket registration.

Iroh-relay v1.1.0 actually emits `X-Iroh-NodeId`, although its source documentation names `X-Iroh-Endpoint-Id`; this release accepts both and rejects conflicting values. Keep the relay binary pinned until an upgrade has passed the real container and forced-relay tests.

Admission is checked when a relay connection is created, not continuously. If the Pubky WebSocket later disconnects, an already-established relay socket may live until either side closes it. The device cannot receive new knocks without its rendezvous connection, and peers still need a fresh accepted, session-bound QUIC handshake.

Rotate `HPK_RELAY_AUTH_SECRET` by updating rendezvous and relay in one maintenance window. A temporary mismatch denies new relay registrations. Never publish this value in Pubky storage, descriptors, logs, client binaries, or command history.

The client library can alternatively attach a relay bearer token through `IrohRelayConfig::with_auth_token`; the CLI exposes `--relay-token`. That mode is useful with the official relay's shared-token policy but is separate from the supplied presence-based HTTP policy.

## V2 rendezvous configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HPK_BIND` | `0.0.0.0:8080` | HTTP/WebSocket listen socket |
| `HPK_RELAY_AUTH_SECRET` | unset | Enables and authenticates the internal relay callback |
| `HPK_SESSION_TTL_SECONDS` | `120` | Pending/accepted session lifetime |
| `HPK_MAX_MESSAGE_BYTES` | `65536` | Complete WebSocket JSON frame bound; minimum 1024 |
| `HPK_KNOCKS_PER_MINUTE` | `30` | Rolling allowance per authenticated identity |
| `HPK_MAX_SESSIONS` | `10000` | Active sessions plus replay-tracked session IDs |
| `HPK_MAX_CONNECTIONS_PER_IDENTITY` | `16` | WebSocket limit for one root identity |
| `HPK_MAX_CONNECTIONS` | `10000` | Global WebSocket limit |
| `HPK_MAX_REGISTRATION_NONCES` | `50000` | Registration replay-cache bound |
| `HPK_ALLOWED_ORIGINS` | empty | Comma-separated browser Origin allowlist |
| `RUST_LOG` | `info` in server image | Structured log filter |

The combined `hole-punchky serve` command intentionally exposes only `--bind` and `--relay-auth-secret`; use `hole-punchky-rendezvous` for the full production policy surface.

Native client transport settings are code-level fields on `RendezvousClientConfig`. The operational CLI supports repeated `--iroh-relay` values (or comma-separated `HPK_IROH_RELAY_URLS`), optional `--iroh-relay-ca` PEM roots (or `HPK_IROH_RELAY_CA_FILES`) for private relay certificates, optional `--relay-token`, `--relay-only`, and explicit `--allow-insecure-relay` for loopback HTTP tests. The default peer frame cap is 16 MiB. Standard iroh QUIC address discovery uses UDP 7842; relay-only clients intentionally skip QAD because they do not need direct candidates.

## HTTP and monitoring surface

| Path | Exposure | Purpose |
| --- | --- | --- |
| `/healthz` | public or monitoring | Liveness and protocol version |
| `/v2/config` | public | Transport, consent, relay-policy flag, and bounds |
| `/v2/ws` | public WSS | Authenticated rendezvous protocol |
| `/metrics` | monitoring preferred | Prometheus text metrics |
| `/internal/relay/authorize` | private only | Relay admission callback |

Allow WebSocket upgrades and idle durations longer than the 25-second default client heartbeat. Bound headers and request bodies at the edge, preserve the source address for abuse controls, and apply per-IP limits in addition to the in-process per-identity limits. Pubky identities are cheap to create, so an identity-only quota is not a DDoS perimeter.

Alert on process health, open WebSockets, authentication failures, rate limiting, accepted sessions, relayed signals, relay authorization denials, relay connections, relay egress, and QUIC connection success. A rise in `hole_punchky_relay_auth_denied_total` can mean a secret mismatch, an ordering bug, or unauthorized relay use. A gap between accepted sessions and application connections normally points to relay reachability, stale endpoint addresses, UDP policy, or QUIC handshake rejection.

Logs should contain bounded connection/session identifiers and state changes, never root/device secrets, bearer tokens, full signed frames, decrypted endpoint addresses, or application data. Identity pairs and timing are personal metadata even when payloads are encrypted.

## Homeserver and state

Do not fork or patch `pubky-homeserver`. The normal Pubky public-storage API holds the descriptor, and normal PKARR discovery locates the homeserver. Back up the homeserver according to its own documentation.

Root signatures are an application boundary: today the CLI's file-backed development path uses a `pubky::Keypair`; production applications should implement the same signing inputs through Pubky Ring when arbitrary signatures are available. Device private keys and root signing operations stay local to the application. No root secret is sent to the rendezvous or relay, and this adapter does not alter descriptor or certificate verification.

The v2 rendezvous has no durable state. A restart disconnects presence and expires in-flight sessions; clients reconnect and must obtain consent again. The relay holds only live connection state. Device and root key files are client state: the CLI creates secret files with mode `0600` on Unix, but production applications should use an OS keystore. Keep the Pubky root offline except for device issuance and descriptor publication.

Protocol v2 is deliberately incompatible with the earlier WebRTC v1 credential and signaling formats. Reissue device credentials and publish the v2 descriptor when upgrading; the Pubky root identity itself does not change. Do not serve v1 and v2 on one path or silently downgrade.

## Scaling and failure recovery

One rendezvous instance is complete. Multiple instances require sticky WebSockets and a shared, bounded view of device presence, sessions, tombstones, registration nonces, and relay admission. An authenticated internal message bus can route signed control frames and opaque ciphertext, but must preserve atomic first-accept semantics.

Scale relay bandwidth separately. Configure multiple trusted relays in each client for infrastructure redundancy and publish multiple signed rendezvous endpoints for control-plane failover. Current dialing uses the address supplied after a single consent flow; if all coordinates go stale, close the attempt, reconnect, and begin a new session rather than reusing ciphertext.

During an incident:

- compromised device: remove its local secret, issue a replacement, and shorten certificate lifetimes; v2 has no immediate online revocation;
- compromised root: create a new Pubky identity and republish through application-specific migration procedures;
- compromised relay callback secret: rotate it on both services and block the callback network path while investigating;
- relay overload: add capacity or temporarily prefer direct paths, while keeping bounded errors and timeouts;
- rendezvous restart: let clients reconnect with fresh registration nonces and session UUIDs.
