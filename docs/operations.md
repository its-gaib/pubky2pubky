# Operations

## Public deployment checklist

1. Give the rendezvous endpoint a DNS name and terminate TLS so clients use `wss://`.
2. Give coturn a stable public IP. Open UDP/TCP 3478, UDP 3479, and the configured UDP relay range 49160–49200.
3. Copy `deploy/.env.example` to `.env`, set the public host/IP, and generate a 32-byte random TURN shared secret.
4. Put the same secret in rendezvous and coturn. Never place it in Pubky storage.
5. Configure `HPK_ALLOWED_ORIGINS` for browser clients. Native clients normally send no Origin.
6. Run `docker compose -f deploy/docker-compose.yml up --build -d`.
7. Verify `/healthz`, `/v1/config`, `/metrics`, a direct test, and a forced TURN-only test from different networks.
8. Publish a root-signed descriptor containing the public `wss://.../v1/ws` URL.

The example compose file disables TURN TLS because WebRTC payloads are already protected by DTLS and UDP TURN is the normal path. Browser clients can use TCP fallback when coturn is configured with certificates and `turns:` on TCP 5349. The current native client supports UDP TURN only, so TCP/TLS relay requires upstream transport support or a separate implementation. WSS for rendezvous is mandatory on the public internet.

The native client currently requires STUN and TURN to use distinct server socket addresses. The example runs a STUN-only coturn process on UDP 3479 and the authenticated TURN process on 3478. They reuse the same image but share neither state nor the TURN secret. Preserve that separation until the upstream WebRTC transport can demultiplex Binding responses from a colocated TURN transaction by message type.

## Reverse proxy

WebSocket upgrades and long idle connections must be allowed. The example Caddyfile works without special upgrade directives. Preserve the original source address for edge abuse controls, set an idle timeout longer than the client heartbeat policy, and cap request/header sizes.

The application binds port 8080 and exposes:

| Path | Purpose |
| --- | --- |
| `/healthz` | Liveness and protocol version |
| `/v1/config` | Non-secret STUN/feature information |
| `/v1/ws` | Authenticated signaling WebSocket |
| `/metrics` | Prometheus text metrics |

Do not expose coturn's CLI port. The compose invocation passes `--no-cli`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HPK_BIND` | `0.0.0.0:8080` | HTTP listen socket |
| `HPK_STUN_URLS` | empty in binary CLI | Comma-separated client STUN URLs |
| `HPK_TURN_URLS` | empty | Comma-separated client TURN URLs |
| `HPK_TURN_SHARED_SECRET` | unset | coturn REST shared secret |
| `HPK_SESSION_TTL_SECONDS` | `120` | Pending/accepted session lifetime |
| `HPK_TURN_CREDENTIAL_TTL_SECONDS` | `300` | TURN REST credential lifetime |
| `HPK_MAX_MESSAGE_BYTES` | `65536` | WebSocket message bound |
| `HPK_KNOCKS_PER_MINUTE` | `30` | Per-identity knock allowance |
| `HPK_MAX_SESSIONS` | `10000` | Global active and replay-tracked session-ID bound |
| `HPK_MAX_CONNECTIONS_PER_IDENTITY` | `16` | Per-identity WebSocket bound |
| `HPK_MAX_CONNECTIONS` | `10000` | Global WebSocket bound |
| `HPK_MAX_REGISTRATION_NONCES` | `50000` | Global registration replay-cache bound |
| `HPK_ALLOWED_ORIGINS` | empty | Comma-separated browser Origin allowlist |
| `RUST_LOG` | runtime-dependent | Structured log filter |

TURN URLs and the shared secret must be configured together. Changing the secret invalidates newly requested access against servers still using the old secret, so roll coturn and rendezvous in a coordinated window.

## Homeserver co-location

Co-location is operational, not protocol coupling. The sidecar does not need homeserver database access or its signing key. A common layout is:

```text
443/tcp  reverse proxy
  /v1/ws          -> hole-punchky-rendezvous:8080
  homeserver host -> pubky-homeserver
3478/udp+tcp      -> coturn TURN
3479/udp          -> coturn STUN
49160-49200/udp   -> coturn allocations
```

Keep upstream `pubky-homeserver` unchanged. Back up the normal homeserver data; the rendezvous itself has no durable v1 data.

## Monitoring

Alert on process health, open WebSockets, registration/authentication failure rate, knock rate limiting, accepted sessions, signal relay rate, coturn allocations, packet loss, and egress bandwidth. A sudden gap between accepted sessions and successful application connections usually indicates STUN/TURN reachability or advertised-IP errors.

Logs intentionally contain connection/session identifiers and state changes, not plaintext candidates or data. Treat identity pairs and timing as personal metadata.
