# Testing strategy

## Always-on test gates

Run before every commit:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit
npm ci --ignore-scripts
npm run lint:schemas
shellcheck scripts/*.sh
```

Install the audit command once with `cargo install cargo-audit --locked`. CI also runs the same RustSec scan on every change.

The default suite covers:

- certificate, descriptor, message, and HPKE round trips;
- signature/ciphertext/header tampering and expiry;
- real WebSocket registration, nonce replay rejection, multi-device fan-out, first accept, opaque relay, sequence replay, TURN REST credentials, health, and metrics;
- two real WebRTC stacks exchanging SDP through the rendezvous and bytes over a host ICE candidate;
- rejection before any SDP/candidate disclosure.

## TURN-only path

Run coturn with the same REST secret used by the ephemeral test server, then execute the ignored integration test:

```bash
docker run --rm --network host \
  coturn/coturn:4.6.3-r3-alpine@sha256:e2bca2f79a4269d7240de5872ab60a9305013ad37296d2acf14f9510874346be \
  --no-cli --log-file=stdout --fingerprint --use-auth-secret \
  --allow-loopback-peers \
  --static-auth-secret=hole-punchky-integration-secret \
  --realm=hole-punchky.test --listening-port=3478 \
  --min-port=49160 --max-port=49200

HPK_TEST_TURN_URL='turn:127.0.0.1:3478?transport=udp' \
HPK_TEST_TURN_SECRET='hole-punchky-integration-secret' \
cargo test -p hole-punchky-client forced_turn_path_relays_data_channel -- --ignored --nocapture
```

The test sets ICE policy to `RelayOnly`, exchanges application bytes, and requires both peers' nominated local candidate stats to report `Relayed`.
`--allow-loopback-peers` is required only because coturn and both test peers share one host. Never enable it on an Internet-facing TURN server.

## Pubky testnet path

With the Pubky development stack running, create an identity, sign it up against the local homeserver, create a loopback descriptor, publish it with `--testnet`, and resolve it with `--testnet --allow-insecure-local`. This verifies the full PKARR → homeserver → public-storage path rather than substituting a generic HTTP endpoint.

## Two-network/NAT lab

The real direct test uses independent UDP sockets but a shared host. For release testing, put each CLI process behind a different Linux network namespace, VM, or physical network. Confirm:

1. direct mode reports `Direct` under endpoint-independent NAT;
2. port-dependent/symmetric NAT selects UDP `Relayed` when TURN is reachable;
3. blocking all UDP returns a bounded error in the current native client;
4. disabling TURN under an impossible NAT returns a bounded error;
5. the rendezvous packet capture contains only signed control metadata and HPKE ciphertext;
6. no inbound port is opened on either client network.

The hosted Linux CI job runs the ignored real-coturn test and the privileged two-namespace NAT lab after the default suite. The deployment smoke script remains available for an end-to-end Compose health check.

On Linux, `scripts/nat-lab.sh` automates the direct-path case with two device namespaces, two independent gateway namespaces, isolated private subnets, port-preserving address translation, and stateful inbound firewalls. This intentionally models endpoint-independent NAT, where UDP hole punching should succeed; the separate TURN-only test covers relay behavior. Start the rendezvous/STUN/TURN deployment first, build the CLI, then run:

```bash
cargo build --release -p hole-punchky
sudo HPK_RENDEZVOUS_CONNECT_IP=192.0.2.10 \
  HPK_RENDEZVOUS_CONNECT_PORT=8080 \
  scripts/nat-lab.sh
```

Use the address of the host-side rendezvous service as `HPK_RENDEZVOUS_CONNECT_IP`. The script requires IPv4 forwarding plus `ip`, `iptables`, `tc`, `flock`, and `timeout`; it fails unless both peers report `Direct` and the echoed bytes match. Its namespaces, routes, firewall/translation rules, identities, and logs are removed on exit.
