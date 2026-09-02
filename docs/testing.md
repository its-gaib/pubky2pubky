# Testing strategy

## Always-on test gates

Run before every commit:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit
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
2. port-dependent/symmetric NAT selects `Relayed`;
3. blocking UDP forces TURN/TCP where configured;
4. disabling TURN under an impossible NAT returns a bounded error;
5. the rendezvous packet capture contains only signed control metadata and HPKE ciphertext;
6. no inbound port is opened on either client network.

The CI suite avoids assuming privileged namespace or Docker access; the ignored test and deployment smoke script cover those infrastructure-dependent paths.
