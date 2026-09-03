# Testing strategy

## Always-on gates

Run the complete repository gate before every commit:

```bash
./scripts/test-all.sh
```

It runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit
npm ci --ignore-scripts
npm run lint:schemas
shellcheck scripts/*.sh
```

Install one-time tools with `cargo install cargo-audit --locked` and your package manager's `shellcheck`. Node 20.19 or newer is required for the pinned schema tooling. Set `HPK_TEST_CONTAINERS=1` to append the Compose smoke test.

The default Rust suite exercises:

- root delegation, independent device keys, descriptor signing, expiry, URL policy, and canonical serialization;
- HPKE privacy, recipient binding, header/ciphertext tampering, signal-kind checks, address bounds, and certified iroh endpoint binding;
- live WebSocket registration, nonce replay rejection, quotas, multi-device fan-out, rejection aggregation, atomic first accept, strict signal direction/sequence, session deletion, and tombstones;
- relay callback bearer authentication, registered-endpoint admission, malformed key rejection, and metrics;
- real iroh endpoints exchanging authenticated QUIC data on a direct path;
- explicit rejection before endpoint disclosure;
- a forced relay-only transfer through an in-process official `iroh-relay` server.

No unit test mocks QUIC authentication. The direct and forced-relay tests use real endpoints and exchange application bytes. The Pubky resolver unit path can use an in-memory descriptor source, while the testnet path below verifies actual PKARR and homeserver storage.

## Container smoke test

The smoke script builds the release rendezvous image and checksum-pinned official relay image, starts Compose, waits for both health checks, verifies `/v2/config`, and tears down its temporary stack:

```bash
HPK_RELAY_AUTH_SECRET="$(openssl rand -hex 32)" \
  ./scripts/container-smoke.sh
```

Run it on an otherwise unused Compose project/host because its cleanup executes `docker compose down --volumes` for the supplied deployment. For a persistent developer stack, use `docker compose up --build --detach --wait` directly and leave it running.

The smoke health check proves image/config compatibility. The Rust relay-only test proves data relay. The two-NAT lab proves the packaged relay and rendezvous can support direct traversal together.

## Manual loopback transfer

Start Compose and build the CLI:

```bash
export HPK_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
docker compose -f deploy/docker-compose.yml up --build --detach --wait
cargo build -p hole-punchky
```

Create Alice and Bob credentials, start Bob with `listen --accept --echo --once`, and use Alice's `dial` command as shown in the README. Require an echoed payload and inspect `connected path=Direct` or `Relayed`. Repeat both clients with `--relay-only` and require `Relayed`.

Test negative behavior as well: omit `--accept`, use a wrong target identity, use an expired credential, use an unregistered endpoint ID against the internal callback, and configure an unreachable relay. Every case must fail within the configured timeout and must not release Bob's endpoint before acceptance.

## Two-network NAT lab

`scripts/nat-lab.sh` places each real CLI process in its own device namespace behind an independent stateful translating gateway. The gateways use separate private subnets and public documentation ranges, perform endpoint-independent port-preserving translation, and have no inbound port forwards. The script verifies both sides report `Direct` and Bob echoes the exact payload.

Prerequisites are Linux root privileges, IPv4 forwarding, and `ip`, `iptables`, `tc`, `flock`, `mktemp`, `sysctl`, and `timeout`. Start a rendezvous and relay reachable from the parent namespace, then run:

```bash
cargo build --release -p hole-punchky
sudo sysctl -w net.ipv4.ip_forward=1
sudo env \
  HPK_BIN="$PWD/target/release/hole-punchky" \
  HPK_RENDEZVOUS_CONNECT_IP=192.0.2.10 \
  HPK_RENDEZVOUS_CONNECT_PORT=8080 \
HPK_IROH_RELAY_CONNECT_PORT=3340 \
HPK_IROH_RELAY_CA=/tmp/hole-punchky-relay-ca.crt \
"$PWD/scripts/nat-lab.sh"
```

Use the real parent-side address of the services, not `192.0.2.10`. The script gives each namespace a scoped `localhost` hosts entry so the client's strict loopback-only HTTP development policy still applies. It cleans namespaces, routes, filters, temporary credentials, and logs on exit.

This lab models a NAT type expected to hole-punch. Add external VM or physical-network coverage for endpoint-dependent/symmetric NAT, carrier-grade NAT, IPv6, dual stack, captive portals, HTTP proxies, and networks that block UDP. In those environments require either a direct path or a successful bounded fallback to `Relayed`; direct connectivity can never be guaranteed.

## Pubky development-stack path

Use the Pubky development environment from the upstream getting-started guide. Obtain the local homeserver's z-base-32 public key, then exercise the real SDK path:

```bash
target/debug/hole-punchky init \
  --device-id bob-testnet \
  --root-out bob.root.json \
  --device-out bob.device.json

target/debug/hole-punchky signup \
  --root bob.root.json \
  --homeserver <local-homeserver-z32-key> \
  --testnet

target/debug/hole-punchky descriptor \
  --root bob.root.json \
  --rendezvous ws://localhost:8080/v2/ws \
  --out bob.descriptor.json

target/debug/hole-punchky publish \
  --root bob.root.json \
  --descriptor bob.descriptor.json \
  --testnet

target/debug/hole-punchky resolve \
  --identity <bob-z32-identity> \
  --testnet \
  --allow-insecure-local
```

The resolved URL must exactly equal the published URL. Finally run Bob's listener and dial Bob without `--rendezvous`, adding `--testnet`; require the same echo and authenticated path result. This final step proves PKARR homeserver discovery, Pubky public storage, root-signature verification, consent signaling, relay admission, QUIC authentication, and application data in one flow.

Use fresh identities or remove prior test accounts according to the Pubky stack's own reset procedure. Test secrets and descriptors belong in a private temporary directory and should be deleted after the run.

## Packet and privacy assertions

For release candidates, capture at the rendezvous, relay, both client LANs, and both WAN sides. Confirm:

1. the pre-consent rendezvous transcript contains only signed registration/knock metadata;
2. Bob sends no endpoint signal and Alice sends no peer QUIC packets before acceptance;
3. the endpoint signal exposes routing headers and ciphertext, not relay URLs or socket addresses;
4. relay fallback carries opaque QUIC traffic and cannot reveal application plaintext;
5. a successful direct migration moves subsequent data off the relay;
6. replayed registration nonces, session IDs, signals, and stream hellos are rejected;
7. neither NAT has a static inbound mapping or port-forward rule.

Record dependency versions, test topology, selected path, and whether a reverse proxy was present. Keep payloads synthetic because packet captures and identity/timing metadata are sensitive.
