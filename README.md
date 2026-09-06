# pubky2pubky

pubky2pubky maps a Pubky identity to an authenticated Iroh QUIC endpoint. Pubky and PKARR are the
identity and discovery plane; the unmodified homeserver stores signed, short-lived connection
records; Iroh carries end-to-end encrypted application bytes.

This repository contains protocol **v1**. Earlier internal experiments were never released and are
not supported by this code.

```text
Pubky ID
  -> PKARR resolves the identity's homeserver
  -> /pub/pubky2pubky/v1/devices/*.json
  -> authenticated Iroh QUIC (relay-only in browsers, direct-capable natively)
  -> mutual short-lived homeserver write proofs after recipient acceptance
  -> application messages
```

The browser package is exported as `pubky2pubky/browser`. It requests a standard Pubky Grant with
the exact `/pub/pubky2pubky/:rw` capability. Root keys remain in Pubky Ring; device and Iroh secrets
are generated locally and never published. Chat bodies are never written to a homeserver.

See [the v1 protocol and threat model](docs/v1.md) for the signed records, consent boundary,
metadata disclosure, browser storage rules, and connection sequence.

## Browser package

Build and verify the committed browser artifact:

```bash
npm ci
npm run setup:browser-toolchain
npm run build:browser
npm run check:browser-artifact
npm run test:browser
```

The generated JavaScript, Wasm, declarations, and storage snippet are committed so applications
can pin an immutable Git commit. The reproducible artifact build currently runs on Linux x86_64;
its setup command installs checksum-verified WASI SDK and Binaryen archives in the user's cache.
A browser build is relay-only because browsers do not expose the UDP primitives Iroh uses for
direct path discovery. Native users of `pubky2pubky-client` may enable relay-assisted UDP hole
punching.

## Rust workspace

- `pubky2pubky-protocol`: Grant-authorized device records, signed handshakes, and currentness proofs.
- `pubky2pubky-client`: bounded homeserver discovery plus authenticated Iroh peers.
- `pubky2pubky-browser-wasm`: browser authentication, protected state, and relay-only bindings.

Run the complete local gate with:

```bash
./scripts/test-all.sh
```

Never enter a real recovery phrase into an experimental application. Licensed under the MIT
License.
