# `pubky2pubky/browser`

Browser transport for pubky2pubky v1. It uses a Pubky 0.11 Ring Grant restricted to
`/pub/pubky2pubky/:rw`, publishes short-lived device locators to the user's homeserver, and carries
chat bytes over mutually authenticated iroh QUIC through an exact HTTPS relay allowlist.

`connectWithRing()` emits `auth-required` with a short-lived `pubkyauth:` URL. Treat that URL as a
secret: show it only in the active UI callback and never log, persist, analyze, or cache it. A
`peer-verified` event is emitted only after the v1 client returns a mutually verified relay peer.

`disconnect()` closes the locator, endpoint, pending requests, and peers, but deliberately retains
the authenticated local identity and encrypted device state for reconnect. `destroy()` additionally
ends the live JavaScript object and subscriptions; it still does not erase local identity material.
Call `removeLocalIdentity(pubky)` explicitly to delete the Grant key, encrypted restore/device
state, AES key, and that account's sequence state. Message history is always owned by the app, not
this package.

Only literal `127.0.0.1` or `[::1]` HTTP relay URLs with explicit ports are accepted, and only when
the explicit testnet configuration is present. Production relay URLs must use HTTPS.

The generated JavaScript, Wasm, declarations, and security-critical storage snippet are committed
so applications can pin a Git commit. Run `npm run build:browser` to reproduce them and
`npm run check:browser-artifact` to verify the complete artifact manifest.
