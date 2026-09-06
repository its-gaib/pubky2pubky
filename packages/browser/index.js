import initWasm, { BrowserCore } from "./generated/pubky2pubky_browser_wasm.js";

const PUBKY = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_MESSAGE_BYTES = 4_096;
const MAX_RELAYS = 4;
const MAX_AUTHORIZATION_URL_BYTES = 8 * 1_024;
const MAX_EVENT_CLOCK_DRIFT_MS = 5 * 60 * 1_000;
const ALPN = "pubky2pubky/iroh/v1";
const ERROR_CODES = new Set([
  "another-tab-online",
  "authentication-required",
  "auth-relay-invalid",
  "browser-unsupported",
  "client-id-invalid",
  "device-state-exists",
  "device-state-invalid",
  "ed25519-unsupported",
  "grant-key-missing",
  "identity-active",
  "identity-exists",
  "identity-mismatch",
  "identity-not-found",
  "identity-verification-failed",
  "internal-error",
  "invalid-pubky",
  "invalid-state",
  "message-invalid",
  "peer-already-connected",
  "peer-not-connected",
  "peer-unreachable",
  "publication-failed",
  "relay-path-unverified",
  "relay-unreachable",
  "relay-config-invalid",
  "request-expired",
  "session-closed",
  "sequence-limit",
  "signing-failed",
  "storage-blocked",
  "storage-failed",
  "storage-invalid",
  "storage-key-missing",
  "storage-tampered",
  "storage-too-large",
  "testnet-config-invalid",
  "transport-unavailable",
]);

let wasmInitialization;

export class Pubky2PubkyBrowserError extends Error {
  constructor(code) {
    super(code);
    this.name = "Pubky2PubkyBrowserError";
    this.code = code;
  }
}

export async function createBrowserTransport(config) {
  const normalized = validateConfig(config);
  wasmInitialization ??= initWasm();
  await wasmInitialization;
  return new BrowserTransport(normalized);
}

class BrowserTransport {
  #config;
  #core;
  #subscribers = new Set();
  #accountId;
  #identity;
  #destroyed = false;
  #destroyPromise;
  #authPending = false;
  #online = false;
  #leaderRelease;
  #leaderCompletion;
  #networkTail = Promise.resolve();

  constructor(config) {
    this.#config = config;
    this.#core = new BrowserCore((event) => this.#handleCoreEvent(event));
  }

  subscribe(listener) {
    if (typeof listener !== "function" || this.#destroyed) throw typed("invalid-state");
    this.#subscribers.add(listener);
    return () => this.#subscribers.delete(listener);
  }

  async initialize(accountId) {
    this.#requireActive();
    if (this.#accountId !== undefined) throw typed("invalid-state");
    if (accountId !== undefined) this.#accountId = requirePubky(accountId);
    if (this.#accountId !== undefined) {
      try {
        const restored = await this.#core.restoreIdentity(
          this.#accountId,
          this.#config.clientId,
          this.#config.testnetHost,
        );
        this.#identity = restored.identity;
        this.#emit({ type: "identity", identity: restored.identity, restored: true });
      } catch (error) {
        if (!["identity-not-found", "authentication-required"].includes(errorCode(error))) {
          throw this.#report(error);
        }
      }
    }
  }

  async connectWithRing() {
    this.#requireActive();
    if (this.#identity !== undefined || this.#authPending) throw typed("invalid-state");
    this.#authPending = true;
    try {
      const request = await this.#core.beginAuth(
        this.#config.clientId,
        this.#config.httpRelay,
        this.#accountId,
        this.#config.testnetHost,
      );
      // The URL carries a short-lived relay secret. It is emitted only to the in-memory callback.
      this.#emit({
        type: "auth-required",
        authorizationUrl: requireAuthorizationUrl(request?.authorizationUrl),
      });
      const identity = await this.#core.completeAuth();
      this.#identity = identity.identity;
      this.#accountId ??= identity.identity;
      this.#emit({ type: "identity", identity: identity.identity, restored: false });
      return identity.identity;
    } catch (error) {
      throw this.#report(error);
    } finally {
      this.#authPending = false;
    }
  }

  async listLocalIdentities() {
    this.#requireActive();
    try {
      return await this.#core.listLocalIdentities();
    } catch (error) {
      throw this.#report(error);
    }
  }

  async removeLocalIdentity(identity) {
    this.#requireActive();
    const account = requirePubky(identity);
    return this.#runNetworkOperation(async () => {
      try {
        const removed = await this.#withIdentityLock(account, () =>
          this.#core.removeLocalIdentity(account));
        if (this.#identity === account) this.#identity = undefined;
        return removed;
      } catch (error) {
        throw this.#report(error);
      }
    });
  }

  async publishAndGoOnline() {
    this.#requireActive();
    if (this.#identity === undefined) await this.connectWithRing();
    return this.#runNetworkOperation(async () => {
      if (this.#online) throw this.#report(typed("invalid-state"));
      await this.#acquireLeader();
      try {
        this.#emit({ type: "connecting" });
        await this.#core.publishAndGoOnline(
          this.#config.deviceId,
          this.#config.irohRelays,
          this.#config.allowLoopbackTestnet,
        );
        this.#online = true;
        this.#emit({ type: "online-state", online: true, status: "online" });
      } catch (error) {
        await this.#releaseLeader();
        throw this.#report(error);
      }
    });
  }

  async connect(peerId) {
    return this.requestPeer(peerId);
  }

  async requestPeer(peerId) {
    this.#requireActive();
    const peer = requirePubky(peerId);
    this.#emit({ type: "connecting", peerId: peer });
    try {
      await this.#core.requestPeer(peer);
    } catch (error) {
      throw this.#report(error);
    }
  }

  async requestConversation(peerId) {
    return this.requestPeer(peerId);
  }

  async acceptInbound(requestId) {
    this.#requireActive();
    try {
      await this.#core.acceptInbound(requireRequestId(requestId));
    } catch (error) {
      throw this.#report(error);
    }
  }

  async accept(requestId) {
    return this.acceptInbound(requestId);
  }

  async rejectInbound(requestId) {
    this.#requireActive();
    try {
      this.#core.rejectInbound(requireRequestId(requestId));
    } catch (error) {
      throw this.#report(error);
    }
  }

  async decline(requestId) {
    return this.rejectInbound(requestId);
  }

  async sendMessage(peerId, bytes) {
    this.#requireActive();
    const peer = requirePubky(peerId);
    validateMessage(bytes);
    try {
      return validateReceipt(await this.#core.sendMessage(peer, bytes), peer);
    } catch (error) {
      throw this.#report(error);
    }
  }

  async send(peerId, text) {
    if (typeof text !== "string") throw typed("message-invalid");
    const bytes = new TextEncoder().encode(text);
    return this.sendMessage(peerId, bytes);
  }

  async disconnect() {
    if (this.#destroyed) return;
    return this.#runNetworkOperation(async () => {
      try {
        await this.#core.disconnect();
      } finally {
        this.#online = false;
        await this.#releaseLeader();
        this.#emit({ type: "online-state", online: false, status: "offline" });
      }
    });
  }

  destroy() {
    if (this.#destroyPromise !== undefined) return this.#destroyPromise;
    if (this.#destroyed) return Promise.resolve();
    this.#destroyed = true;
    this.#subscribers.clear();
    const core = this.#core;
    this.#destroyPromise = this.#runNetworkOperation(async () => {
      try {
        await core.cancelAuth();
        await core.disconnect();
      } finally {
        this.#online = false;
        await this.#releaseLeader();
        // Do not call wasm-bindgen's manual free while an already-started async call may still
        // hold the receiver. Dropping this last live reference lets GC release it safely.
        this.#core = undefined;
      }
    });
    return this.#destroyPromise;
  }

  #requireActive() {
    if (this.#destroyed) throw typed("invalid-state");
  }

  #emit(event) {
    const frozen = Object.freeze(event);
    for (const subscriber of [...this.#subscribers]) {
      try {
        subscriber(frozen);
      } catch (_error) {
        // Consumer callback failures must not escape into transport/auth state machines.
      }
    }
  }

  #handleCoreEvent(event) {
    try {
      const normalized = normalizeCoreEvent(event);
      this.#emit(normalized);
      if (normalized.type === "online-state" && normalized.online === false) {
        this.#online = false;
        void this.#releaseLeader();
      }
    } catch (_error) {
      this.#emit({ type: "error", code: "internal-error" });
    }
  }

  #report(error) {
    const normalized = normalizeError(error);
    this.#emit({ type: "error", code: normalized.code });
    return normalized;
  }

  async #acquireLeader() {
    if (this.#leaderRelease !== undefined) return;
    if (!globalThis.navigator?.locks?.request) throw typed("browser-unsupported");
    let announce;
    const acquired = new Promise((resolve) => {
      announce = resolve;
    });
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    let lockFailure = false;
    try {
      this.#leaderCompletion = navigator.locks.request(
        `pubky2pubky:network-leader:${requirePubky(this.#identity)}`,
        { mode: "exclusive", ifAvailable: true },
        async (lock) => {
          announce(lock !== null);
          if (lock !== null) await held;
        },
      ).catch(() => {
        lockFailure = true;
        announce(false);
      });
    } catch (_error) {
      throw typed("browser-unsupported");
    }
    if (!(await acquired)) {
      await this.#leaderCompletion;
      this.#leaderCompletion = undefined;
      throw typed(lockFailure ? "browser-unsupported" : "another-tab-online");
    }
    this.#leaderRelease = release;
  }

  async #releaseLeader() {
    const release = this.#leaderRelease;
    const completion = this.#leaderCompletion;
    this.#leaderRelease = undefined;
    this.#leaderCompletion = undefined;
    release?.();
    await completion;
  }

  async #runNetworkOperation(operation) {
    const previous = this.#networkTail;
    let release;
    this.#networkTail = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  async #withIdentityLock(identity, operation) {
    if (!globalThis.navigator?.locks?.request) throw typed("browser-unsupported");
    let acquired = false;
    let result;
    let operationError;
    try {
      await navigator.locks.request(
        `pubky2pubky:network-leader:${requirePubky(identity)}`,
        { mode: "exclusive", ifAvailable: true },
        async (lock) => {
          if (lock === null) return;
          acquired = true;
          try {
            result = await operation();
          } catch (error) {
            operationError = error;
          }
        },
      );
    } catch (_error) {
      throw typed("browser-unsupported");
    }
    if (!acquired) throw typed("identity-active");
    if (operationError !== undefined) throw operationError;
    return result;
  }
}

function validateConfig(input) {
  if (!isPlainRecord(input)) throw typed("invalid-state");
  const clientId = requireBoundedText(input.clientId, 253, "client-id-invalid");
  const httpRelay = requireUrl(input.httpRelay, true, Boolean(input.testnet), "auth-relay-invalid");
  if (!["/inbox", "/inbox/"].includes(httpRelay.pathname)) {
    throw typed("auth-relay-invalid");
  }
  if (!Array.isArray(input.irohRelays) || input.irohRelays.length < 1 || input.irohRelays.length > MAX_RELAYS) {
    throw typed("relay-config-invalid");
  }
  const relays = input.irohRelays.map((value) => {
    const url = requireUrl(value, false, Boolean(input.testnet), "relay-config-invalid");
    if (url.pathname !== "/") throw typed("relay-config-invalid");
    return url.href;
  });
  if (new Set(relays).size !== relays.length) throw typed("relay-config-invalid");
  let testnetHost;
  let allowLoopbackTestnet = false;
  if (input.testnet !== undefined) {
    if (!isPlainRecord(input.testnet) || input.testnet.enabled !== true) {
      throw typed("testnet-config-invalid");
    }
    testnetHost = requireBoundedText(input.testnet.pubkyHost, 253, "testnet-config-invalid");
    if (/[/\\@:]/u.test(testnetHost)) throw typed("testnet-config-invalid");
    allowLoopbackTestnet = true;
  }
  const deviceId = input.deviceId === undefined
    ? "browser"
    : requireBoundedText(input.deviceId, 64, "device-state-invalid");
  return Object.freeze({
    clientId,
    httpRelay: httpRelay.href,
    irohRelays: Object.freeze(relays),
    testnetHost,
    allowLoopbackTestnet,
    deviceId,
    alpn: ALPN,
  });
}

function requireUrl(value, authRelay, allowLoopback, code) {
  const text = requireBoundedText(value, 2_048, code);
  let url;
  try {
    url = new URL(text);
  } catch (_error) {
    throw typed(code);
  }
  const loopback =
    (url.hostname === "127.0.0.1" || url.hostname === "[::1]") && url.port !== "";
  if (
    (url.protocol !== "https:" && !(allowLoopback && loopback && url.protocol === "http:")) ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (!authRelay && url.pathname !== "/")
  ) {
    throw typed(code);
  }
  return url;
}

function requireBoundedText(value, maximum, code) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw typed(code);
  }
  return value;
}

function requirePubky(value) {
  if (typeof value !== "string" || !PUBKY.test(value)) throw typed("invalid-pubky");
  return value;
}

function requireRequestId(value) {
  if (typeof value !== "string" || !REQUEST_ID.test(value)) throw typed("request-expired");
  return value;
}

function validateMessage(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > MAX_MESSAGE_BYTES) {
    throw typed("message-invalid");
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (new TextEncoder().encode(text).byteLength !== bytes.byteLength) throw typed("message-invalid");
  } catch (_error) {
    throw typed("message-invalid");
  }
}

function validateReceipt(value, expectedPeer) {
  if (
    !isPlainRecord(value) ||
    value.peerId !== expectedPeer ||
    !isLocalTimestamp(value.acceptedAt)
  ) {
    throw typed("internal-error");
  }
  return Object.freeze({ peerId: expectedPeer, acceptedAt: value.acceptedAt });
}

function normalizeCoreEvent(event) {
  if (!isPlainRecord(event) || typeof event.type !== "string") throw typed("internal-error");
  switch (event.type) {
    case "online-state": {
      if (event.online !== false) throw typed("internal-error");
      return { type: "online-state", online: false, status: "offline" };
    }
    case "inbound-request": {
      const id = requireRequestId(event.id);
      const peerId = requirePubky(event.peerId);
      const peerDeviceId = requireBoundedText(event.peerDeviceId, 64, "internal-error");
      if (event.application !== "pubky2pubky/chat/1" || !isLocalTimestamp(event.receivedAt)) {
        throw typed("internal-error");
      }
      return {
        type: "inbound-request",
        id,
        peerId,
        peerDeviceId,
        receivedAt: event.receivedAt,
      };
    }
    case "inbound-request-expired":
      return { type: "inbound-request-expired", id: requireRequestId(event.id) };
    case "peer-verified": {
      const peerId = requirePubky(event.peerId);
      const peerDeviceId = requireBoundedText(event.peerDeviceId, 64, "internal-error");
      if (
        event.path !== "relay" ||
        event.route !== "relay" ||
        event.e2e !== true ||
        event.irohQuicEncrypted !== true ||
        event.pubkyIdentityVerified !== true ||
        event.protocolVersion !== 1 ||
        event.alpn !== ALPN
      ) {
        throw typed("internal-error");
      }
      return {
        type: "peer-verified",
        peerId,
        peerDeviceId,
        path: "relay",
        route: "relay",
        e2e: true,
        irohQuicEncrypted: true,
        pubkyIdentityVerified: true,
        protocolVersion: 1,
        alpn: ALPN,
      };
    }
    case "peer-disconnected":
      return { type: "peer-disconnected", peerId: requirePubky(event.peerId) };
    case "message": {
      const peerId = requirePubky(event.peerId);
      validateMessage(event.body);
      if (!isLocalTimestamp(event.receivedAt)) {
        throw typed("internal-error");
      }
      return {
        type: "message",
        peerId,
        body: new Uint8Array(event.body),
        receivedAt: event.receivedAt,
      };
    }
    case "error": {
      if (!ERROR_CODES.has(event.code)) throw typed("internal-error");
      return { type: "error", code: event.code };
    }
    default:
      throw typed("internal-error");
  }
}

function isPlainRecord(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireAuthorizationUrl(value) {
  const text = requireBoundedText(value, MAX_AUTHORIZATION_URL_BYTES, "internal-error");
  let url;
  try {
    url = new URL(text);
  } catch (_error) {
    throw typed("internal-error");
  }
  if (url.protocol !== "pubkyauth:") throw typed("internal-error");
  return text;
}

function isLocalTimestamp(value) {
  return (
    Number.isSafeInteger(value) &&
    value > 0 &&
    Math.abs(value - Date.now()) <= MAX_EVENT_CLOCK_DRIFT_MS
  );
}

function errorCode(error) {
  if (error instanceof Pubky2PubkyBrowserError) return error.code;
  const message = typeof error?.message === "string" ? error.message : "";
  return ERROR_CODES.has(message) ? message : "internal-error";
}

function normalizeError(error) {
  return typed(errorCode(error));
}

function typed(code) {
  return new Pubky2PubkyBrowserError(ERROR_CODES.has(code) ? code : "internal-error");
}
