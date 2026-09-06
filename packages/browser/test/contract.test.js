import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, test } from "node:test";

import { Pubky2PubkyBrowserError, createBrowserTransport } from "../index.js";
import initWasm, { BrowserCore } from "../generated/pubky2pubky_browser_wasm.js";

before(async () => {
  const wasm = await readFile(
    new URL("../generated/pubky2pubky_browser_wasm_bg.wasm", import.meta.url),
  );
  await initWasm({ module_or_path: wasm });
});

test("production configuration rejects plaintext relay origins", async () => {
  await assert.rejects(
    createBrowserTransport({
      clientId: "chat.test",
      httpRelay: "http://relay.test/inbox",
      irohRelays: ["https://relay.test/"],
    }),
    (error) => error instanceof Pubky2PubkyBrowserError && error.code === "auth-relay-invalid",
  );
  await assert.rejects(
    createBrowserTransport({
      clientId: "chat.test",
      httpRelay: "https://relay.test/inbox",
      irohRelays: ["http://relay.test/"],
    }),
    (error) => error instanceof Pubky2PubkyBrowserError && error.code === "relay-config-invalid",
  );
});

test("loopback plaintext relays require explicit testnet configuration", async () => {
  const transport = await createBrowserTransport({
    clientId: "chat.test",
    httpRelay: "http://127.0.0.1:8080/inbox",
    irohRelays: ["http://127.0.0.1:3340/"],
    testnet: { enabled: true, pubkyHost: "127.0.0.1" },
  });
  await transport.destroy();

  for (const relay of [
    "http://127.0.0.1/",
    "http://localhost:3340/",
    "http://127.0.0.2:3340/",
    "http://127.0.0.1:3340/path",
    "http://user@127.0.0.1:3340/",
    "http://127.0.0.1:3340/?query=yes",
  ]) {
    await assert.rejects(
      createBrowserTransport({
        clientId: "chat.test",
        httpRelay: "http://127.0.0.1:8080/inbox",
        irohRelays: [relay],
        testnet: { enabled: true, pubkyHost: "127.0.0.1" },
      }),
      (error) => error instanceof Pubky2PubkyBrowserError && error.code === "relay-config-invalid",
    );
  }
});

test("message contract rejects invalid UTF-8 and oversized bodies before transport", async () => {
  const transport = await createBrowserTransport({
    clientId: "chat.test",
    httpRelay: "https://relay.test/inbox",
    irohRelays: ["https://relay.test/"],
  });
  const peer = "y".repeat(52);
  await assert.rejects(
    transport.sendMessage(peer, new Uint8Array([0xff])),
    (error) => error instanceof Pubky2PubkyBrowserError && error.code === "message-invalid",
  );
  await assert.rejects(
    transport.sendMessage(peer, new Uint8Array(4_097)),
    (error) => error instanceof Pubky2PubkyBrowserError && error.code === "message-invalid",
  );
  await transport.destroy();
});

test("mocked core proves publication before success and holds the per-account leader lock through close", async () => {
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const originals = new Map();
  for (const name of [
    "beginAuth",
    "completeAuth",
    "publishAndGoOnline",
    "disconnect",
    "cancelAuth",
  ]) {
    originals.set(name, BrowserCore.prototype[name]);
  }
  let lockHeld = false;
  const lockNames = [];
  const lockManager = {
    request(name, options, callback) {
      lockNames.push(name);
      if (options.ifAvailable && lockHeld) return Promise.resolve(callback(null));
      lockHeld = true;
      return Promise.resolve(callback({ name })).finally(() => {
        lockHeld = false;
      });
    },
  };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { locks: lockManager },
  });

  let publishStarted;
  const sawPublish = new Promise((resolve) => {
    publishStarted = resolve;
  });
  let finishPublish;
  const publication = new Promise((resolve) => {
    finishPublish = resolve;
  });
  let firstPublication = true;
  let closeStarted;
  const sawClose = new Promise((resolve) => {
    closeStarted = resolve;
  });
  let finishClose;
  const close = new Promise((resolve) => {
    finishClose = resolve;
  });
  BrowserCore.prototype.beginAuth = async () => ({
    authorizationUrl: "pubkyauth://signin_grant?secret=kept-in-memory",
  });
  BrowserCore.prototype.completeAuth = async () => ({ identity: "y".repeat(52) });
  BrowserCore.prototype.publishAndGoOnline = async () => {
    if (firstPublication) {
      firstPublication = false;
      publishStarted();
      await publication;
    }
  };
  BrowserCore.prototype.disconnect = async () => {
    closeStarted();
    await close;
  };
  BrowserCore.prototype.cancelAuth = async () => {};

  const config = {
    clientId: "chat.test",
    httpRelay: "https://relay.test/inbox",
    irohRelays: ["https://relay.test/"],
  };
  const first = await createBrowserTransport(config);
  const second = await createBrowserTransport(config);
  const events = [];
  first.subscribe((event) => events.push(event));
  try {
    const goingOnline = first.publishAndGoOnline();
    await sawPublish;
    assert.equal(events.some((event) => event.type === "online-state" && event.online), false);
    finishPublish();
    await goingOnline;
    assert.equal(events.some((event) => event.type === "online-state" && event.online), true);
    assert.equal(lockNames[0], `pubky2pubky:network-leader:${"y".repeat(52)}`);

    await assert.rejects(
      second.publishAndGoOnline(),
      (error) => error instanceof Pubky2PubkyBrowserError && error.code === "another-tab-online",
    );
    await assert.rejects(
      second.removeLocalIdentity("y".repeat(52)),
      (error) => error instanceof Pubky2PubkyBrowserError && error.code === "identity-active",
    );
    const disconnecting = first.disconnect();
    await sawClose;
    await assert.rejects(
      second.publishAndGoOnline(),
      (error) => error instanceof Pubky2PubkyBrowserError && error.code === "another-tab-online",
    );
    finishClose();
    await disconnecting;
    await second.publishAndGoOnline();
  } finally {
    finishPublish();
    finishClose();
    await first.destroy();
    await second.destroy();
    for (const [name, implementation] of originals) {
      BrowserCore.prototype[name] = implementation;
    }
    if (originalNavigator === undefined) delete globalThis.navigator;
    else Object.defineProperty(globalThis, "navigator", originalNavigator);
  }
});

test("mocked core rejects unsafe auth URLs and implausible receipt timestamps", async () => {
  const originalBegin = BrowserCore.prototype.beginAuth;
  const originalComplete = BrowserCore.prototype.completeAuth;
  const originalSend = BrowserCore.prototype.sendMessage;
  const originalCancel = BrowserCore.prototype.cancelAuth;
  const originalDisconnect = BrowserCore.prototype.disconnect;
  BrowserCore.prototype.beginAuth = async () => ({
    authorizationUrl: "https://attacker.test/?secret=must-not-be-emitted",
  });
  BrowserCore.prototype.completeAuth = async () => ({ identity: "y".repeat(52) });
  BrowserCore.prototype.sendMessage = async (peerId) => ({ peerId, acceptedAt: 1 });
  BrowserCore.prototype.cancelAuth = async () => {};
  BrowserCore.prototype.disconnect = async () => {};
  const transport = await createBrowserTransport({
    clientId: "chat.test",
    httpRelay: "https://relay.test/inbox",
    irohRelays: ["https://relay.test/"],
  });
  try {
    await assert.rejects(
      transport.connectWithRing(),
      (error) => error instanceof Pubky2PubkyBrowserError && error.code === "internal-error",
    );
    await assert.rejects(
      transport.sendMessage("b".repeat(52), new TextEncoder().encode("hello")),
      (error) => error instanceof Pubky2PubkyBrowserError && error.code === "internal-error",
    );
  } finally {
    await transport.destroy();
    BrowserCore.prototype.beginAuth = originalBegin;
    BrowserCore.prototype.completeAuth = originalComplete;
    BrowserCore.prototype.sendMessage = originalSend;
    BrowserCore.prototype.cancelAuth = originalCancel;
    BrowserCore.prototype.disconnect = originalDisconnect;
  }
});
