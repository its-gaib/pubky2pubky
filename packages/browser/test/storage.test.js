import assert from "node:assert/strict";
import { afterEach, before, test } from "node:test";
import { webcrypto } from "node:crypto";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";

const cryptoKeyProbe = await webcrypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);

Object.defineProperties(globalThis, {
  crypto: { configurable: true, value: webcrypto },
  CryptoKey: { configurable: true, value: cryptoKeyProbe.constructor },
  indexedDB: { configurable: true, value: indexedDB },
  IDBKeyRange: { configurable: true, value: IDBKeyRange },
  isSecureContext: { configurable: true, value: true },
  location: { configurable: true, value: { origin: "https://chat.test" } },
});

const store = await import("../../../crates/browser-wasm/js/browser_store.js");
const alice = "y".repeat(52);
const bob = "b".repeat(52);
const control = "n".repeat(52);

before(async () => store.__p2pTestReset());
afterEach(async () => store.__p2pTestReset());

test("delegated signing key is nonextractable and restore/device plaintext is sealed", async () => {
  const grantKey = await store.__p2pEnsureGrantKey();
  assert.equal(grantKey.publicKey.byteLength, 32);
  const signature = await store.__p2pSignBytes(grantKey.keyId, new Uint8Array([1, 2, 3]));
  assert.equal(signature.byteLength, 64);

  await store.__p2pSaveIdentity({
    identity: alice,
    keyId: grantKey.keyId,
    clientId: "chat.test",
    homeserver: bob,
    grantId: "grant-1",
    grantExpiresAt: 4_102_444_800,
    restore: JSON.stringify({ grantJws: "header.payload.signature" }),
  });
  const restored = await store.__p2pLoadIdentity(alice);
  assert.deepEqual(Object.keys(restored).sort(), [
    "clientId",
    "grantExpiresAt",
    "grantId",
    "homeserver",
    "identity",
    "keyId",
    "restore",
  ]);
  await store.__p2pSaveNewDeviceState(
    alice,
    control,
    JSON.stringify({ control_signing_secret: "must-not-be-plaintext" }),
  );

  const inspection = await store.__p2pTestInspect(alice);
  assert.equal(inspection.hasEncryptionKey, true);
  assert.equal(inspection.encryptionKeyExtractable, false);
  assert.ok(inspection.identityCiphertextBytes > 16);
  assert.ok(inspection.deviceCiphertextBytes > 16);
  assert.equal(inspection.containsPlaintext, false);
  assert.match(await store.__p2pLoadDeviceState(alice), /must-not-be-plaintext/u);
});

test("authenticated sequence batches are atomic and bind equal counters to their digest", async () => {
  const first = { identity: bob, scope: "locator:one", counter: 3, digest: "A".repeat(43) };
  await store.__p2pRecordSequenceBatch(alice, [first]);
  await store.__p2pRecordSequenceBatch(alice, [first]);
  await assert.rejects(
    store.__p2pRecordSequenceBatch(alice, [{ ...first, digest: "B".repeat(43) }]),
    /sequence-equivocation/u,
  );
  await assert.rejects(
    store.__p2pRecordSequenceBatch(alice, [
      { identity: bob, scope: "locator:new", counter: 1, digest: "C".repeat(43) },
      { ...first, counter: 2 },
    ]),
    /sequence-rollback/u,
  );
  // The first item in the rejected batch was not committed.
  await store.__p2pRecordSequenceBatch(alice, [
    { identity: bob, scope: "locator:new", counter: 1, digest: "D".repeat(43) },
  ]);
});

test("an expired Grant record can be atomically reauthorized without retaining its old key", async () => {
  const oldGrantKey = await store.__p2pEnsureGrantKey();
  await store.__p2pSaveIdentity({
    identity: alice,
    keyId: oldGrantKey.keyId,
    clientId: "chat.test",
    homeserver: bob,
    grantId: "expired-grant",
    grantExpiresAt: 1,
    restore: "expired-restore",
  });
  const newGrantKey = await store.__p2pEnsureGrantKey();
  await store.__p2pSaveIdentity({
    identity: alice,
    keyId: newGrantKey.keyId,
    clientId: "chat.test",
    homeserver: bob,
    grantId: "fresh-grant",
    grantExpiresAt: 4_102_444_800,
    restore: "fresh-restore",
  });
  const restored = await store.__p2pLoadIdentity(alice);
  assert.equal(restored.grantId, "fresh-grant");
  assert.equal(restored.restore, "fresh-restore");
  await assert.rejects(
    store.__p2pLoadGrantPublicKey(oldGrantKey.keyId),
    /grant-key-missing/u,
  );
});

test("publisher allocation is positive, monotonic, and cannot silently reinitialize", async () => {
  await store.__p2pInitializePublisher(alice, alice, control);
  assert.equal(await store.__p2pNextPublisherSequence(alice, alice, control), 1);
  assert.equal(await store.__p2pNextPublisherSequence(alice, alice, control), 2);
  await assert.rejects(
    store.__p2pInitializePublisher(alice, alice, control),
    /publisher-already-initialized/u,
  );
});

test("device rotation and its fresh publisher counter commit atomically", async () => {
  await store.__p2pSaveNewDeviceState(alice, control, "old-device-state");
  assert.equal(await store.__p2pNextPublisherSequence(alice, alice, control), 1);
  const nextControl = "r".repeat(52);
  await store.__p2pReplaceDeviceState(alice, control, nextControl, "new-device-state");
  assert.equal(await store.__p2pLoadDeviceState(alice), "new-device-state");
  assert.equal(await store.__p2pNextPublisherSequence(alice, alice, nextControl), 1);
  assert.equal(await store.__p2pNextPublisherSequence(alice, alice, control), 2);
  await assert.rejects(
    store.__p2pReplaceDeviceState(alice, control, "f".repeat(52), "bad-rotation"),
    /storage-tampered/u,
  );
  assert.equal(await store.__p2pLoadDeviceState(alice), "new-device-state");
});

test("removing an identity deletes its key, sealed state, and account sequence state", async () => {
  const grantKey = await store.__p2pEnsureGrantKey();
  await store.__p2pSaveIdentity({
    identity: alice,
    keyId: grantKey.keyId,
    clientId: "chat.test",
    homeserver: bob,
    grantId: "grant-1",
    grantExpiresAt: 4_102_444_800,
    restore: "restore-metadata",
  });
  await store.__p2pSaveNewDeviceState(alice, control, "device-state");
  await store.__p2pRemoveIdentity(alice);
  await assert.rejects(store.__p2pLoadIdentity(alice), /identity-not-found/u);
  await assert.rejects(store.__p2pLoadGrantPublicKey(grantKey.keyId), /grant-key-missing/u);
  await assert.rejects(
    store.__p2pNextPublisherSequence(alice, alice, control),
    /publisher-state-missing/u,
  );
});
