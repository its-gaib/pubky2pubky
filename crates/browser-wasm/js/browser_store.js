// Browser-only key and state storage. This module is copied into wasm-bindgen's generated
// snippets and is also imported directly by the storage contract tests.

// This fresh namespace deliberately does not open the unpublished pre-v1 database. Protocol-v1
// device keys and anti-rollback state must be generated from scratch, never relabeled.
const DB_NAME = "pubky2pubky-browser-protocol-v1";
const DB_VERSION = 1;
const GRANT_KEYS = "grantKeys";
const IDENTITIES = "identities";
const ENCRYPTION_KEYS = "encryptionKeys";
const DEVICE_STATES = "deviceStates";
const SEQUENCES = "sequences";
const MAX_SIGNING_BYTES = 48 * 1024;
const MAX_SEALED_BYTES = 64 * 1024;
const MAX_IDENTITIES = 64;
const MAX_SEQUENCE_ENTRIES = 4_096;
const MAX_SEQUENCE_BYTES = 1024 * 1024;
const Z32 = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/;
const SCOPE = /^[A-Za-z0-9_:-]{1,128}$/;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;

function failure(code) {
  return new Error(code);
}

function requireRuntime() {
  if (
    !globalThis.isSecureContext ||
    !globalThis.crypto?.subtle ||
    !globalThis.indexedDB ||
    !globalThis.location?.origin ||
    globalThis.location.origin === "null"
  ) {
    throw failure("browser-unsupported");
  }
}

function validateIdentity(value) {
  if (typeof value !== "string" || !Z32.test(value)) {
    throw failure("invalid-pubky");
  }
  return value;
}

function validateBoundedText(value, maximum, code = "storage-invalid") {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw failure(code);
  }
  return value;
}

function randomId() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(failure("storage-failed"));
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(failure("storage-failed"));
    transaction.onabort = () => reject(failure("storage-failed"));
  });
}

function openDatabase() {
  requireRuntime();
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(GRANT_KEYS)) {
        database.createObjectStore(GRANT_KEYS, { keyPath: "keyId" });
      }
      if (!database.objectStoreNames.contains(IDENTITIES)) {
        database.createObjectStore(IDENTITIES, { keyPath: "identity" });
      }
      if (!database.objectStoreNames.contains(ENCRYPTION_KEYS)) {
        database.createObjectStore(ENCRYPTION_KEYS, { keyPath: "identity" });
      }
      if (!database.objectStoreNames.contains(DEVICE_STATES)) {
        database.createObjectStore(DEVICE_STATES, { keyPath: "identity" });
      }
      if (!database.objectStoreNames.contains(SEQUENCES)) {
        database.createObjectStore(SEQUENCES, { keyPath: "key" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(failure("storage-failed"));
    request.onblocked = () => reject(failure("storage-blocked"));
  });
}

async function readOne(storeName, key) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(storeName, "readonly");
    const done = transactionDone(transaction);
    const value = await requestResult(transaction.objectStore(storeName).get(key));
    await done;
    return value;
  } finally {
    database.close();
  }
}

async function addOne(storeName, value) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(storeName, "readwrite");
    const done = transactionDone(transaction);
    transaction.objectStore(storeName).add(value);
    await done;
  } finally {
    database.close();
  }
}

async function ensureEncryptionKey(identity) {
  validateIdentity(identity);
  const existing = await readOne(ENCRYPTION_KEYS, identity);
  if (existing?.key instanceof CryptoKey) return existing.key;
  if (existing !== undefined) throw failure("storage-tampered");

  const generated = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  try {
    await addOne(ENCRYPTION_KEYS, {
      identity,
      version: 1,
      key: generated,
      createdAt: Date.now(),
    });
    return generated;
  } catch (_error) {
    // A concurrent tab may have won the add. Never overwrite its key: load the winner.
    const winner = await readOne(ENCRYPTION_KEYS, identity);
    if (winner?.key instanceof CryptoKey) return winner.key;
    throw failure("storage-failed");
  }
}

function associatedData(purpose, identity, clientId, keyId) {
  return new TextEncoder().encode(
    [
      "pubky2pubky-browser-protocol-v1-state-v1",
      purpose,
      location.origin,
      identity,
      clientId,
      keyId,
    ].join("\u0000"),
  );
}

async function seal(key, plaintext, aad) {
  const bytes = new TextEncoder().encode(plaintext);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_SEALED_BYTES) {
    throw failure("storage-too-large");
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    bytes,
  );
  return { iv: iv.buffer, ciphertext };
}

async function unseal(key, record, aad) {
  if (
    record?.version !== 1 ||
    !(record.iv instanceof ArrayBuffer) ||
    record.iv.byteLength !== 12 ||
    !(record.ciphertext instanceof ArrayBuffer) ||
    record.ciphertext.byteLength === 0 ||
    record.ciphertext.byteLength > MAX_SEALED_BYTES + 16
  ) {
    throw failure("storage-tampered");
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: record.iv,
        additionalData: aad,
        tagLength: 128,
      },
      key,
      record.ciphertext,
    );
    if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_SEALED_BYTES) {
      throw failure("storage-tampered");
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch (_error) {
    throw failure("storage-tampered");
  }
}

export function __p2pBrowserStorageAvailable() {
  try {
    requireRuntime();
    return true;
  } catch (_error) {
    return false;
  }
}

export async function __p2pEnsureGrantKey(keyId) {
  requireRuntime();
  const resolved = keyId === undefined ? randomId() : validateBoundedText(keyId, 128);
  const existing = await readOne(GRANT_KEYS, resolved);
  if (existing !== undefined) {
    if (
      existing?.privateKey instanceof CryptoKey &&
      existing.privateKey.type === "private" &&
      existing.privateKey.extractable === false &&
      existing.publicKeyRaw instanceof ArrayBuffer &&
      existing.publicKeyRaw.byteLength === 32
    ) {
      return { keyId: resolved, publicKey: new Uint8Array(existing.publicKeyRaw) };
    }
    throw failure("storage-tampered");
  }

  let pair;
  try {
    pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  } catch (_error) {
    throw failure("ed25519-unsupported");
  }
  const publicKeyRaw = await crypto.subtle.exportKey("raw", pair.publicKey);
  if (publicKeyRaw.byteLength !== 32 || pair.privateKey.extractable !== false) {
    throw failure("ed25519-unsupported");
  }
  await addOne(GRANT_KEYS, {
    keyId: resolved,
    version: 1,
    privateKey: pair.privateKey,
    publicKeyRaw,
    createdAt: Date.now(),
  });
  return { keyId: resolved, publicKey: new Uint8Array(publicKeyRaw) };
}

export async function __p2pLoadGrantPublicKey(keyId) {
  const resolved = validateBoundedText(keyId, 128);
  const existing = await readOne(GRANT_KEYS, resolved);
  if (
    !(existing?.privateKey instanceof CryptoKey) ||
    existing.privateKey.extractable !== false ||
    !(existing.publicKeyRaw instanceof ArrayBuffer) ||
    existing.publicKeyRaw.byteLength !== 32
  ) {
    throw failure(existing === undefined ? "grant-key-missing" : "storage-tampered");
  }
  return new Uint8Array(existing.publicKeyRaw);
}

export async function __p2pSignGrantInput(keyId, signingInput) {
  const value = validateBoundedText(signingInput, MAX_SIGNING_BYTES, "signing-input-invalid");
  if (!/^[\x20-\x7e]+$/u.test(value)) throw failure("signing-input-invalid");
  return __p2pSignBytes(keyId, new TextEncoder().encode(value));
}

export async function __p2pSignBytes(keyId, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > MAX_SIGNING_BYTES) {
    throw failure("signing-input-invalid");
  }
  const resolved = validateBoundedText(keyId, 128);
  const existing = await readOne(GRANT_KEYS, resolved);
  if (!(existing?.privateKey instanceof CryptoKey) || existing.privateKey.extractable !== false) {
    throw failure(existing === undefined ? "grant-key-missing" : "storage-tampered");
  }
  try {
    return new Uint8Array(
      await crypto.subtle.sign({ name: "Ed25519" }, existing.privateKey, bytes),
    );
  } catch (_error) {
    throw failure("signing-failed");
  }
}

export async function __p2pDeleteGrantKey(keyId) {
  const resolved = validateBoundedText(keyId, 128);
  const database = await openDatabase();
  try {
    const transaction = database.transaction(GRANT_KEYS, "readwrite");
    const done = transactionDone(transaction);
    transaction.objectStore(GRANT_KEYS).delete(resolved);
    await done;
  } finally {
    database.close();
  }
}

function validateIdentityRecord(record) {
  if (record === null || typeof record !== "object") throw failure("storage-invalid");
  const identity = validateIdentity(record.identity);
  const keyId = validateBoundedText(record.keyId, 128);
  const clientId = validateBoundedText(record.clientId, 253);
  const homeserver = validateIdentity(record.homeserver);
  const grantId = validateBoundedText(record.grantId, 128);
  if (!Number.isSafeInteger(record.grantExpiresAt) || record.grantExpiresAt <= 0) {
    throw failure("storage-invalid");
  }
  const restore = validateBoundedText(record.restore, MAX_SEALED_BYTES);
  return {
    identity,
    keyId,
    clientId,
    homeserver,
    grantId,
    grantExpiresAt: record.grantExpiresAt,
    restore,
  };
}

export async function __p2pSaveIdentity(input) {
  const value = validateIdentityRecord(input);
  const key = await ensureEncryptionKey(value.identity);
  const encrypted = await seal(
    key,
    value.restore,
    associatedData("grant", value.identity, value.clientId, value.keyId),
  );
  const database = await openDatabase();
  try {
    const transaction = database.transaction([GRANT_KEYS, IDENTITIES], "readwrite");
    const done = transactionDone(transaction);
    const identities = transaction.objectStore(IDENTITIES);
    const [existing, count] = await Promise.all([
      requestResult(identities.get(value.identity)),
      requestResult(identities.count()),
    ]);
    if (existing !== undefined) {
      let summary;
      try {
        summary = sanitizedIdentity(existing);
      } catch (error) {
        transaction.abort();
        await done.catch(() => {});
        throw error;
      }
      if (summary.grantExpiresAt > Math.floor(Date.now() / 1000)) {
        transaction.abort();
        await done.catch(() => {});
        throw failure("identity-exists");
      }
      if (existing.keyId !== value.keyId) {
        transaction.objectStore(GRANT_KEYS).delete(existing.keyId);
      }
    } else if (count >= MAX_IDENTITIES) {
      transaction.abort();
      await done.catch(() => {});
      throw failure("storage-too-large");
    }
    identities.put({
      version: 1,
      identity: value.identity,
      keyId: value.keyId,
      clientId: value.clientId,
      homeserver: value.homeserver,
      grantId: value.grantId,
      grantExpiresAt: value.grantExpiresAt,
      createdAt: Date.now(),
      ...encrypted,
    });
    await done;
  } finally {
    database.close();
  }
}

function sanitizedIdentity(record) {
  if (
    record?.version !== 1 ||
    !Z32.test(record.identity) ||
    !Z32.test(record.homeserver) ||
    typeof record.clientId !== "string" ||
    record.clientId.length === 0 ||
    record.clientId.length > 253 ||
    typeof record.keyId !== "string" ||
    record.keyId.length === 0 ||
    record.keyId.length > 128 ||
    typeof record.grantId !== "string" ||
    record.grantId.length === 0 ||
    record.grantId.length > 128 ||
    /[\u0000-\u001f\u007f]/u.test(record.clientId) ||
    /[\u0000-\u001f\u007f]/u.test(record.keyId) ||
    /[\u0000-\u001f\u007f]/u.test(record.grantId) ||
    !Number.isSafeInteger(record.grantExpiresAt) ||
    record.grantExpiresAt <= 0 ||
    !Number.isSafeInteger(record.createdAt) ||
    record.createdAt <= 0
  ) {
    throw failure("storage-tampered");
  }
  return {
    identity: record.identity,
    clientId: record.clientId,
    homeserver: record.homeserver,
    grantId: record.grantId,
    grantExpiresAt: record.grantExpiresAt,
    createdAt: record.createdAt,
  };
}

export async function __p2pListIdentities() {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(IDENTITIES, "readonly");
    const done = transactionDone(transaction);
    const records = await requestResult(transaction.objectStore(IDENTITIES).getAll());
    await done;
    if (!Array.isArray(records) || records.length > MAX_IDENTITIES) {
      throw failure("storage-tampered");
    }
    return records.map(sanitizedIdentity);
  } finally {
    database.close();
  }
}

export async function __p2pLoadIdentity(identity) {
  const account = validateIdentity(identity);
  const database = await openDatabase();
  try {
    const transaction = database.transaction([IDENTITIES, ENCRYPTION_KEYS], "readonly");
    const done = transactionDone(transaction);
    const [record, keyRecord] = await Promise.all([
      requestResult(transaction.objectStore(IDENTITIES).get(account)),
      requestResult(transaction.objectStore(ENCRYPTION_KEYS).get(account)),
    ]);
    await done;
    if (record === undefined) throw failure("identity-not-found");
    const summary = sanitizedIdentity(record);
    if (!(keyRecord?.key instanceof CryptoKey) || keyRecord.key.extractable !== false) {
      throw failure("storage-key-missing");
    }
    const restore = await unseal(
      keyRecord.key,
      record,
      associatedData("grant", account, record.clientId, record.keyId),
    );
    return {
      identity: summary.identity,
      keyId: record.keyId,
      clientId: summary.clientId,
      homeserver: summary.homeserver,
      grantId: summary.grantId,
      grantExpiresAt: summary.grantExpiresAt,
      restore,
    };
  } finally {
    database.close();
  }
}

export async function __p2pSaveNewDeviceState(identity, controlKey, plaintext) {
  const account = validateIdentity(identity);
  const control = validateIdentity(controlKey);
  const state = validateBoundedText(plaintext, MAX_SEALED_BYTES);
  const encryptionKey = await ensureEncryptionKey(account);
  const encrypted = await seal(
    encryptionKey,
    state,
    associatedData("device", account, "v1", control),
  );
  const sequenceKey = `${account}\u0000${account}\u0000v1:publisher:${control}`;
  const publisher = {
    key: sequenceKey,
    accountId: account,
    identity: account,
    scope: `v1:publisher:${control}`,
    kind: "publisher",
    counter: 0,
    digest: null,
  };
  const database = await openDatabase();
  try {
    const transaction = database.transaction([DEVICE_STATES, SEQUENCES], "readwrite");
    const done = transactionDone(transaction);
    const devices = transaction.objectStore(DEVICE_STATES);
    const sequences = transaction.objectStore(SEQUENCES);
    const [oldDevice, oldCounter, records] = await Promise.all([
      requestResult(devices.get(account)),
      requestResult(sequences.get(sequenceKey)),
      requestResult(sequences.getAll()),
    ]);
    if (oldDevice !== undefined || oldCounter !== undefined) {
      transaction.abort();
      await done.catch(() => {});
      throw failure("device-state-exists");
    }
    if (Array.isArray(records) && records.some(
      (record) => record?.accountId === account && record?.kind === "publisher",
    )) {
      transaction.abort();
      await done.catch(() => {});
      throw failure("storage-key-missing");
    }
    try {
      validateSequenceCandidate(records, publisher);
    } catch (error) {
      transaction.abort();
      await done.catch(() => {});
      throw error;
    }
    devices.add({ version: 1, identity: account, controlKey: control, ...encrypted });
    sequences.add(publisher);
    await done;
  } finally {
    database.close();
  }
}

export async function __p2pReplaceDeviceState(identity, oldControlKey, newControlKey, plaintext) {
  const account = validateIdentity(identity);
  const oldControl = validateIdentity(oldControlKey);
  const newControl = validateIdentity(newControlKey);
  if (oldControl === newControl) throw failure("storage-tampered");
  const state = validateBoundedText(plaintext, MAX_SEALED_BYTES);
  const encryptionKey = await ensureEncryptionKey(account);
  const encrypted = await seal(
    encryptionKey,
    state,
    associatedData("device", account, "v1", newControl),
  );
  const sequenceKey = `${account}\u0000${account}\u0000v1:publisher:${newControl}`;
  const publisher = {
    key: sequenceKey,
    accountId: account,
    identity: account,
    scope: `v1:publisher:${newControl}`,
    kind: "publisher",
    counter: 0,
    digest: null,
  };
  const database = await openDatabase();
  try {
    const transaction = database.transaction([DEVICE_STATES, SEQUENCES], "readwrite");
    const done = transactionDone(transaction);
    const devices = transaction.objectStore(DEVICE_STATES);
    const sequences = transaction.objectStore(SEQUENCES);
    const [oldDevice, newCounter, records] = await Promise.all([
      requestResult(devices.get(account)),
      requestResult(sequences.get(sequenceKey)),
      requestResult(sequences.getAll()),
    ]);
    if (
      oldDevice?.version !== 1 ||
      oldDevice.identity !== account ||
      oldDevice.controlKey !== oldControl ||
      newCounter !== undefined
    ) {
      transaction.abort();
      await done.catch(() => {});
      throw failure("storage-tampered");
    }
    try {
      validateSequenceCandidate(records, publisher);
    } catch (error) {
      transaction.abort();
      await done.catch(() => {});
      throw error;
    }
    devices.put({ version: 1, identity: account, controlKey: newControl, ...encrypted });
    sequences.add(publisher);
    await done;
  } finally {
    database.close();
  }
}

export async function __p2pLoadDeviceState(identity) {
  const account = validateIdentity(identity);
  const database = await openDatabase();
  try {
    const transaction = database.transaction([DEVICE_STATES, ENCRYPTION_KEYS], "readonly");
    const done = transactionDone(transaction);
    const [record, keyRecord] = await Promise.all([
      requestResult(transaction.objectStore(DEVICE_STATES).get(account)),
      requestResult(transaction.objectStore(ENCRYPTION_KEYS).get(account)),
    ]);
    await done;
    if (record === undefined) return undefined;
    if (
      record?.version !== 1 ||
      record.identity !== account ||
      !Z32.test(record.controlKey) ||
      !(keyRecord?.key instanceof CryptoKey) ||
      keyRecord.key.extractable !== false
    ) {
      throw failure(keyRecord === undefined ? "storage-key-missing" : "storage-tampered");
    }
    return await unseal(
      keyRecord.key,
      record,
      associatedData("device", account, "v1", record.controlKey),
    );
  } finally {
    database.close();
  }
}

export async function __p2pHasPublisherSequence(accountId, identity, controlKey) {
  const account = validateIdentity(accountId);
  const owner = validateIdentity(identity);
  const control = validateIdentity(controlKey);
  const key = sequenceKey(account, owner, `v1:publisher:${control}`);
  const record = await readOne(SEQUENCES, key);
  if (record === undefined) return false;
  validateStoredSequence(record);
  if (record.kind !== "publisher") throw failure("storage-tampered");
  return true;
}

export async function __p2pRemoveIdentity(identity) {
  const account = validateIdentity(identity);
  const identityRecord = await readOne(IDENTITIES, account);
  if (identityRecord === undefined) throw failure("identity-not-found");
  const summary = sanitizedIdentity(identityRecord);
  const keyId = validateBoundedText(identityRecord.keyId, 128);
  const database = await openDatabase();
  try {
    const transaction = database.transaction(
      [GRANT_KEYS, IDENTITIES, ENCRYPTION_KEYS, DEVICE_STATES, SEQUENCES],
      "readwrite",
    );
    const done = transactionDone(transaction);
    transaction.objectStore(GRANT_KEYS).delete(keyId);
    transaction.objectStore(IDENTITIES).delete(account);
    transaction.objectStore(ENCRYPTION_KEYS).delete(account);
    transaction.objectStore(DEVICE_STATES).delete(account);
    const sequences = transaction.objectStore(SEQUENCES);
    const request = sequences.openCursor();
    await new Promise((resolve, reject) => {
      request.onerror = () => reject(failure("storage-failed"));
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null) {
          resolve();
          return;
        }
        if (cursor.value?.accountId === account) cursor.delete();
        cursor.continue();
      };
    });
    await done;
    return summary;
  } finally {
    database.close();
  }
}

function sequenceKey(accountId, identity, scope) {
  return `${validateIdentity(accountId)}\u0000${validateIdentity(identity)}\u0000${validateScope(scope)}`;
}

function validateScope(scope) {
  if (typeof scope !== "string" || !SCOPE.test(scope)) throw failure("sequence-invalid");
  if (scope.startsWith("v1:publisher:")) {
    const control = scope.slice("v1:publisher:".length);
    if (!Z32.test(control)) throw failure("sequence-invalid");
  }
  return scope;
}

function validateCounter(counter, allowZero = false) {
  if (!Number.isSafeInteger(counter) || counter < (allowZero ? 0 : 1)) {
    throw failure("sequence-invalid");
  }
  return counter;
}

function validateDigest(digest) {
  if (typeof digest !== "string" || !DIGEST.test(digest)) throw failure("sequence-invalid");
  return digest;
}

function validateObservation(accountId, observation) {
  if (observation === null || typeof observation !== "object") throw failure("sequence-invalid");
  const identity = validateIdentity(observation.identity);
  const scope = validateScope(observation.scope);
  if (scope.startsWith("v1:publisher:")) throw failure("sequence-invalid");
  const counter = validateCounter(observation.counter);
  const digest = validateDigest(observation.digest);
  return {
    key: sequenceKey(accountId, identity, scope),
    accountId,
    identity,
    scope,
    kind: "authenticated",
    counter,
    digest,
  };
}

function validateStoredSequence(record) {
  if (
    record === null ||
    typeof record !== "object" ||
    typeof record.key !== "string" ||
    !Z32.test(record.accountId) ||
    !Z32.test(record.identity) ||
    !SCOPE.test(record.scope) ||
    !["publisher", "authenticated"].includes(record.kind)
  ) {
    throw failure("storage-tampered");
  }
  if (record.kind === "publisher" && !record.scope.startsWith("v1:publisher:")) {
    throw failure("storage-tampered");
  }
  if (record.kind === "authenticated" && record.scope.startsWith("v1:publisher:")) {
    throw failure("storage-tampered");
  }
  validateCounter(record.counter, record.kind === "publisher");
  if (record.kind === "authenticated") validateDigest(record.digest);
  if (record.kind !== "authenticated" && record.digest !== null) throw failure("storage-tampered");
  if (record.key !== sequenceKey(record.accountId, record.identity, record.scope)) {
    throw failure("storage-tampered");
  }
  return record;
}

function estimateSequenceBytes(records) {
  const encoded = new TextEncoder().encode(JSON.stringify(records));
  if (encoded.byteLength > MAX_SEQUENCE_BYTES) throw failure("sequence-limit");
}

function validateSequenceCandidate(records, candidate) {
  if (!Array.isArray(records) || records.length >= MAX_SEQUENCE_ENTRIES) {
    throw failure(Array.isArray(records) ? "sequence-limit" : "storage-tampered");
  }
  records.forEach(validateStoredSequence);
  validateStoredSequence(candidate);
  estimateSequenceBytes([...records, candidate]);
}

async function updateSequences(update) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(SEQUENCES, "readwrite");
    const done = transactionDone(transaction);
    const store = transaction.objectStore(SEQUENCES);
    const records = await requestResult(store.getAll());
    try {
      if (!Array.isArray(records) || records.length > MAX_SEQUENCE_ENTRIES) {
        throw failure("storage-tampered");
      }
      const current = new Map(records.map((record) => {
        validateStoredSequence(record);
        return [record.key, record];
      }));
      const changed = update(current);
      if (current.size > MAX_SEQUENCE_ENTRIES) throw failure("sequence-limit");
      estimateSequenceBytes([...current.values()]);
      for (const record of changed) store.put(record);
    } catch (error) {
      try {
        transaction.abort();
      } catch (_abortError) {
        // The transaction may already have failed closed.
      }
      await done.catch(() => {});
      throw error;
    }
    await done;
  } finally {
    database.close();
  }
}

export async function __p2pInitializePublisher(accountId, identity, controlKey) {
  const account = validateIdentity(accountId);
  const owner = validateIdentity(identity);
  const control = validateIdentity(controlKey);
  const scope = `v1:publisher:${control}`;
  const key = sequenceKey(account, owner, scope);
  await updateSequences((current) => {
    if (current.has(key)) throw failure("publisher-already-initialized");
    const record = {
      key,
      accountId: account,
      identity: owner,
      scope,
      kind: "publisher",
      counter: 0,
      digest: null,
    };
    current.set(key, record);
    return [record];
  });
}

export async function __p2pNextPublisherSequence(accountId, identity, controlKey) {
  const account = validateIdentity(accountId);
  const owner = validateIdentity(identity);
  const control = validateIdentity(controlKey);
  const key = sequenceKey(account, owner, `v1:publisher:${control}`);
  let next;
  await updateSequences((current) => {
    const record = current.get(key);
    if (record?.kind !== "publisher") throw failure("publisher-state-missing");
    next = validateCounter(record.counter, true) + 1;
    validateCounter(next);
    const updated = { ...record, counter: next };
    current.set(key, updated);
    return [updated];
  });
  return next;
}

export async function __p2pRecordSequenceBatch(accountId, observations) {
  const account = validateIdentity(accountId);
  if (!Array.isArray(observations) || observations.length > 128) {
    throw failure("sequence-invalid");
  }
  const prepared = new Map();
  for (const input of observations) {
    const observation = validateObservation(account, input);
    const duplicate = prepared.get(observation.key);
    if (
      duplicate &&
      (duplicate.counter !== observation.counter || duplicate.digest !== observation.digest)
    ) {
      throw failure("sequence-batch-conflict");
    }
    prepared.set(observation.key, observation);
  }
  if (prepared.size === 0) return;

  await updateSequences((current) => {
    const changed = [];
    // Validate the complete batch before mutating the staged map.
    for (const observation of prepared.values()) {
      const previous = current.get(observation.key);
      if (previous?.kind === "publisher") throw failure("sequence-invalid");
      if (previous && observation.counter < previous.counter) {
        throw failure("sequence-rollback");
      }
      if (
        previous?.kind === "authenticated" &&
        observation.counter === previous.counter &&
        observation.digest !== previous.digest
      ) {
        throw failure("sequence-equivocation");
      }
    }
    for (const observation of prepared.values()) {
      const previous = current.get(observation.key);
      if (
        previous?.kind === "authenticated" &&
        observation.counter === previous.counter &&
        observation.digest === previous.digest
      ) {
        continue;
      }
      current.set(observation.key, observation);
      changed.push(observation);
    }
    return changed;
  });
}

// Test-only hooks deliberately expose metadata/key properties, never key bytes.
export async function __p2pTestInspect(identity) {
  const account = validateIdentity(identity);
  const key = await readOne(ENCRYPTION_KEYS, account);
  const grant = await readOne(IDENTITIES, account);
  const device = await readOne(DEVICE_STATES, account);
  return {
    hasEncryptionKey: key?.key instanceof CryptoKey,
    encryptionKeyExtractable: key?.key?.extractable,
    identityCiphertextBytes: grant?.ciphertext?.byteLength ?? 0,
    deviceCiphertextBytes: device?.ciphertext?.byteLength ?? 0,
    containsPlaintext: JSON.stringify({ grant, device }).includes("control_signing_secret"),
  };
}

export async function __p2pTestReset() {
  if (!globalThis.indexedDB) return;
  await new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(failure("storage-failed"));
    request.onblocked = () => reject(failure("storage-blocked"));
  });
}
