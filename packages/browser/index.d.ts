export type PubkyId = string;

export type BrowserErrorCode =
  | "another-tab-online"
  | "authentication-required"
  | "auth-relay-invalid"
  | "browser-unsupported"
  | "client-id-invalid"
  | "device-state-exists"
  | "device-state-invalid"
  | "ed25519-unsupported"
  | "grant-key-missing"
  | "identity-active"
  | "identity-exists"
  | "identity-mismatch"
  | "identity-not-found"
  | "identity-verification-failed"
  | "internal-error"
  | "invalid-pubky"
  | "invalid-state"
  | "message-invalid"
  | "peer-already-connected"
  | "peer-not-connected"
  | "peer-unreachable"
  | "publication-failed"
  | "relay-path-unverified"
  | "relay-unreachable"
  | "relay-config-invalid"
  | "request-expired"
  | "session-closed"
  | "sequence-limit"
  | "signing-failed"
  | "storage-failed"
  | "storage-blocked"
  | "storage-invalid"
  | "storage-key-missing"
  | "storage-tampered"
  | "storage-too-large"
  | "testnet-config-invalid"
  | "transport-unavailable";

export class Pubky2PubkyBrowserError extends Error {
  readonly code: BrowserErrorCode;
  constructor(code: BrowserErrorCode);
}

export interface BrowserTransportConfig {
  clientId: string;
  httpRelay: string;
  irohRelays: readonly string[];
  deviceId?: string;
  testnet?: { readonly enabled: true; readonly pubkyHost: string };
}

export type BrowserTransportEvent =
  | { readonly type: "unavailable"; readonly code: "transport-unavailable" }
  | { readonly type: "auth-required"; readonly authorizationUrl: string }
  | { readonly type: "identity"; readonly identity: PubkyId; readonly restored: boolean }
  | { readonly type: "connecting"; readonly peerId?: PubkyId }
  | { readonly type: "online-state"; readonly online: boolean; readonly status: "online" | "offline" }
  | { readonly type: "inbound-request"; readonly id: string; readonly peerId: PubkyId; readonly peerDeviceId: string; readonly receivedAt: number }
  | { readonly type: "inbound-request-expired"; readonly id: string }
  | { readonly type: "peer-verified"; readonly peerId: PubkyId; readonly peerDeviceId: string; readonly path: "relay"; readonly route: "relay"; readonly e2e: true; readonly irohQuicEncrypted: true; readonly pubkyIdentityVerified: true; readonly protocolVersion: 1; readonly alpn: "pubky2pubky/iroh/v1" }
  | { readonly type: "peer-disconnected"; readonly peerId: PubkyId }
  | { readonly type: "message"; readonly peerId: PubkyId; readonly body: Uint8Array; readonly receivedAt: number }
  | { readonly type: "error"; readonly code: BrowserErrorCode };

export interface LocalIdentitySummary {
  readonly identity: PubkyId;
  readonly clientId: string;
  readonly homeserver: PubkyId;
  readonly grantId: string;
  readonly grantExpiresAt: number;
  readonly createdAt: number;
}

export interface MessageReceipt {
  readonly peerId: PubkyId;
  readonly acceptedAt: number;
}

export interface BrowserTransport {
  subscribe(listener: (event: BrowserTransportEvent) => void): () => void;
  initialize(accountId?: PubkyId): Promise<void>;
  connectWithRing(): Promise<PubkyId>;
  listLocalIdentities(): Promise<readonly LocalIdentitySummary[]>;
  removeLocalIdentity(identity: PubkyId): Promise<LocalIdentitySummary>;
  publishAndGoOnline(): Promise<void>;
  connect(peerId: PubkyId): Promise<void>;
  requestPeer(peerId: PubkyId): Promise<void>;
  requestConversation(peerId: PubkyId): Promise<void>;
  acceptInbound(requestId: string): Promise<void>;
  accept(requestId: string): Promise<void>;
  rejectInbound(requestId: string): Promise<void>;
  decline(requestId: string): Promise<void>;
  sendMessage(peerId: PubkyId, bytes: Uint8Array): Promise<MessageReceipt>;
  send(peerId: PubkyId, text: string): Promise<MessageReceipt>;
  /** Close all live peers/publication while retaining this authenticated local identity. */
  disconnect(): Promise<void>;
  /** Close the live object and subscriptions; persisted identity removal remains explicit. */
  destroy(): Promise<void>;
}

export function createBrowserTransport(config: BrowserTransportConfig): Promise<BrowserTransport>;
