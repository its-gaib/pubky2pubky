/* tslint:disable */
/* eslint-disable */
/**
 * The `ReadableStreamType` enum.
 *
 * *This API requires the following crate features to be activated: `ReadableStreamType`*
 */

export type ReadableStreamType = "bytes";

/**
 * Browser-owned authentication, device-state, and v4 relay-only network core.
 */
export class BrowserCore {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Accept one offline-authenticated inbound request and run mutual live-authority proofs.
     */
    acceptInbound(request_id: string): Promise<any>;
    /**
     * Begin a Ring sign-in flow using one nonextractable browser-held Ed25519 key.
     */
    beginAuth(client_id: string, http_relay: string, expected_identity?: string | null, testnet_host?: string | null): Promise<any>;
    /**
     * Cancel an in-memory Ring approval/restore operation and discard any unpublished key.
     */
    cancelAuth(): Promise<void>;
    /**
     * Wait for approval, validate the exact identity/grant, and persist encrypted restore data.
     */
    completeAuth(): Promise<any>;
    /**
     * Close the endpoint, all peers, and pending consent requests while retaining local auth and
     * protected device state for a later reconnect.
     */
    disconnect(): Promise<void>;
    /**
     * Synchronous feature check for secure-context `WebCrypto` and `IndexedDB`.
     */
    static isStorageAvailable(): boolean;
    /**
     * Return public summaries only; encrypted restore material never leaves this core.
     */
    listLocalIdentities(): Promise<any>;
    /**
     * Construct a browser core. No persistent or network work occurs here.
     */
    constructor(on_event: Function);
    /**
     * Prepare or restore the protected v4 device credential. This does not claim network success.
     */
    prepareDevice(device_id: string): Promise<any>;
    /**
     * Bind the relay-only endpoint, allocate/publish a locator, and start inbound processing.
     */
    publishAndGoOnline(device_id: string, relay_urls: any, allow_loopback_testnet: boolean): Promise<any>;
    /**
     * Reject one inbound request without making sender-directed Pubky network requests.
     */
    rejectInbound(request_id: string): void;
    /**
     * Remove all package-owned local material for one offline identity.
     */
    removeLocalIdentity(identity: string): Promise<any>;
    /**
     * Resolve and connect to a user-selected Pubky identity. The result is withheld until the
     * complete mutual currentness exchange succeeds.
     */
    requestPeer(peer_identity: string): Promise<any>;
    /**
     * Restore a delegated session only when `IndexedDB` still has the exact nonextractable key.
     */
    restoreIdentity(identity: string, client_id: string, testnet_host?: string | null): Promise<any>;
    /**
     * Send one bounded, valid UTF-8 payload over an already mutually verified QUIC peer.
     */
    sendMessage(peer_identity: string, data: Uint8Array): Promise<any>;
}

export class IntoUnderlyingByteSource {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    cancel(): void;
    pull(controller: ReadableByteStreamController): Promise<any>;
    start(controller: ReadableByteStreamController): void;
    readonly autoAllocateChunkSize: number;
    readonly type: ReadableStreamType;
}

export class IntoUnderlyingSink {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    abort(reason: any): Promise<any>;
    close(): Promise<any>;
    write(chunk: any): Promise<any>;
}

export class IntoUnderlyingSource {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    cancel(): void;
    pull(controller: ReadableStreamDefaultController): Promise<any>;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_browsercore_free: (a: number, b: number) => void;
    readonly browsercore_acceptInbound: (a: number, b: number, c: number) => any;
    readonly browsercore_beginAuth: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => any;
    readonly browsercore_cancelAuth: (a: number) => any;
    readonly browsercore_completeAuth: (a: number) => any;
    readonly browsercore_disconnect: (a: number) => any;
    readonly browsercore_isStorageAvailable: () => number;
    readonly browsercore_listLocalIdentities: (a: number) => any;
    readonly browsercore_new: (a: any) => number;
    readonly browsercore_prepareDevice: (a: number, b: number, c: number) => any;
    readonly browsercore_publishAndGoOnline: (a: number, b: number, c: number, d: any, e: number) => any;
    readonly browsercore_rejectInbound: (a: number, b: number, c: number) => [number, number];
    readonly browsercore_removeLocalIdentity: (a: number, b: number, c: number) => any;
    readonly browsercore_requestPeer: (a: number, b: number, c: number) => any;
    readonly browsercore_restoreIdentity: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly browsercore_sendMessage: (a: number, b: number, c: number, d: any) => any;
    readonly ring_core_0_17_14__bn_mul_mont: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly __wbg_intounderlyingsource_free: (a: number, b: number) => void;
    readonly intounderlyingsource_cancel: (a: number) => void;
    readonly intounderlyingsource_pull: (a: number, b: any) => any;
    readonly __wbg_intounderlyingbytesource_free: (a: number, b: number) => void;
    readonly intounderlyingbytesource_autoAllocateChunkSize: (a: number) => number;
    readonly intounderlyingbytesource_cancel: (a: number) => void;
    readonly intounderlyingbytesource_pull: (a: number, b: any) => any;
    readonly intounderlyingbytesource_start: (a: number, b: any) => void;
    readonly intounderlyingbytesource_type: (a: number) => number;
    readonly __wbg_intounderlyingsink_free: (a: number, b: number) => void;
    readonly intounderlyingsink_abort: (a: number, b: any) => any;
    readonly intounderlyingsink_close: (a: number) => any;
    readonly intounderlyingsink_write: (a: number, b: any) => any;
    readonly wasm_bindgen__convert__closures_____invoke__h51b1f1bcebfca655: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h28f7d93b133d0813: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__hde6f166c283822a3: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h354fcefe2c4d66dc: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h208de9cb13c09a06: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h7de5358ffcde78cb: (a: number, b: number) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h66edf16271dd4c69: (a: number, b: number) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h3cfa906194e71f00: (a: number, b: number) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h10aee7c40130eda9: (a: number, b: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
