/* tslint:disable */
/* eslint-disable */

/**
 * Encrypted messages after the handshake. Any rejected message closes it.
 */
export class Channel {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    decrypt(ciphertext: Uint8Array): Uint8Array;
    encrypt(plaintext: Uint8Array): Uint8Array;
    /**
     * The largest plaintext one message can carry.
     */
    static maxPlaintext(): number;
    readonly isOpen: boolean;
}

/**
 * This device's long-term X25519 key for the handshake.
 */
export class DeviceKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static fromPrivate(private_key: Uint8Array): DeviceKey;
    static generate(): DeviceKey;
    /**
     * Only for storing the key on this device.
     */
    privateKey(): Uint8Array;
    readonly publicKey: Uint8Array;
}

/**
 * Every key of a group, derived from its secret. `context` names the app and protocol version, such
 * as `my-app/v1`, so two apps with the same secret get different keys.
 */
export class GroupKeys {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Six bytes for people to compare on their devices.
     */
    fingerprint(): Uint8Array;
    constructor(context: Uint8Array, secret: Uint8Array);
    open(sealed: Uint8Array, aad: Uint8Array): Uint8Array;
    seal(plaintext: Uint8Array, aad: Uint8Array): Uint8Array;
    /**
     * A relay topic for `label` that only group members can compute.
     */
    topic(label: Uint8Array): Uint8Array;
}

/**
 * The Noise IKpsk1 handshake. Turn it into a [`Channel`] once [`Handshake::is_finished`] is true.
 */
export class Handshake {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static initiator(device: DeviceKey, remote_public: Uint8Array, group: GroupKeys, prologue: Uint8Array): Handshake;
    /**
     * Ends the handshake; this object can't be used afterwards.
     */
    intoChannel(): Channel;
    readMessage(message: Uint8Array): Uint8Array;
    static responder(device: DeviceKey, group: GroupKeys, prologue: Uint8Array): Handshake;
    writeMessage(payload: Uint8Array): Uint8Array;
    readonly isFinished: boolean;
    /**
     * The other device's public key, once its first message has been read.
     */
    readonly remoteStatic: Uint8Array | undefined;
}

/**
 * Whether the device with `local_public` starts the handshake with `remote_public`.
 */
export function initiates(local_public: Uint8Array, remote_public: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_channel_free: (a: number, b: number) => void;
    readonly __wbg_devicekey_free: (a: number, b: number) => void;
    readonly __wbg_groupkeys_free: (a: number, b: number) => void;
    readonly __wbg_handshake_free: (a: number, b: number) => void;
    readonly channel_decrypt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly channel_encrypt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly channel_isOpen: (a: number) => number;
    readonly channel_maxPlaintext: () => number;
    readonly devicekey_fromPrivate: (a: number, b: number) => [number, number, number];
    readonly devicekey_generate: () => [number, number, number];
    readonly devicekey_privateKey: (a: number) => [number, number];
    readonly devicekey_publicKey: (a: number) => [number, number];
    readonly groupkeys_fingerprint: (a: number) => [number, number];
    readonly groupkeys_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly groupkeys_open: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly groupkeys_seal: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly groupkeys_topic: (a: number, b: number, c: number) => [number, number];
    readonly handshake_initiator: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly handshake_intoChannel: (a: number) => [number, number, number];
    readonly handshake_isFinished: (a: number) => number;
    readonly handshake_readMessage: (a: number, b: number, c: number) => [number, number, number, number];
    readonly handshake_remoteStatic: (a: number) => [number, number];
    readonly handshake_responder: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly handshake_writeMessage: (a: number, b: number, c: number) => [number, number, number, number];
    readonly initiates: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
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
