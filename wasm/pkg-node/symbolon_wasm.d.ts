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
