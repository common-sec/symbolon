/* @ts-self-types="./symbolon_wasm.d.ts" */

/**
 * Encrypted messages after the handshake. Any rejected message closes it.
 */
class Channel {
    static __wrap(ptr) {
        const obj = Object.create(Channel.prototype);
        obj.__wbg_ptr = ptr;
        ChannelFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ChannelFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_channel_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} ciphertext
     * @returns {Uint8Array}
     */
    decrypt(ciphertext) {
        const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.channel_decrypt(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    encrypt(plaintext) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.channel_encrypt(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @returns {boolean}
     */
    get isOpen() {
        const ret = wasm.channel_isOpen(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * The largest plaintext one message can carry.
     * @returns {number}
     */
    static maxPlaintext() {
        const ret = wasm.channel_maxPlaintext();
        return ret >>> 0;
    }
}
if (Symbol.dispose) Channel.prototype[Symbol.dispose] = Channel.prototype.free;
exports.Channel = Channel;

/**
 * This device's long-term X25519 key for the handshake.
 */
class DeviceKey {
    static __wrap(ptr) {
        const obj = Object.create(DeviceKey.prototype);
        obj.__wbg_ptr = ptr;
        DeviceKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DeviceKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_devicekey_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} private_key
     * @returns {DeviceKey}
     */
    static fromPrivate(private_key) {
        const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.devicekey_fromPrivate(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return DeviceKey.__wrap(ret[0]);
    }
    /**
     * @returns {DeviceKey}
     */
    static generate() {
        const ret = wasm.devicekey_generate();
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return DeviceKey.__wrap(ret[0]);
    }
    /**
     * Only for storing the key on this device.
     * @returns {Uint8Array}
     */
    privateKey() {
        const ret = wasm.devicekey_privateKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    get publicKey() {
        const ret = wasm.devicekey_publicKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) DeviceKey.prototype[Symbol.dispose] = DeviceKey.prototype.free;
exports.DeviceKey = DeviceKey;

/**
 * Every key of a group, derived from its secret. `context` names the app and protocol version, such
 * as `my-app/v1`, so two apps with the same secret get different keys.
 */
class GroupKeys {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GroupKeysFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_groupkeys_free(ptr, 0);
    }
    /**
     * Six bytes for people to compare on their devices.
     * @returns {Uint8Array}
     */
    fingerprint() {
        const ret = wasm.groupkeys_fingerprint(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} context
     * @param {Uint8Array} secret
     */
    constructor(context, secret) {
        const ptr0 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.groupkeys_new(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        GroupKeysFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array} sealed
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    open(sealed, aad) {
        const ptr0 = passArray8ToWasm0(sealed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.groupkeys_open(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    seal(plaintext, aad) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.groupkeys_seal(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * A relay topic for `label` that only group members can compute.
     * @param {Uint8Array} label
     * @returns {Uint8Array}
     */
    topic(label) {
        const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.groupkeys_topic(this.__wbg_ptr, ptr0, len0);
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
}
if (Symbol.dispose) GroupKeys.prototype[Symbol.dispose] = GroupKeys.prototype.free;
exports.GroupKeys = GroupKeys;

/**
 * The Noise IKpsk1 handshake. Turn it into a [`Channel`] once [`Handshake::is_finished`] is true.
 */
class Handshake {
    static __wrap(ptr) {
        const obj = Object.create(Handshake.prototype);
        obj.__wbg_ptr = ptr;
        HandshakeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        HandshakeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_handshake_free(ptr, 0);
    }
    /**
     * @param {DeviceKey} device
     * @param {Uint8Array} remote_public
     * @param {GroupKeys} group
     * @param {Uint8Array} prologue
     * @returns {Handshake}
     */
    static initiator(device, remote_public, group, prologue) {
        _assertClass(device, DeviceKey);
        const ptr0 = passArray8ToWasm0(remote_public, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        _assertClass(group, GroupKeys);
        const ptr1 = passArray8ToWasm0(prologue, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.handshake_initiator(device.__wbg_ptr, ptr0, len0, group.__wbg_ptr, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Handshake.__wrap(ret[0]);
    }
    /**
     * Ends the handshake; this object can't be used afterwards.
     * @returns {Channel}
     */
    intoChannel() {
        const ret = wasm.handshake_intoChannel(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Channel.__wrap(ret[0]);
    }
    /**
     * @returns {boolean}
     */
    get isFinished() {
        const ret = wasm.handshake_isFinished(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @param {Uint8Array} message
     * @returns {Uint8Array}
     */
    readMessage(message) {
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.handshake_readMessage(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * The other device's public key, once its first message has been read.
     * @returns {Uint8Array | undefined}
     */
    get remoteStatic() {
        const ret = wasm.handshake_remoteStatic(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {DeviceKey} device
     * @param {GroupKeys} group
     * @param {Uint8Array} prologue
     * @returns {Handshake}
     */
    static responder(device, group, prologue) {
        _assertClass(device, DeviceKey);
        _assertClass(group, GroupKeys);
        const ptr0 = passArray8ToWasm0(prologue, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.handshake_responder(device.__wbg_ptr, group.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Handshake.__wrap(ret[0]);
    }
    /**
     * @param {Uint8Array} payload
     * @returns {Uint8Array}
     */
    writeMessage(payload) {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.handshake_writeMessage(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
}
if (Symbol.dispose) Handshake.prototype[Symbol.dispose] = Handshake.prototype.free;
exports.Handshake = Handshake;

/**
 * Whether the device with `local_public` starts the handshake with `remote_public`.
 * @param {Uint8Array} local_public
 * @param {Uint8Array} remote_public
 * @returns {boolean}
 */
function initiates(local_public, remote_public) {
    const ptr0 = passArray8ToWasm0(local_public, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(remote_public, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.initiates(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.initiates = initiates;
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_30c8987f7c2ed4e2: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_throw_41e9ee4f547fc59a: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_getRandomValues_a608c4436c19407a: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./symbolon_wasm_bg.js": import0,
    };
}

const ChannelFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_channel_free(ptr, 1));
const DeviceKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_devicekey_free(ptr, 1));
const GroupKeysFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_groupkeys_free(ptr, 1));
const HandshakeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_handshake_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/symbolon_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasmInstance = new WebAssembly.Instance(wasmModule, __wbg_get_imports());
let wasm = wasmInstance.exports;
wasm.__wbindgen_start();
