// Runs the JavaScript binding in Node: `node --test wasm/tests/` after building it into
// wasm/pkg-node with `wasm-bindgen --target nodejs`. The browser build (--target web) has the same API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const { GroupKeys, DeviceKey, Handshake, Channel, initiates } =
  createRequire(import.meta.url)('../pkg-node/symbolon_wasm.js');

const enc = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');
const secret = Uint8Array.from({ length: 32 }, (_, i) => i);
const context = enc('test/v1');

test('derives the same keys as the Rust crate', () => {
  const keys = new GroupKeys(context, secret);
  assert.equal(hex(keys.fingerprint()), 'f7fa2518636b');
  assert.equal(hex(keys.topic(enc('signal'))),
    '0aaf3dd06e80e9403c61c9b61d88868c0ce8e73352cad44508bcbda3cb99ddcb');
  assert.throws(() => new GroupKeys(context, new Uint8Array(16)));
});

test('sealed messages open only with the same key and context', () => {
  const keys = new GroupKeys(context, secret);
  const sealed = keys.seal(enc('hello'), enc('offer'));
  assert.equal(new TextDecoder().decode(keys.open(sealed, enc('offer'))), 'hello');
  assert.throws(() => keys.open(sealed, enc('answer')));
  assert.throws(() => new GroupKeys(enc('other/v1'), secret).open(sealed, enc('offer')));
});

function connect(a, b, keysA, keysB) {
  const prologue = enc('test');
  const initiator = Handshake.initiator(a, b.publicKey, keysA, prologue);
  const responder = Handshake.responder(b, keysB, prologue);
  responder.readMessage(initiator.writeMessage(new Uint8Array()));
  assert.deepEqual(responder.remoteStatic, a.publicKey);
  initiator.readMessage(responder.writeMessage(new Uint8Array()));
  assert.ok(initiator.isFinished && responder.isFinished);
  return [initiator.intoChannel(), responder.intoChannel()];
}

test('two devices of one group get a working channel', () => {
  const keys = new GroupKeys(context, secret);
  const a = DeviceKey.generate();
  const b = DeviceKey.fromPrivate(DeviceKey.generate().privateKey());
  assert.notEqual(initiates(a.publicKey, b.publicKey), initiates(b.publicKey, a.publicKey));
  const [ca, cb] = connect(a, b, keys, keys);
  assert.deepEqual(cb.decrypt(ca.encrypt(enc('hi'))), enc('hi'));
  assert.ok(Channel.maxPlaintext() > 60000);
  assert.throws(() => ca.decrypt(new Uint8Array([1, 2, 3])));
  assert.equal(ca.isOpen, false);
});

test('a device from another group is rejected', () => {
  const other = new GroupKeys(context, Uint8Array.from({ length: 32 }, () => 7));
  assert.throws(() => connect(DeviceKey.generate(), DeviceKey.generate(),
    new GroupKeys(context, secret), other));
});

test('refuses anything that is not a Uint8Array', () => {
  // A string or plain array would otherwise be turned into other bytes without an error.
  for (const bad of ['a'.repeat(32), Array(32).fill(1), new Uint16Array(32), 5, null, undefined]) {
    assert.throws(() => new GroupKeys(context, bad), /Uint8Array/, String(bad));
  }
  assert.throws(() => DeviceKey.fromPrivate('x'.repeat(32)), /Uint8Array/);
  assert.throws(() => initiates(new Uint8Array(32), new Uint8Array(31)), /32-byte/);
});

test('signalling messages and Nostr events', () => {
  const { Signal, SignalBox, EventSigner, newSession, signalFilter } =
    createRequire(import.meta.url)('../pkg-node/symbolon_wasm.js');
  const box = new SignalBox(new GroupKeys(context, secret));
  // The same topic as the Rust crate's known value, since SignalBox uses the label "signal".
  assert.equal(hex(box.topic),
    '0aaf3dd06e80e9403c61c9b61d88868c0ce8e73352cad44508bcbda3cb99ddcb');

  const now = 1_800_000_000;
  const [me, you] = [newSession(), newSession()];
  const device = DeviceKey.generate().publicKey;
  const offer = new Signal('offer', now, me, you, device, enc('v=0'));
  const content = box.seal(offer);
  const opened = box.open(content, now + 1);
  assert.equal(opened.kind, 'offer');
  assert.equal(opened.createdAt, now);
  assert.deepEqual([opened.from, opened.to, opened.device, opened.body], [me, you, device, enc('v=0')]);
  assert.throws(() => box.open(content, now + 3600));
  assert.throws(() => new SignalBox(new GroupKeys(enc('other/v1'), secret)).open(content, now));
  // Announce goes to everyone; an offer to everyone or an unknown kind is refused.
  box.seal(new Signal('announce', now, me, new Uint8Array(16), device, new Uint8Array()));
  assert.throws(() => box.seal(new Signal('offer', now, me, new Uint8Array(16), device, enc('x'))));
  assert.throws(() => new Signal('hello', now, me, you, device, enc('x')));
  assert.throws(() => new Signal('offer', 1.5, me, you, device, enc('x')));

  const signer = EventSigner.generate();
  const event = JSON.parse(signer.signalEvent(now, box.topic, content));
  assert.equal(event.pubkey, signer.publicKey);
  assert.equal(event.content, content);
  assert.deepEqual(event.tags[0], ['t', hex(box.topic)]);
  assert.notEqual(EventSigner.generate().publicKey, signer.publicKey);
  assert.throws(() => signer.signalEvent(now, box.topic, 'needs "escaping"'));
  assert.deepEqual(JSON.parse(signalFilter(box.topic, now)),
    { kinds: [21059], '#t': [hex(box.topic)], since: now });
});
