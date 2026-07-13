import test from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'libsodium-wrappers-sumo';
import {
  KDF_DEFAULTS,
  ready,
  utf8,
  randomBytes,
  wipe,
  deriveUnlockKey,
  deriveVaultKeys,
  wrapRootKey,
  unwrapRootKey,
  wrapFileKey,
  unwrapFileKey,
  encryptManifest,
  decryptManifest,
  createRecoveryCode,
  parseRecoveryCode,
  chunkAad,
  b64,
  computeVersionHash
} from '../src/client/crypto-core.js';

await ready();

test('Argon2id-wrapped vault root round-trips and rejects a wrong passphrase', () => {
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
  const root = randomBytes(32);
  const correct = deriveUnlockKey(utf8('correct horse battery staple 2026'), salt, KDF_DEFAULTS);
  const wrong = deriveUnlockKey(utf8('incorrect horse battery staple'), salt, KDF_DEFAULTS);
  const wrapped = wrapRootKey(root, correct);
  const opened = unwrapRootKey(wrapped.ciphertext, wrapped.nonce, correct);
  assert.deepEqual(opened, root);
  assert.throws(() => unwrapRootKey(wrapped.ciphertext, wrapped.nonce, wrong));
  wipe(salt, root, correct, wrong, wrapped.ciphertext, wrapped.nonce, opened);
});

test('Recovery code is case-insensitive hex with checksum validation', () => {
  const key = randomBytes(32);
  const code = createRecoveryCode(key);
  const parsed = parseRecoveryCode(code.toLowerCase());
  assert.deepEqual(parsed, key);
  const damaged = `${code.slice(0, -1)}${code.endsWith('A') ? 'B' : 'A'}`;
  assert.throws(() => parseRecoveryCode(damaged));
  wipe(key, parsed);
});

test('Per-file key and encrypted manifest are bound to object identity', () => {
  const root = randomBytes(32);
  const { wrappingKey, metadataKey } = deriveVaultKeys(root);
  const fileKey = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  const wrapped = wrapFileKey(fileKey, wrappingKey, '11111111-1111-4111-8111-111111111111', 1);
  const opened = unwrapFileKey(wrapped.ciphertext, wrapped.nonce, wrappingKey, '11111111-1111-4111-8111-111111111111', 1);
  assert.deepEqual(opened, fileKey);
  assert.throws(() => unwrapFileKey(wrapped.ciphertext, wrapped.nonce, wrappingKey, '22222222-2222-4222-8222-222222222222', 1));

  const manifest = {
    formatVersion: 1,
    objectId: '11111111-1111-4111-8111-111111111111',
    version: 1,
    filename: 'test.txt',
    chunkCount: 1
  };
  const encrypted = encryptManifest(manifest, metadataKey, manifest.objectId, 1);
  assert.deepEqual(decryptManifest(encrypted.ciphertext, encrypted.nonce, metadataKey, manifest.objectId, 1), manifest);
  assert.throws(() => decryptManifest(encrypted.ciphertext, encrypted.nonce, metadataKey, '22222222-2222-4222-8222-222222222222', 1));
  wipe(root, wrappingKey, metadataKey, fileKey, wrapped.ciphertext, wrapped.nonce, opened, encrypted.ciphertext, encrypted.nonce);
});

test('Secretstream detects corruption, ordering errors, and final-tag state', () => {
  const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  const objectId = '11111111-1111-4111-8111-111111111111';
  const messages = [utf8('alpha'), utf8('beta'), new Uint8Array()];
  const push = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const ciphers = messages.map((message, index) => sodium.crypto_secretstream_xchacha20poly1305_push(
    push.state,
    message,
    chunkAad(objectId, 1, index, messages.length, 9),
    index === messages.length - 1
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  ));

  const pull = sodium.crypto_secretstream_xchacha20poly1305_init_pull(push.header, key);
  const results = ciphers.map((cipher, index) => sodium.crypto_secretstream_xchacha20poly1305_pull(
    pull,
    cipher,
    chunkAad(objectId, 1, index, messages.length, 9)
  ));
  assert.equal(results[0].tag, sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
  assert.equal(results[2].tag, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
  assert.equal(new TextDecoder().decode(results[0].message), 'alpha');

  const corrupted = ciphers[0].slice();
  corrupted[0] ^= 1;
  const corruptPull = sodium.crypto_secretstream_xchacha20poly1305_init_pull(push.header, key);
  assert.equal(sodium.crypto_secretstream_xchacha20poly1305_pull(
    corruptPull,
    corrupted,
    chunkAad(objectId, 1, 0, messages.length, 9)
  ), false);

  const reorderPull = sodium.crypto_secretstream_xchacha20poly1305_init_pull(push.header, key);
  assert.equal(sodium.crypto_secretstream_xchacha20poly1305_pull(
    reorderPull,
    ciphers[1],
    chunkAad(objectId, 1, 1, messages.length, 9)
  ), false);
  wipe(key, push.header, corrupted, ...messages, ...ciphers, ...results.map((result) => result.message));
});

test('Version hash changes when protected object metadata changes', () => {
  const record = {
    objectId: '11111111-1111-4111-8111-111111111111',
    version: 1,
    chunkCount: 2,
    ciphertextSize: 123,
    streamHeaderB64: b64(randomBytes(24)),
    wrappedDekB64: b64(randomBytes(48)),
    wrappedDekNonceB64: b64(randomBytes(24)),
    encryptedManifestB64: b64(randomBytes(80)),
    manifestNonceB64: b64(randomBytes(24)),
    previousVersionHashB64: null
  };
  const first = computeVersionHash(record);
  const second = computeVersionHash({ ...record, ciphertextSize: 124 });
  assert.notDeepEqual(first, second);
  wipe(first, second);
});
