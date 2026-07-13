import sodium from 'libsodium-wrappers-sumo';

export const FORMAT_VERSION = 1;
export const PACKAGE_MAGIC = 'BPCV0001';
export const PACKAGE_END_MAGIC = 'BPCVEND1';
export const CHUNK_SIZE = 4 * 1024 * 1024;
export const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024;
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MIN_PASSPHRASE_BYTES = 20;
export const KDF_DEFAULTS = Object.freeze({
  algorithm: 'argon2id13',
  opsLimit: 4,
  memLimit: 128 * 1024 * 1024,
  outputLength: 32
});

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export async function ready() {
  await sodium.ready;
  return sodium;
}

export function utf8(value) {
  return encoder.encode(value);
}

export function fromUtf8(value) {
  return decoder.decode(value);
}

export function b64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function unb64(value) {
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function randomBytes(length) {
  return sodium.randombytes_buf(length);
}

export function wipe(...values) {
  for (const value of values) {
    if (value instanceof Uint8Array && value.byteLength > 0) sodium.memzero(value);
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function encodeJson(value) {
  return utf8(canonicalJson(value));
}

export function decodeJson(bytes) {
  return JSON.parse(fromUtf8(bytes));
}

export function sha256(bytes) {
  return sodium.crypto_hash_sha256(bytes);
}

export function hashObject(value) {
  return sha256(encodeJson(value));
}

export function deriveVaultKeys(rootKey) {
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== sodium.crypto_kdf_KEYBYTES) {
    throw new Error('Invalid vault root key.');
  }
  return {
    wrappingKey: sodium.crypto_kdf_derive_from_key(32, 1, 'BPWRAP01', rootKey),
    metadataKey: sodium.crypto_kdf_derive_from_key(32, 2, 'BPMETA01', rootKey)
  };
}

export function deriveUnlockKey(passphraseBytes, salt, params = KDF_DEFAULTS) {
  if (!(passphraseBytes instanceof Uint8Array) || passphraseBytes.length < MIN_PASSPHRASE_BYTES) {
    throw new Error('Passphrase must contain at least 20 UTF-8 bytes.');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new Error('Invalid Argon2id salt.');
  }
  if (params.algorithm !== 'argon2id13' || params.outputLength !== 32) {
    throw new Error('Unsupported password derivation parameters.');
  }
  if (!Number.isInteger(params.opsLimit) || params.opsLimit < 3 || params.opsLimit > 10) {
    throw new Error('Argon2id operation limit is outside the accepted security range.');
  }
  if (!Number.isInteger(params.memLimit) || params.memLimit < 64 * 1024 * 1024 || params.memLimit > 256 * 1024 * 1024) {
    throw new Error('Argon2id memory limit is outside the accepted security range.');
  }
  return sodium.crypto_pwhash(
    params.outputLength,
    passphraseBytes,
    salt,
    params.opsLimit,
    params.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

export function vaultRootAad(vaultId = 'primary') {
  return utf8(`blackpine:vault-root:v${FORMAT_VERSION}:${vaultId}`);
}

export function recoveryRootAad(vaultId = 'primary') {
  return utf8(`blackpine:vault-recovery:v${FORMAT_VERSION}:${vaultId}`);
}

export function fileKeyAad(objectId, version) {
  return utf8(`blackpine:file-key:v${FORMAT_VERSION}:${objectId}:${version}`);
}

export function manifestAad(objectId, version) {
  return utf8(`blackpine:manifest:v${FORMAT_VERSION}:${objectId}:${version}`);
}

export function chunkAad(objectId, version, index, count, plaintextSize) {
  return utf8(`blackpine:chunk:v${FORMAT_VERSION}:${objectId}:${version}:${index}:${count}:${plaintextSize}`);
}

export function aeadEncrypt(plaintext, key, aad) {
  const nonce = randomBytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key
  );
  return { nonce, ciphertext };
}

export function aeadDecrypt(ciphertext, nonce, key, aad) {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    key
  );
}

export function wrapRootKey(rootKey, unlockKey, vaultId = 'primary') {
  return aeadEncrypt(rootKey, unlockKey, vaultRootAad(vaultId));
}

export function unwrapRootKey(ciphertext, nonce, unlockKey, vaultId = 'primary') {
  const rootKey = aeadDecrypt(ciphertext, nonce, unlockKey, vaultRootAad(vaultId));
  if (rootKey.length !== sodium.crypto_kdf_KEYBYTES) throw new Error('Invalid root key length.');
  return rootKey;
}

export function wrapFileKey(fileKey, wrappingKey, objectId, version) {
  return aeadEncrypt(fileKey, wrappingKey, fileKeyAad(objectId, version));
}

export function unwrapFileKey(ciphertext, nonce, wrappingKey, objectId, version) {
  const key = aeadDecrypt(ciphertext, nonce, wrappingKey, fileKeyAad(objectId, version));
  if (key.length !== sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES) {
    throw new Error('Invalid file key length.');
  }
  return key;
}

export function encryptManifest(manifest, metadataKey, objectId, version) {
  const encoded = encodeJson(manifest);
  if (encoded.byteLength > MAX_MANIFEST_BYTES) throw new Error('Encrypted manifest is too large.');
  return aeadEncrypt(encoded, metadataKey, manifestAad(objectId, version));
}

export function decryptManifest(ciphertext, nonce, metadataKey, objectId, version) {
  const plaintext = aeadDecrypt(ciphertext, nonce, metadataKey, manifestAad(objectId, version));
  if (plaintext.byteLength > MAX_MANIFEST_BYTES) throw new Error('Manifest exceeds safe limit.');
  const manifest = decodeJson(plaintext);
  wipe(plaintext);
  if (manifest.formatVersion !== FORMAT_VERSION || manifest.objectId !== objectId || manifest.version !== version) {
    throw new Error('Manifest identity validation failed.');
  }
  return manifest;
}

export function createRecoveryCode(recoveryKey) {
  const checksum = sodium.crypto_generichash(4, recoveryKey);
  const encoded = sodium.to_hex(concatBytes(recoveryKey, checksum)).toUpperCase();
  wipe(checksum);
  return encoded.match(/.{1,6}/g).join('-');
}

export function parseRecoveryCode(code) {
  const normalized = String(code).replace(/[^A-Fa-f0-9]/g, '');
  if (normalized.length !== 72) throw new Error('Recovery code length is invalid.');
  let decoded;
  try {
    decoded = sodium.from_hex(normalized);
  } catch {
    throw new Error('Recovery code is not valid.');
  }
  if (decoded.length !== 36) throw new Error('Recovery code length is invalid.');
  const key = decoded.slice(0, 32);
  const checksum = decoded.slice(32);
  const expected = sodium.crypto_generichash(4, key);
  const valid = sodium.memcmp(checksum, expected);
  wipe(decoded, expected);
  if (!valid) {
    wipe(key, checksum);
    throw new Error('Recovery code checksum failed.');
  }
  wipe(checksum);
  return key;
}

export function computeVersionHash(record) {
  return hashObject({
    formatVersion: FORMAT_VERSION,
    objectId: record.objectId,
    version: record.version,
    chunkCount: record.chunkCount,
    ciphertextSize: record.ciphertextSize,
    streamHeaderB64: record.streamHeaderB64,
    wrappedDekB64: record.wrappedDekB64,
    wrappedDekNonceB64: record.wrappedDekNonceB64,
    encryptedManifestB64: record.encryptedManifestB64,
    manifestNonceB64: record.manifestNonceB64,
    previousVersionHashB64: record.previousVersionHashB64 || null
  });
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, item) => sum + item.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    output.set(item, offset);
    offset += item.byteLength;
  }
  return output;
}

export function uint32be(number) {
  if (!Number.isSafeInteger(number) || number < 0 || number > 0xffffffff) {
    throw new Error('Integer is outside uint32 range.');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, number, false);
  return bytes;
}

export function readUint32be(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 4) throw new Error('Expected four bytes.');
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
}

export function safeFilename(name, fallback = 'decrypted-file') {
  const cleaned = String(name || '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 180);
  return cleaned || fallback;
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return 'unknown';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}
