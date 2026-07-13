import sodium from 'libsodium-wrappers-sumo';
import {
  FORMAT_VERSION,
  PACKAGE_MAGIC,
  PACKAGE_END_MAGIC,
  CHUNK_SIZE,
  MAX_FILE_SIZE,
  KDF_DEFAULTS,
  ready,
  utf8,
  fromUtf8,
  b64,
  unb64,
  randomBytes,
  wipe,
  encodeJson,
  decodeJson,
  sha256,
  deriveVaultKeys,
  deriveUnlockKey,
  vaultRootAad,
  recoveryRootAad,
  chunkAad,
  aeadEncrypt,
  aeadDecrypt,
  wrapRootKey,
  unwrapRootKey,
  wrapFileKey,
  unwrapFileKey,
  encryptManifest,
  decryptManifest,
  createRecoveryCode,
  parseRecoveryCode,
  concatBytes,
  uint32be,
  readUint32be,
  safeFilename,
  computeVersionHash
} from './crypto-core.js';

await ready();

let apiToken = '';
let vaultRootKey = null;
let wrappingKey = null;
let metadataKey = null;
let pendingLocalDecrypt = null;
let outputSequence = 0;
const outputAcks = new Map();

const MAX_HEADER_BYTES = 256 * 1024;
const MAX_FOOTER_BYTES = 2 * 1024 * 1024;
const MAX_CIPHER_CHUNK = CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
const MAX_CHUNKS = Math.ceil(MAX_FILE_SIZE / CHUNK_SIZE);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function emit(id, event, data = {}, transfer = []) {
  self.postMessage({ id, kind: 'event', event, data }, transfer);
}

function emitOutputChunk(id, buffer) {
  const sequence = ++outputSequence;
  const key = `${id}:${sequence}`;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      outputAcks.delete(key);
      reject(new Error('Output writer stopped responding.'));
    }, 120000);
    outputAcks.set(key, { resolve, reject, timeout });
    self.postMessage({ id, kind: 'event', event: 'output-chunk', data: { chunk: buffer, sequence } }, [buffer]);
  });
}

function complete(id, result = {}) {
  self.postMessage({ id, kind: 'result', result });
}

function fail(id, error) {
  const message = error instanceof Error ? error.message : 'Unknown operation failure.';
  self.postMessage({ id, kind: 'error', error: message });
}

function clearVaultKeys() {
  wipe(vaultRootKey, wrappingKey, metadataKey);
  vaultRootKey = null;
  wrappingKey = null;
  metadataKey = null;
}

function setVaultRoot(root) {
  clearVaultKeys();
  const keys = deriveVaultKeys(root);
  vaultRootKey = root;
  wrappingKey = keys.wrappingKey;
  metadataKey = keys.metadataKey;
}

function requireToken() {
  if (!apiToken || apiToken.length < 48) throw new Error('Server access token is not set or is too short. Run AUTH first.');
}

function requireUnlocked() {
  if (!vaultRootKey || !wrappingKey || !metadataKey) throw new Error('Vault is locked. Run UNLOCK first.');
}

async function api(path, options = {}) {
  requireToken();
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${apiToken}`);
  headers.set('X-Blackpine-Client-Version', String(FORMAT_VERSION));
  const response = await fetch(new URL(path, self.location.origin), {
    ...options,
    headers,
    cache: 'no-store',
    credentials: 'same-origin',
    redirect: 'error'
  });
  if (!response.ok) {
    let message = `Server rejected the request (${response.status}).`;
    try {
      const body = await response.json();
      if (body?.error) message = body.error;
    } catch {
      // Keep generic error.
    }
    throw new Error(message);
  }
  return response;
}

async function apiJson(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && typeof options.body !== 'string') {
    headers.set('Content-Type', 'application/json');
    options = { ...options, body: JSON.stringify(options.body) };
  }
  const response = await api(path, { ...options, headers });
  if (response.status === 204) return null;
  return response.json();
}

function passphraseBytesFrom(payload) {
  if (!(payload instanceof ArrayBuffer)) throw new Error('Passphrase buffer is missing.');
  return new Uint8Array(payload);
}

function verifyFile(file) {
  if (!(file instanceof File)) throw new Error('No file was selected.');
  if (file.size > MAX_FILE_SIZE) throw new Error('File exceeds the configured 5 GB limit.');
  return file;
}

function objectVersionRecord(base) {
  const record = {
    objectId: base.objectId,
    version: base.version,
    chunkCount: base.chunkCount,
    ciphertextSize: base.ciphertextSize,
    streamHeaderB64: base.streamHeaderB64,
    wrappedDekB64: base.wrappedDekB64,
    wrappedDekNonceB64: base.wrappedDekNonceB64,
    encryptedManifestB64: base.encryptedManifestB64,
    manifestNonceB64: base.manifestNonceB64,
    previousVersionHashB64: base.previousVersionHashB64 || null
  };
  record.versionHashB64 = b64(computeVersionHash(record));
  return record;
}

function verifyVersionRecord(record) {
  const expected = computeVersionHash(record);
  const supplied = unb64(record.versionHashB64);
  const valid = expected.length === supplied.length && sodium.memcmp(expected, supplied);
  wipe(expected, supplied);
  if (!valid) throw new Error('Stored object record integrity check failed.');
}

async function setupVault(passphraseBuffer) {
  const passphrase = passphraseBytesFrom(passphraseBuffer);
  let unlockKey;
  let root;
  let recoveryKey;
  try {
    const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
    unlockKey = deriveUnlockKey(passphrase, salt, KDF_DEFAULTS);
    root = randomBytes(sodium.crypto_kdf_KEYBYTES);
    recoveryKey = randomBytes(32);
    const rootWrap = wrapRootKey(root, unlockKey);
    const recoveryWrap = aeadEncrypt(root, recoveryKey, recoveryRootAad());
    const payload = {
      cryptoVersion: FORMAT_VERSION,
      kdf: KDF_DEFAULTS,
      saltB64: b64(salt),
      wrappedRootB64: b64(rootWrap.ciphertext),
      rootNonceB64: b64(rootWrap.nonce),
      recoveryWrappedRootB64: b64(recoveryWrap.ciphertext),
      recoveryNonceB64: b64(recoveryWrap.nonce)
    };
    await apiJson('/api/v1/vault', { method: 'POST', body: payload });
    setVaultRoot(root);
    root = null;
    return { recoveryCode: createRecoveryCode(recoveryKey) };
  } finally {
    wipe(passphrase, unlockKey, root, recoveryKey);
  }
}

async function unlockVault(passphraseBuffer) {
  const passphrase = passphraseBytesFrom(passphraseBuffer);
  let unlockKey;
  let root;
  try {
    const record = await apiJson('/api/v1/vault');
    unlockKey = deriveUnlockKey(passphrase, unb64(record.saltB64), record.kdf);
    root = unwrapRootKey(
      unb64(record.wrappedRootB64),
      unb64(record.rootNonceB64),
      unlockKey
    );
    setVaultRoot(root);
    root = null;
    return { unlocked: true };
  } catch (error) {
    clearVaultKeys();
    if (/cipher|decrypt|verification|invalid/i.test(error?.message || '')) {
      throw new Error('Vault passphrase is incorrect or the vault record is damaged.');
    }
    throw error;
  } finally {
    wipe(passphrase, unlockKey, root);
  }
}

async function recoverVault(recoveryCode, newPassphraseBuffer) {
  const passphrase = passphraseBytesFrom(newPassphraseBuffer);
  let recoveryKey;
  let root;
  let unlockKey;
  try {
    const record = await apiJson('/api/v1/vault');
    recoveryKey = parseRecoveryCode(recoveryCode);
    root = aeadDecrypt(
      unb64(record.recoveryWrappedRootB64),
      unb64(record.recoveryNonceB64),
      recoveryKey,
      recoveryRootAad()
    );
    const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
    unlockKey = deriveUnlockKey(passphrase, salt, KDF_DEFAULTS);
    const wrapped = wrapRootKey(root, unlockKey);
    await apiJson('/api/v1/vault/rewrap', {
      method: 'PUT',
      body: {
        cryptoVersion: FORMAT_VERSION,
        kdf: KDF_DEFAULTS,
        saltB64: b64(salt),
        wrappedRootB64: b64(wrapped.ciphertext),
        rootNonceB64: b64(wrapped.nonce)
      }
    });
    setVaultRoot(root);
    root = null;
    return { recovered: true };
  } catch (error) {
    clearVaultKeys();
    if (/cipher|decrypt|verification|checksum|recovery/i.test(error?.message || '')) {
      throw new Error('Recovery code is incorrect or the recovery record is damaged.');
    }
    throw error;
  } finally {
    wipe(passphrase, recoveryKey, root, unlockKey);
  }
}

function createManifest(file, objectId, version, chunkHashes, contentHashB64) {
  return {
    formatVersion: FORMAT_VERSION,
    objectId,
    version,
    filename: file.name,
    mimeType: file.type || 'application/octet-stream',
    plaintextSize: file.size,
    lastModified: Number.isFinite(file.lastModified) ? file.lastModified : 0,
    createdAt: new Date().toISOString(),
    chunkSize: CHUNK_SIZE,
    chunkCount: chunkHashes.length,
    chunkSha256B64: chunkHashes,
    contentSha256B64: contentHashB64
  };
}

async function uploadFile(id, fileValue) {
  requireUnlocked();
  const file = verifyFile(fileValue);
  const objectId = crypto.randomUUID();
  const version = 1;
  const chunkCount = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  const fileKey = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(fileKey);
  const wrapped = wrapFileKey(fileKey, wrappingKey, objectId, version);
  const chunkHashes = [];
  let ciphertextSize = 0;
  const contentState = sodium.crypto_hash_sha256_init();
  let init = null;
  let completed = false;
  try {
    init = await apiJson('/api/v1/uploads', {
      method: 'POST',
      body: { objectId, version, expectedChunks: chunkCount }
    });
    for (let index = 0; index < chunkCount; index += 1) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(file.size, start + CHUNK_SIZE);
      const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
      sodium.crypto_hash_sha256_update(contentState, plaintext);
      const tag = index === chunkCount - 1
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      const aad = chunkAad(objectId, version, index, chunkCount, file.size);
      const ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(
        stream.state,
        plaintext,
        aad,
        tag
      );
      wipe(plaintext, aad);
      const hash = sha256(ciphertext);
      const hashB64 = b64(hash);
      wipe(hash);
      const response = await api(`/api/v1/uploads/${encodeURIComponent(init.sessionId)}/chunks/${index}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Chunk-SHA256': hashB64
        },
        body: ciphertext
      });
      await response.arrayBuffer();
      chunkHashes.push(hashB64);
      ciphertextSize += ciphertext.byteLength;
      emit(id, 'progress', {
        phase: 'upload',
        completed: index + 1,
        total: chunkCount,
        bytesProcessed: end,
        totalBytes: file.size
      });
      wipe(ciphertext);
    }
    const contentHash = sodium.crypto_hash_sha256_final(contentState);
    const manifest = createManifest(file, objectId, version, chunkHashes, b64(contentHash));
    wipe(contentHash);
    const encryptedManifest = encryptManifest(manifest, metadataKey, objectId, version);
    const record = objectVersionRecord({
      objectId,
      version,
      chunkCount,
      ciphertextSize,
      streamHeaderB64: b64(stream.header),
      wrappedDekB64: b64(wrapped.ciphertext),
      wrappedDekNonceB64: b64(wrapped.nonce),
      encryptedManifestB64: b64(encryptedManifest.ciphertext),
      manifestNonceB64: b64(encryptedManifest.nonce),
      previousVersionHashB64: null
    });
    await apiJson(`/api/v1/uploads/${encodeURIComponent(init.sessionId)}/complete`, {
      method: 'POST',
      body: record
    });
    completed = true;
    return {
      objectId,
      filename: safeFilename(file.name),
      size: file.size,
      versionHashB64: record.versionHashB64
    };
  } finally {
    wipe(fileKey, wrapped.ciphertext, wrapped.nonce, stream.header);
    if (!completed && init?.sessionId) {
      try {
        await api(`/api/v1/uploads/${encodeURIComponent(init.sessionId)}`, { method: 'DELETE' });
      } catch {
        // Server expiry cleanup is the fallback.
      }
    }
  }
}

function validateManifest(manifest, record) {
  if (!manifest || typeof manifest !== 'object') throw new Error('Manifest structure is invalid.');
  if (!Number.isSafeInteger(manifest.plaintextSize) || manifest.plaintextSize < 0 || manifest.plaintextSize > MAX_FILE_SIZE) {
    throw new Error('Manifest plaintext size is invalid.');
  }
  if (manifest.chunkSize !== CHUNK_SIZE || manifest.chunkCount !== record.chunkCount) {
    throw new Error('Manifest chunk framing is invalid.');
  }
  const expectedCount = Math.max(1, Math.ceil(manifest.plaintextSize / CHUNK_SIZE));
  if (manifest.chunkCount !== expectedCount || manifest.chunkCount > MAX_CHUNKS) {
    throw new Error('Manifest chunk count is inconsistent with file size.');
  }
  if (!Array.isArray(manifest.chunkSha256B64) || manifest.chunkSha256B64.length !== manifest.chunkCount) {
    throw new Error('Manifest chunk hash list is invalid.');
  }
  for (const hash of manifest.chunkSha256B64) {
    const bytes = unb64(hash);
    const valid = bytes.byteLength === 32;
    wipe(bytes);
    if (!valid) throw new Error('Manifest contains an invalid chunk hash.');
  }
  const contentHash = unb64(manifest.contentSha256B64);
  const contentHashValid = contentHash.byteLength === 32;
  wipe(contentHash);
  if (!contentHashValid) throw new Error('Manifest content hash is invalid.');
  if (typeof manifest.filename !== 'string' || manifest.filename.length > 1024) throw new Error('Manifest filename is invalid.');
  if (typeof manifest.mimeType !== 'string' || manifest.mimeType.length > 255) throw new Error('Manifest MIME type is invalid.');
  return manifest;
}

async function decryptObjectRecord(record) {
  verifyVersionRecord(record);
  const manifest = decryptManifest(
    unb64(record.encryptedManifestB64),
    unb64(record.manifestNonceB64),
    metadataKey,
    record.objectId,
    record.version
  );
  return validateManifest(manifest, record);
}

async function listFiles() {
  requireUnlocked();
  const response = await apiJson('/api/v1/objects');
  const output = [];
  for (const record of response.objects) {
    try {
      const manifest = await decryptObjectRecord(record);
      output.push({
        objectId: record.objectId,
        version: record.version,
        filename: safeFilename(manifest.filename),
        size: manifest.plaintextSize,
        mimeType: manifest.mimeType,
        createdAt: manifest.createdAt,
        versionHashB64: record.versionHashB64,
        corrupt: false
      });
    } catch {
      output.push({
        objectId: record.objectId,
        version: record.version,
        filename: '[UNREADABLE OR TAMPERED RECORD]',
        size: 0,
        mimeType: 'application/octet-stream',
        createdAt: record.createdAt,
        versionHashB64: record.versionHashB64,
        corrupt: true
      });
    }
  }
  return output;
}

async function downloadFile(id, objectId) {
  requireUnlocked();
  const record = await apiJson(`/api/v1/objects/${encodeURIComponent(objectId)}`);
  const manifest = await decryptObjectRecord(record);
  const fileKey = unwrapFileKey(
    unb64(record.wrappedDekB64),
    unb64(record.wrappedDekNonceB64),
    wrappingKey,
    objectId,
    record.version
  );
  const pullState = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    unb64(record.streamHeaderB64),
    fileKey
  );
  const contentState = sodium.crypto_hash_sha256_init();
  emit(id, 'output-start', {
    filename: safeFilename(manifest.filename),
    mimeType: manifest.mimeType || 'application/octet-stream',
    size: manifest.plaintextSize
  });
  let emitted = 0;
  try {
    for (let index = 0; index < record.chunkCount; index += 1) {
      const response = await api(`/api/v1/objects/${encodeURIComponent(objectId)}/chunks/${index}`);
      const ciphertext = new Uint8Array(await response.arrayBuffer());
      if (ciphertext.byteLength < sodium.crypto_secretstream_xchacha20poly1305_ABYTES || ciphertext.byteLength > MAX_CIPHER_CHUNK) {
        throw new Error('Ciphertext chunk length is invalid.');
      }
      const actualHash = sha256(ciphertext);
      const expectedHash = unb64(manifest.chunkSha256B64[index]);
      const hashValid = actualHash.length === expectedHash.length && sodium.memcmp(actualHash, expectedHash);
      wipe(actualHash, expectedHash);
      if (!hashValid) throw new Error(`Ciphertext integrity check failed at chunk ${index}.`);
      const aad = chunkAad(objectId, record.version, index, record.chunkCount, manifest.plaintextSize);
      const pulled = sodium.crypto_secretstream_xchacha20poly1305_pull(pullState, ciphertext, aad);
      wipe(ciphertext, aad);
      if (!pulled) throw new Error(`Authenticated decryption failed at chunk ${index}.`);
      const shouldBeFinal = index === record.chunkCount - 1;
      if (shouldBeFinal && pulled.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        wipe(pulled.message);
        throw new Error('Final authentication tag is missing.');
      }
      if (!shouldBeFinal && pulled.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        wipe(pulled.message);
        throw new Error('File stream ended before the declared final chunk.');
      }
      sodium.crypto_hash_sha256_update(contentState, pulled.message);
      emitted += pulled.message.byteLength;
      const buffer = pulled.message.buffer.slice(
        pulled.message.byteOffset,
        pulled.message.byteOffset + pulled.message.byteLength
      );
      wipe(pulled.message);
      await emitOutputChunk(id, buffer);
      emit(id, 'progress', {
        phase: 'download',
        completed: index + 1,
        total: record.chunkCount,
        bytesProcessed: emitted,
        totalBytes: manifest.plaintextSize
      });
    }
    const actualContentHash = sodium.crypto_hash_sha256_final(contentState);
    const expectedContentHash = unb64(manifest.contentSha256B64);
    const contentValid = actualContentHash.length === expectedContentHash.length
      && sodium.memcmp(actualContentHash, expectedContentHash);
    wipe(actualContentHash, expectedContentHash);
    if (!contentValid || emitted !== manifest.plaintextSize) throw new Error('Plaintext content verification failed.');
    emit(id, 'output-complete', {});
    return { filename: safeFilename(manifest.filename), size: emitted };
  } catch (error) {
    emit(id, 'output-abort', { reason: error.message });
    throw error;
  } finally {
    wipe(fileKey);
  }
}

async function deleteFile(objectId) {
  requireUnlocked();
  await api(`/api/v1/objects/${encodeURIComponent(objectId)}`, { method: 'DELETE' });
  return { deleted: true };
}

function packageHeaderBytes(header) {
  const json = encodeJson(header);
  if (json.byteLength > MAX_HEADER_BYTES) throw new Error('Package header exceeds safe limit.');
  return concatBytes(utf8(PACKAGE_MAGIC), uint32be(json.byteLength), json);
}

function packageFooterBytes(footer) {
  const json = encodeJson(footer);
  if (json.byteLength > MAX_FOOTER_BYTES) throw new Error('Package footer exceeds safe limit.');
  return concatBytes(uint32be(json.byteLength), json, utf8(PACKAGE_END_MAGIC));
}

async function localEncrypt(id, fileValue, passphraseBuffer) {
  const file = verifyFile(fileValue);
  const passphrase = passphraseBytesFrom(passphraseBuffer);
  let unlockKey;
  let root;
  let fileKey;
  let localWrappingKey;
  let localMetadataKey;
  try {
    const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
    unlockKey = deriveUnlockKey(passphrase, salt, KDF_DEFAULTS);
    root = randomBytes(sodium.crypto_kdf_KEYBYTES);
    const keys = deriveVaultKeys(root);
    localWrappingKey = keys.wrappingKey;
    localMetadataKey = keys.metadataKey;
    const rootWrap = wrapRootKey(root, unlockKey, 'local');
    const objectId = crypto.randomUUID();
    const version = 1;
    const chunkCount = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    fileKey = sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(fileKey);
    const wrapped = wrapFileKey(fileKey, localWrappingKey, objectId, version);
    const header = {
      format: PACKAGE_MAGIC,
      formatVersion: FORMAT_VERSION,
      kdf: KDF_DEFAULTS,
      saltB64: b64(salt),
      wrappedRootB64: b64(rootWrap.ciphertext),
      rootNonceB64: b64(rootWrap.nonce),
      objectId,
      version,
      plaintextSize: file.size,
      chunkSize: CHUNK_SIZE,
      chunkCount,
      streamHeaderB64: b64(stream.header),
      wrappedDekB64: b64(wrapped.ciphertext),
      wrappedDekNonceB64: b64(wrapped.nonce)
    };
    const headerBytes = packageHeaderBytes(header);
    emit(id, 'output-start', {
      filename: `${safeFilename(file.name)}.bpv`,
      mimeType: 'application/octet-stream',
      size: null
    });
    await emitOutputChunk(id, headerBytes.buffer);
    const chunkHashes = [];
    const contentState = sodium.crypto_hash_sha256_init();
    let ciphertextSize = 0;
    for (let index = 0; index < chunkCount; index += 1) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(file.size, start + CHUNK_SIZE);
      const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
      sodium.crypto_hash_sha256_update(contentState, plaintext);
      const tag = index === chunkCount - 1
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      const aad = chunkAad(objectId, version, index, chunkCount, file.size);
      const ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(stream.state, plaintext, aad, tag);
      wipe(plaintext, aad);
      const hash = sha256(ciphertext);
      chunkHashes.push(b64(hash));
      wipe(hash);
      const framed = concatBytes(uint32be(ciphertext.byteLength), ciphertext);
      ciphertextSize += ciphertext.byteLength;
      await emitOutputChunk(id, framed.buffer);
      wipe(ciphertext);
      emit(id, 'progress', {
        phase: 'encrypt',
        completed: index + 1,
        total: chunkCount,
        bytesProcessed: end,
        totalBytes: file.size
      });
    }
    const contentHash = sodium.crypto_hash_sha256_final(contentState);
    const manifest = createManifest(file, objectId, version, chunkHashes, b64(contentHash));
    wipe(contentHash);
    const encryptedManifest = encryptManifest(manifest, localMetadataKey, objectId, version);
    const record = objectVersionRecord({
      objectId,
      version,
      chunkCount,
      ciphertextSize,
      streamHeaderB64: header.streamHeaderB64,
      wrappedDekB64: header.wrappedDekB64,
      wrappedDekNonceB64: header.wrappedDekNonceB64,
      encryptedManifestB64: b64(encryptedManifest.ciphertext),
      manifestNonceB64: b64(encryptedManifest.nonce),
      previousVersionHashB64: null
    });
    const footer = {
      encryptedManifestB64: record.encryptedManifestB64,
      manifestNonceB64: record.manifestNonceB64,
      versionHashB64: record.versionHashB64,
      ciphertextSize
    };
    const footerBytes = packageFooterBytes(footer);
    await emitOutputChunk(id, footerBytes.buffer);
    emit(id, 'output-complete', {});
    return { filename: `${safeFilename(file.name)}.bpv`, plaintextSize: file.size };
  } catch (error) {
    emit(id, 'output-abort', { reason: error.message });
    throw error;
  } finally {
    wipe(passphrase, unlockKey, root, fileKey, localWrappingKey, localMetadataKey);
  }
}

async function readRange(file, start, length) {
  if (start < 0 || length < 0 || start + length > file.size) throw new Error('Encrypted package is truncated.');
  return new Uint8Array(await file.slice(start, start + length).arrayBuffer());
}

async function parsePackage(file) {
  if (!(file instanceof File)) throw new Error('No encrypted package was selected.');
  if (file.size < 8 + 4 + 8) throw new Error('Encrypted package is too small.');
  const prefix = await readRange(file, 0, 12);
  const magic = fromUtf8(prefix.slice(0, 8));
  if (magic !== PACKAGE_MAGIC) throw new Error('Unsupported encrypted package format.');
  const headerLength = readUint32be(prefix.slice(8, 12));
  if (headerLength <= 0 || headerLength > MAX_HEADER_BYTES) throw new Error('Package header length is invalid.');
  const header = decodeJson(await readRange(file, 12, headerLength));
  if (header.format !== PACKAGE_MAGIC || header.formatVersion !== FORMAT_VERSION) {
    throw new Error('Package version is unsupported.');
  }
  if (!UUID_RE.test(header.objectId) || header.version !== 1) throw new Error('Package object identity is invalid.');
  if (!Number.isInteger(header.chunkCount) || header.chunkCount < 1 || header.chunkCount > MAX_CHUNKS) {
    throw new Error('Package chunk count is invalid.');
  }
  if (!Number.isSafeInteger(header.plaintextSize) || header.plaintextSize < 0 || header.plaintextSize > MAX_FILE_SIZE) {
    throw new Error('Package plaintext size is invalid.');
  }
  if (header.chunkSize !== CHUNK_SIZE || header.chunkCount !== Math.max(1, Math.ceil(header.plaintextSize / CHUNK_SIZE))) {
    throw new Error('Package chunk framing is inconsistent.');
  }
  let offset = 12 + headerLength;
  let totalCiphertextSize = 0;
  const chunks = [];
  for (let index = 0; index < header.chunkCount; index += 1) {
    const lengthBytes = await readRange(file, offset, 4);
    const cipherLength = readUint32be(lengthBytes);
    offset += 4;
    if (cipherLength < sodium.crypto_secretstream_xchacha20poly1305_ABYTES || cipherLength > MAX_CIPHER_CHUNK) {
      throw new Error(`Package chunk ${index} has an invalid length.`);
    }
    chunks.push({ offset, length: cipherLength });
    totalCiphertextSize += cipherLength;
    offset += cipherLength;
    if (offset > file.size) throw new Error('Encrypted package is truncated.');
  }
  const footerLength = readUint32be(await readRange(file, offset, 4));
  offset += 4;
  if (footerLength <= 0 || footerLength > MAX_FOOTER_BYTES) throw new Error('Package footer length is invalid.');
  const footer = decodeJson(await readRange(file, offset, footerLength));
  if (!Number.isSafeInteger(footer.ciphertextSize) || footer.ciphertextSize !== totalCiphertextSize) {
    throw new Error('Package ciphertext size is inconsistent.');
  }
  offset += footerLength;
  const endMagic = fromUtf8(await readRange(file, offset, 8));
  offset += 8;
  if (endMagic !== PACKAGE_END_MAGIC || offset !== file.size) throw new Error('Package ending is invalid or extra data is present.');
  return { header, footer, chunks };
}

function clearPendingLocalDecrypt() {
  if (!pendingLocalDecrypt) return;
  wipe(pendingLocalDecrypt.fileKey);
  pendingLocalDecrypt = null;
}

async function prepareLocalDecrypt(file, passphraseBuffer) {
  clearPendingLocalDecrypt();
  const passphrase = passphraseBytesFrom(passphraseBuffer);
  let unlockKey;
  let root;
  let localWrappingKey;
  let localMetadataKey;
  let fileKey;
  try {
    const parsed = await parsePackage(file);
    unlockKey = deriveUnlockKey(passphrase, unb64(parsed.header.saltB64), parsed.header.kdf);
    root = unwrapRootKey(
      unb64(parsed.header.wrappedRootB64),
      unb64(parsed.header.rootNonceB64),
      unlockKey,
      'local'
    );
    const keys = deriveVaultKeys(root);
    localWrappingKey = keys.wrappingKey;
    localMetadataKey = keys.metadataKey;
    fileKey = unwrapFileKey(
      unb64(parsed.header.wrappedDekB64),
      unb64(parsed.header.wrappedDekNonceB64),
      localWrappingKey,
      parsed.header.objectId,
      parsed.header.version
    );
    const record = {
      objectId: parsed.header.objectId,
      version: parsed.header.version,
      chunkCount: parsed.header.chunkCount,
      ciphertextSize: parsed.footer.ciphertextSize,
      streamHeaderB64: parsed.header.streamHeaderB64,
      wrappedDekB64: parsed.header.wrappedDekB64,
      wrappedDekNonceB64: parsed.header.wrappedDekNonceB64,
      encryptedManifestB64: parsed.footer.encryptedManifestB64,
      manifestNonceB64: parsed.footer.manifestNonceB64,
      previousVersionHashB64: null,
      versionHashB64: parsed.footer.versionHashB64
    };
    verifyVersionRecord(record);
    const manifest = decryptManifest(
      unb64(record.encryptedManifestB64),
      unb64(record.manifestNonceB64),
      localMetadataKey,
      record.objectId,
      record.version
    );
    validateManifest(manifest, record);
    if (manifest.chunkCount !== parsed.chunks.length || manifest.plaintextSize !== parsed.header.plaintextSize) {
      throw new Error('Package manifest does not match its framing.');
    }
    pendingLocalDecrypt = { file, parsed, manifest, fileKey };
    fileKey = null;
    return {
      filename: safeFilename(manifest.filename),
      mimeType: manifest.mimeType || 'application/octet-stream',
      size: manifest.plaintextSize
    };
  } catch (error) {
    clearPendingLocalDecrypt();
    if (/cipher|decrypt|verification|invalid root/i.test(error?.message || '')) {
      throw new Error('Passphrase is incorrect or the encrypted package is damaged.');
    }
    throw error;
  } finally {
    wipe(passphrase, unlockKey, root, localWrappingKey, localMetadataKey, fileKey);
  }
}

async function runLocalDecrypt(id) {
  if (!pendingLocalDecrypt) throw new Error('No prepared encrypted package. Run DECRYPT again.');
  const pending = pendingLocalDecrypt;
  const { file, parsed, manifest, fileKey } = pending;
  const pullState = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    unb64(parsed.header.streamHeaderB64),
    fileKey
  );
  const contentState = sodium.crypto_hash_sha256_init();
  emit(id, 'output-start', {
    filename: safeFilename(manifest.filename),
    mimeType: manifest.mimeType || 'application/octet-stream',
    size: manifest.plaintextSize
  });
  let emitted = 0;
  try {
    for (let index = 0; index < parsed.chunks.length; index += 1) {
      const chunkInfo = parsed.chunks[index];
      const ciphertext = await readRange(file, chunkInfo.offset, chunkInfo.length);
      const actualHash = sha256(ciphertext);
      const expectedHash = unb64(manifest.chunkSha256B64[index]);
      const hashValid = actualHash.length === expectedHash.length && sodium.memcmp(actualHash, expectedHash);
      wipe(actualHash, expectedHash);
      if (!hashValid) throw new Error(`Package integrity check failed at chunk ${index}.`);
      const aad = chunkAad(
        parsed.header.objectId,
        parsed.header.version,
        index,
        parsed.header.chunkCount,
        parsed.header.plaintextSize
      );
      const pulled = sodium.crypto_secretstream_xchacha20poly1305_pull(pullState, ciphertext, aad);
      wipe(ciphertext, aad);
      if (!pulled) throw new Error(`Package authentication failed at chunk ${index}.`);
      const shouldBeFinal = index === parsed.chunks.length - 1;
      if (shouldBeFinal && pulled.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        wipe(pulled.message);
        throw new Error('Package final authentication tag is missing.');
      }
      if (!shouldBeFinal && pulled.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        wipe(pulled.message);
        throw new Error('Package stream ended early.');
      }
      sodium.crypto_hash_sha256_update(contentState, pulled.message);
      emitted += pulled.message.byteLength;
      const buffer = pulled.message.buffer.slice(
        pulled.message.byteOffset,
        pulled.message.byteOffset + pulled.message.byteLength
      );
      wipe(pulled.message);
      await emitOutputChunk(id, buffer);
      emit(id, 'progress', {
        phase: 'decrypt',
        completed: index + 1,
        total: parsed.chunks.length,
        bytesProcessed: emitted,
        totalBytes: manifest.plaintextSize
      });
    }
    const actualContentHash = sodium.crypto_hash_sha256_final(contentState);
    const expectedContentHash = unb64(manifest.contentSha256B64);
    const valid = actualContentHash.length === expectedContentHash.length
      && sodium.memcmp(actualContentHash, expectedContentHash);
    wipe(actualContentHash, expectedContentHash);
    if (!valid || emitted !== manifest.plaintextSize) throw new Error('Decrypted package content verification failed.');
    emit(id, 'output-complete', {});
    return { filename: safeFilename(manifest.filename), size: emitted };
  } catch (error) {
    emit(id, 'output-abort', { reason: error.message });
    throw error;
  } finally {
    clearPendingLocalDecrypt();
  }
}

async function health() {
  const response = await fetch(new URL('/api/v1/health', self.location.origin), {
    cache: 'no-store',
    credentials: 'same-origin'
  });
  if (!response.ok) throw new Error(`Health endpoint returned ${response.status}.`);
  return response.json();
}

self.onmessage = async (messageEvent) => {
  const incoming = messageEvent.data || {};
  if (incoming.kind === 'stream-ack') {
    const key = `${incoming.id}:${incoming.sequence}`;
    const waiter = outputAcks.get(key);
    if (waiter) {
      clearTimeout(waiter.timeout);
      outputAcks.delete(key);
      if (incoming.ok === false) waiter.reject(new Error(incoming.error || 'Output write failed.'));
      else waiter.resolve();
    }
    return;
  }
  const { id, type, payload = {} } = incoming;
  if (!id || !type) return;
  try {
    let result;
    switch (type) {
      case 'set-token':
        apiToken = String(payload.token || '');
        result = { tokenSet: apiToken.length >= 48 };
        break;
      case 'clear-token':
        apiToken = '';
        clearVaultKeys();
        clearPendingLocalDecrypt();
        result = { tokenSet: false, locked: true };
        break;
      case 'health':
        result = await health();
        break;
      case 'setup':
        result = await setupVault(payload.passphrase);
        break;
      case 'unlock':
        result = await unlockVault(payload.passphrase);
        break;
      case 'recover':
        result = await recoverVault(payload.recoveryCode, payload.newPassphrase);
        break;
      case 'lock':
        clearVaultKeys();
        clearPendingLocalDecrypt();
        result = { locked: true };
        break;
      case 'is-unlocked':
        result = { unlocked: Boolean(vaultRootKey) };
        break;
      case 'upload':
        result = await uploadFile(id, payload.file);
        break;
      case 'list':
        result = { files: await listFiles() };
        break;
      case 'download':
        result = await downloadFile(id, payload.objectId);
        break;
      case 'delete':
        result = await deleteFile(payload.objectId);
        break;
      case 'local-encrypt':
        result = await localEncrypt(id, payload.file, payload.passphrase);
        break;
      case 'local-decrypt-prepare':
        result = await prepareLocalDecrypt(payload.file, payload.passphrase);
        break;
      case 'local-decrypt-run':
        result = await runLocalDecrypt(id);
        break;
      case 'local-decrypt-cancel':
        clearPendingLocalDecrypt();
        result = { cancelled: true };
        break;
      default:
        throw new Error('Unknown worker command.');
    }
    complete(id, result);
  } catch (error) {
    fail(id, error);
  }
};
