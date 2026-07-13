const API_PREFIX = '/api/v1';
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_CHUNK_BYTES = 4 * 1024 * 1024 + 17;
const MAX_CHUNKS = 1280;
const MAX_FILE_CIPHERTEXT = 5 * 1024 * 1024 * 1024 + MAX_CHUNKS * 17;
const SESSION_TTL_MS = 30 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const encoder = new TextEncoder();

const SECURITY_HEADERS = Object.freeze({
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'self'; child-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; font-src 'none'; media-src 'none'; frame-src 'none'; manifest-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'; upgrade-insecure-requests",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), publickey-credentials-get=(self), screen-wake-lock=(), serial=(), usb=(), web-share=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Origin-Agent-Cluster': '?1',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'X-Robots-Tag': 'noindex, nofollow, noarchive'
});

function json(data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, max-age=0',
    ...extraHeaders
  });
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(status, message) {
  return json({ error: message }, status);
}

function withSecurityHeaders(response, pathname) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (pathname.startsWith(API_PREFIX)) {
    headers.set('Cache-Control', 'no-store, max-age=0');
  } else if (/\/assets\/.*-[A-Za-z0-9_-]+\.(?:js|css|wasm)$/.test(pathname)) {
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  } else {
    headers.set('Cache-Control', 'no-store, max-age=0, must-revalidate');
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function toB64Url(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromB64Url(value) {
  if (typeof value !== 'string' || !value || !B64URL_RE.test(value)) throw new Error('Invalid base64url value.');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function constantTimeTokenMatch(supplied, expected) {
  if (typeof supplied !== 'string' || typeof expected !== 'string' || expected.length < 48) return false;
  const [left, right] = await Promise.all([
    sha256(encoder.encode(supplied)),
    sha256(encoder.encode(expected))
  ]);
  let diff = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    diff |= (left[index] || 0) ^ (right[index] || 0);
  }
  left.fill(0);
  right.fill(0);
  return diff === 0;
}

async function requireAuthentication(request, env) {
  const header = request.headers.get('Authorization') || '';
  const match = /^Bearer ([\x21-\x7e]+)$/.exec(header);
  if (!match || !(await constantTimeTokenMatch(match[1], env.VAULT_API_TOKEN))) {
    throw Object.assign(new Error('Authentication failed.'), { status: 401 });
  }
}

function requireSameOrigin(request) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return;
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get('Origin');
  const fetchSite = request.headers.get('Sec-Fetch-Site');
  if (origin && origin !== requestOrigin) throw Object.assign(new Error('Cross-origin request rejected.'), { status: 403 });
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    throw Object.assign(new Error('Cross-site request rejected.'), { status: 403 });
  }
}

async function readJson(request) {
  const type = request.headers.get('Content-Type') || '';
  if (!type.toLowerCase().startsWith('application/json')) throw Object.assign(new Error('Content-Type must be application/json.'), { status: 415 });
  const declared = Number(request.headers.get('Content-Length') || 0);
  if (declared > MAX_JSON_BYTES) throw Object.assign(new Error('JSON request is too large.'), { status: 413 });
  const text = await request.text();
  if (encoder.encode(text).byteLength > MAX_JSON_BYTES) throw Object.assign(new Error('JSON request is too large.'), { status: 413 });
  try {
    return JSON.parse(text);
  } catch {
    throw Object.assign(new Error('Malformed JSON request.'), { status: 400 });
  }
}

async function readBodyWithLimit(request, maxBytes) {
  const declared = Number(request.headers.get('Content-Length') || 0);
  if (declared > maxBytes) throw Object.assign(new Error('Request body is too large.'), { status: 413 });
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += chunk.byteLength;
      if (total > maxBytes) {
        await reader.cancel('Body exceeded configured limit').catch(() => {});
        throw Object.assign(new Error('Request body is too large.'), { status: 413 });
      }
      chunks.push(chunk);
    }
    const output = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return output;
  } finally {
    reader.releaseLock();
  }
}

function requireUuid(value, label = 'identifier') {
  if (typeof value !== 'string' || !UUID_RE.test(value)) throw Object.assign(new Error(`Invalid ${label}.`), { status: 400 });
  return value.toLowerCase();
}

function requireInteger(value, min, max, label) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw Object.assign(new Error(`Invalid ${label}.`), { status: 400 });
  }
  return value;
}

function requireB64(value, minBytes, maxBytes, label) {
  let bytes;
  try {
    bytes = fromB64Url(value);
  } catch {
    throw Object.assign(new Error(`Invalid ${label}.`), { status: 400 });
  }
  if (bytes.byteLength < minBytes || bytes.byteLength > maxBytes) {
    throw Object.assign(new Error(`Invalid ${label} length.`), { status: 400 });
  }
  return bytes;
}

function validateKdf(kdf) {
  if (!kdf || kdf.algorithm !== 'argon2id13' || kdf.outputLength !== 32) {
    throw Object.assign(new Error('Unsupported password derivation settings.'), { status: 400 });
  }
  requireInteger(kdf.opsLimit, 3, 10, 'Argon2id operation limit');
  requireInteger(kdf.memLimit, 64 * 1024 * 1024, 256 * 1024 * 1024, 'Argon2id memory limit');
  return {
    algorithm: 'argon2id13',
    opsLimit: kdf.opsLimit,
    memLimit: kdf.memLimit,
    outputLength: 32
  };
}

function objectRowToClient(row) {
  return {
    objectId: row.id,
    version: row.version,
    encryptedManifestB64: row.encrypted_manifest_b64,
    manifestNonceB64: row.manifest_nonce_b64,
    wrappedDekB64: row.wrapped_dek_b64,
    wrappedDekNonceB64: row.wrapped_dek_nonce_b64,
    streamHeaderB64: row.stream_header_b64,
    chunkCount: row.chunk_count,
    ciphertextSize: row.ciphertext_size,
    previousVersionHashB64: row.previous_version_hash_b64,
    versionHashB64: row.version_hash_b64,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function calculateVersionHashB64(record) {
  const material = {
    formatVersion: 1,
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
  };
  return toB64Url(await sha256(encoder.encode(canonicalJson(material))));
}

async function appendAudit(env, eventType, objectId = null) {
  const createdAt = new Date().toISOString();
  const previous = await env.VAULT_DB.prepare('SELECT entry_hash_b64 FROM audit_entries ORDER BY id DESC LIMIT 1').first();
  const previousHashB64 = previous?.entry_hash_b64 || null;
  const entryHashB64 = toB64Url(await sha256(encoder.encode(canonicalJson({
    eventType,
    objectId,
    previousHashB64,
    createdAt
  }))));
  await env.VAULT_DB.prepare(
    'INSERT INTO audit_entries (event_type, object_id, previous_hash_b64, entry_hash_b64, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(eventType, objectId, previousHashB64, entryHashB64, createdAt).run();
}

async function getVault(env) {
  const row = await env.VAULT_DB.prepare('SELECT * FROM vaults WHERE id = ?').bind('primary').first();
  if (!row) throw Object.assign(new Error('Vault has not been set up.'), { status: 404 });
  return json({
    cryptoVersion: row.crypto_version,
    kdf: JSON.parse(row.kdf_json),
    saltB64: row.salt_b64,
    wrappedRootB64: row.wrapped_root_b64,
    rootNonceB64: row.root_nonce_b64,
    recoveryWrappedRootB64: row.recovery_wrapped_root_b64,
    recoveryNonceB64: row.recovery_nonce_b64,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  });
}

async function createVault(request, env) {
  const body = await readJson(request);
  if (body.cryptoVersion !== 1) throw Object.assign(new Error('Unsupported cryptographic schema.'), { status: 400 });
  const kdf = validateKdf(body.kdf);
  requireB64(body.saltB64, 16, 16, 'Argon2id salt');
  requireB64(body.wrappedRootB64, 48, 48, 'wrapped root key');
  requireB64(body.rootNonceB64, 24, 24, 'root nonce');
  requireB64(body.recoveryWrappedRootB64, 48, 48, 'recovery-wrapped root key');
  requireB64(body.recoveryNonceB64, 24, 24, 'recovery nonce');
  const now = new Date().toISOString();
  const result = await env.VAULT_DB.prepare(
    `INSERT OR IGNORE INTO vaults
      (id, crypto_version, kdf_json, salt_b64, wrapped_root_b64, root_nonce_b64,
       recovery_wrapped_root_b64, recovery_nonce_b64, created_at, updated_at)
     VALUES ('primary', 1, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    JSON.stringify(kdf), body.saltB64, body.wrappedRootB64, body.rootNonceB64,
    body.recoveryWrappedRootB64, body.recoveryNonceB64, now, now
  ).run();
  if (!result.meta.changes) throw Object.assign(new Error('Vault already exists. Use UNLOCK or RECOVER.'), { status: 409 });
  await appendAudit(env, 'vault-created');
  return json({ created: true }, 201);
}

async function rewrapVault(request, env) {
  const body = await readJson(request);
  if (body.cryptoVersion !== 1) throw Object.assign(new Error('Unsupported cryptographic schema.'), { status: 400 });
  const kdf = validateKdf(body.kdf);
  requireB64(body.saltB64, 16, 16, 'Argon2id salt');
  requireB64(body.wrappedRootB64, 48, 48, 'wrapped root key');
  requireB64(body.rootNonceB64, 24, 24, 'root nonce');
  const now = new Date().toISOString();
  const result = await env.VAULT_DB.prepare(
    `UPDATE vaults SET kdf_json = ?, salt_b64 = ?, wrapped_root_b64 = ?, root_nonce_b64 = ?, updated_at = ? WHERE id = 'primary'`
  ).bind(JSON.stringify(kdf), body.saltB64, body.wrappedRootB64, body.rootNonceB64, now).run();
  if (!result.meta.changes) throw Object.assign(new Error('Vault has not been set up.'), { status: 404 });
  await appendAudit(env, 'vault-rewrapped');
  return json({ updated: true });
}

async function createUpload(request, env) {
  const body = await readJson(request);
  const objectId = requireUuid(body.objectId, 'object ID');
  const version = requireInteger(body.version, 1, 1, 'object version');
  const expectedChunks = requireInteger(body.expectedChunks, 1, MAX_CHUNKS, 'chunk count');
  const existing = await env.VAULT_DB.prepare('SELECT id FROM objects WHERE id = ?').bind(objectId).first();
  if (existing) throw Object.assign(new Error('Object ID already exists.'), { status: 409 });
  const sessionId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  await env.VAULT_DB.prepare(
    `INSERT INTO upload_sessions
      (id, object_id, version, expected_chunks, received_chunks, total_ciphertext_size, status, expires_at, created_at)
     VALUES (?, ?, ?, ?, 0, 0, 'open', ?, ?)`
  ).bind(sessionId, objectId, version, expectedChunks, expiresAt, createdAt).run();
  return json({ sessionId, expiresAt }, 201);
}

async function getOpenSession(env, sessionId) {
  requireUuid(sessionId, 'upload session ID');
  const session = await env.VAULT_DB.prepare('SELECT * FROM upload_sessions WHERE id = ?').bind(sessionId).first();
  if (!session || session.status !== 'open') throw Object.assign(new Error('Upload session is not open.'), { status: 404 });
  if (Date.parse(session.expires_at) <= Date.now()) {
    await env.VAULT_DB.prepare("UPDATE upload_sessions SET status = 'cancelled' WHERE id = ?").bind(sessionId).run();
    throw Object.assign(new Error('Upload session expired.'), { status: 410 });
  }
  return session;
}

async function putChunk(request, env, sessionId, indexValue) {
  const session = await getOpenSession(env, sessionId);
  const index = requireInteger(Number(indexValue), 0, session.expected_chunks - 1, 'chunk index');
  const existing = await env.VAULT_DB.prepare(
    'SELECT 1 AS found FROM upload_chunks WHERE session_id = ? AND chunk_index = ?'
  ).bind(sessionId, index).first();
  if (existing) throw Object.assign(new Error('Chunk index was already uploaded.'), { status: 409 });
  const contentType = (request.headers.get('Content-Type') || '').toLowerCase();
  if (!contentType.startsWith('application/octet-stream')) {
    throw Object.assign(new Error('Ciphertext chunks must use application/octet-stream.'), { status: 415 });
  }
  const ciphertext = await readBodyWithLimit(request, MAX_CHUNK_BYTES);
  if (ciphertext.byteLength < 17 || ciphertext.byteLength > MAX_CHUNK_BYTES) {
    throw Object.assign(new Error('Ciphertext chunk length is invalid.'), { status: 400 });
  }
  const suppliedHash = request.headers.get('X-Chunk-SHA256') || '';
  requireB64(suppliedHash, 32, 32, 'chunk SHA-256');
  const actualHash = toB64Url(await sha256(ciphertext));
  if (actualHash !== suppliedHash) throw Object.assign(new Error('Chunk hash does not match its body.'), { status: 400 });
  if (session.total_ciphertext_size + ciphertext.byteLength > MAX_FILE_CIPHERTEXT) {
    throw Object.assign(new Error('Upload exceeds the configured file-size limit.'), { status: 413 });
  }
  const storageKey = `vault/${session.object_id}/v${session.version}/${String(index).padStart(6, '0')}.bin`;
  await env.VAULT_BUCKET.put(storageKey, ciphertext, {
    httpMetadata: { contentType: 'application/octet-stream', cacheControl: 'no-store' },
    customMetadata: { sha256: actualHash, session: sessionId }
  });
  try {
    await env.VAULT_DB.batch([
      env.VAULT_DB.prepare(
        'INSERT INTO upload_chunks (session_id, chunk_index, size_bytes, sha256_b64, storage_key) VALUES (?, ?, ?, ?, ?)'
      ).bind(sessionId, index, ciphertext.byteLength, actualHash, storageKey),
      env.VAULT_DB.prepare(
        'UPDATE upload_sessions SET received_chunks = received_chunks + 1, total_ciphertext_size = total_ciphertext_size + ? WHERE id = ? AND status = ?'
      ).bind(ciphertext.byteLength, sessionId, 'open')
    ]);
  } catch (error) {
    await env.VAULT_BUCKET.delete(storageKey);
    throw error;
  } finally {
    ciphertext.fill(0);
  }
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
}

function validateCompletionRecord(body, session, aggregate) {
  const objectId = requireUuid(body.objectId, 'object ID');
  if (objectId !== session.object_id) throw Object.assign(new Error('Upload object ID mismatch.'), { status: 400 });
  const version = requireInteger(body.version, 1, 1, 'object version');
  if (version !== session.version) throw Object.assign(new Error('Upload version mismatch.'), { status: 400 });
  const chunkCount = requireInteger(body.chunkCount, 1, MAX_CHUNKS, 'chunk count');
  if (chunkCount !== session.expected_chunks || chunkCount !== aggregate.chunk_count) {
    throw Object.assign(new Error('Upload chunk count is incomplete.'), { status: 400 });
  }
  const ciphertextSize = requireInteger(body.ciphertextSize, 17, MAX_FILE_CIPHERTEXT, 'ciphertext size');
  if (ciphertextSize !== aggregate.total_size || ciphertextSize !== session.total_ciphertext_size) {
    throw Object.assign(new Error('Upload ciphertext size mismatch.'), { status: 400 });
  }
  requireB64(body.streamHeaderB64, 24, 24, 'secretstream header');
  requireB64(body.wrappedDekB64, 48, 48, 'wrapped file key');
  requireB64(body.wrappedDekNonceB64, 24, 24, 'wrapped file key nonce');
  requireB64(body.encryptedManifestB64, 17, 1500 * 1024, 'encrypted manifest');
  requireB64(body.manifestNonceB64, 24, 24, 'manifest nonce');
  if (body.previousVersionHashB64 !== null) throw Object.assign(new Error('Version 1 cannot have a previous version hash.'), { status: 400 });
  requireB64(body.versionHashB64, 32, 32, 'version hash');
  return {
    objectId,
    version,
    chunkCount,
    ciphertextSize,
    streamHeaderB64: body.streamHeaderB64,
    wrappedDekB64: body.wrappedDekB64,
    wrappedDekNonceB64: body.wrappedDekNonceB64,
    encryptedManifestB64: body.encryptedManifestB64,
    manifestNonceB64: body.manifestNonceB64,
    previousVersionHashB64: null,
    versionHashB64: body.versionHashB64
  };
}

async function completeUpload(request, env, sessionId) {
  const session = await getOpenSession(env, sessionId);
  const body = await readJson(request);
  const aggregate = await env.VAULT_DB.prepare(
    'SELECT COUNT(*) AS chunk_count, COALESCE(SUM(size_bytes), 0) AS total_size FROM upload_chunks WHERE session_id = ?'
  ).bind(sessionId).first();
  const record = validateCompletionRecord(body, session, {
    chunk_count: Number(aggregate.chunk_count),
    total_size: Number(aggregate.total_size)
  });
  const expectedVersionHash = await calculateVersionHashB64(record);
  if (expectedVersionHash !== record.versionHashB64) {
    throw Object.assign(new Error('Version hash validation failed.'), { status: 400 });
  }
  const now = new Date().toISOString();
  try {
    await env.VAULT_DB.batch([
      env.VAULT_DB.prepare(
        `INSERT INTO objects
          (id, version, encrypted_manifest_b64, manifest_nonce_b64, wrapped_dek_b64, wrapped_dek_nonce_b64,
           stream_header_b64, chunk_count, ciphertext_size, previous_version_hash_b64, version_hash_b64,
           created_at, updated_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`
      ).bind(
        record.objectId, record.version, record.encryptedManifestB64, record.manifestNonceB64,
        record.wrappedDekB64, record.wrappedDekNonceB64, record.streamHeaderB64,
        record.chunkCount, record.ciphertextSize, null, record.versionHashB64, now, now
      ),
      env.VAULT_DB.prepare("UPDATE upload_sessions SET status = 'completed' WHERE id = ? AND status = 'open'").bind(sessionId)
    ]);
  } catch (error) {
    if (/UNIQUE|constraint/i.test(String(error))) throw Object.assign(new Error('Object ID already exists.'), { status: 409 });
    throw error;
  }
  await appendAudit(env, 'object-created', record.objectId);
  return json({ completed: true, objectId: record.objectId }, 201);
}

async function cancelUpload(env, sessionId) {
  const session = await env.VAULT_DB.prepare('SELECT * FROM upload_sessions WHERE id = ?').bind(requireUuid(sessionId, 'upload session ID')).first();
  if (!session) return new Response(null, { status: 204 });
  if (session.status === 'completed') throw Object.assign(new Error('Completed upload cannot be cancelled.'), { status: 409 });
  const chunks = await env.VAULT_DB.prepare('SELECT storage_key FROM upload_chunks WHERE session_id = ?').bind(sessionId).all();
  const keys = chunks.results.map((row) => row.storage_key);
  for (let index = 0; index < keys.length; index += 1000) {
    await env.VAULT_BUCKET.delete(keys.slice(index, index + 1000));
  }
  await env.VAULT_DB.batch([
    env.VAULT_DB.prepare("UPDATE upload_sessions SET status = 'cancelled' WHERE id = ?").bind(sessionId),
    env.VAULT_DB.prepare('DELETE FROM upload_chunks WHERE session_id = ?').bind(sessionId)
  ]);
  return new Response(null, { status: 204 });
}

async function listObjects(env) {
  const rows = await env.VAULT_DB.prepare(
    "SELECT * FROM objects WHERE status = 'active' ORDER BY updated_at DESC LIMIT 500"
  ).all();
  return json({ objects: rows.results.map(objectRowToClient) });
}

async function getObject(env, objectId) {
  const id = requireUuid(objectId, 'object ID');
  const row = await env.VAULT_DB.prepare("SELECT * FROM objects WHERE id = ? AND status = 'active'").bind(id).first();
  if (!row) throw Object.assign(new Error('Object was not found.'), { status: 404 });
  return json(objectRowToClient(row));
}

async function getObjectChunk(env, objectId, indexValue) {
  const id = requireUuid(objectId, 'object ID');
  const row = await env.VAULT_DB.prepare(
    "SELECT version, chunk_count FROM objects WHERE id = ? AND status = 'active'"
  ).bind(id).first();
  if (!row) throw Object.assign(new Error('Object was not found.'), { status: 404 });
  const index = requireInteger(Number(indexValue), 0, row.chunk_count - 1, 'chunk index');
  const storageKey = `vault/${id}/v${row.version}/${String(index).padStart(6, '0')}.bin`;
  const object = await env.VAULT_BUCKET.get(storageKey);
  if (!object) throw Object.assign(new Error('Ciphertext chunk was not found.'), { status: 404 });
  const headers = new Headers({
    'Content-Type': 'application/octet-stream',
    'Cache-Control': 'no-store, max-age=0',
    'Content-Length': String(object.size),
    'Content-Disposition': 'attachment',
    'X-Content-Type-Options': 'nosniff'
  });
  if (object.httpEtag) headers.set('ETag', object.httpEtag);
  return new Response(object.body, { headers });
}

async function deleteObject(env, objectId) {
  const id = requireUuid(objectId, 'object ID');
  const row = await env.VAULT_DB.prepare("SELECT version, chunk_count FROM objects WHERE id = ? AND status = 'active'").bind(id).first();
  if (!row) throw Object.assign(new Error('Object was not found.'), { status: 404 });
  const prefix = `vault/${id}/v${row.version}/`;
  let cursor;
  do {
    const listed = await env.VAULT_BUCKET.list({ prefix, cursor, limit: 1000 });
    if (listed.objects.length) await env.VAULT_BUCKET.delete(listed.objects.map((item) => item.key));
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  const now = new Date().toISOString();
  await env.VAULT_DB.prepare("UPDATE objects SET status = 'deleted', updated_at = ? WHERE id = ?").bind(now, id).run();
  await appendAudit(env, 'object-deleted', id);
  return new Response(null, { status: 204 });
}

async function cleanupExpiredUploads(env, limit = 5) {
  const now = new Date().toISOString();
  const sessions = await env.VAULT_DB.prepare(
    "SELECT id FROM upload_sessions WHERE (status = 'open' AND expires_at <= ?) OR status = 'cancelled' ORDER BY created_at ASC LIMIT ?"
  ).bind(now, limit).all();
  let removed = 0;
  for (const session of sessions.results) {
    const chunks = await env.VAULT_DB.prepare('SELECT storage_key FROM upload_chunks WHERE session_id = ?').bind(session.id).all();
    const keys = chunks.results.map((row) => row.storage_key);
    for (let index = 0; index < keys.length; index += 1000) {
      await env.VAULT_BUCKET.delete(keys.slice(index, index + 1000));
    }
    await env.VAULT_DB.batch([
      env.VAULT_DB.prepare('DELETE FROM upload_chunks WHERE session_id = ?').bind(session.id),
      env.VAULT_DB.prepare('DELETE FROM upload_sessions WHERE id = ?').bind(session.id)
    ]);
    removed += 1;
  }
  return removed;
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  if (url.pathname === `${API_PREFIX}/health` && request.method === 'GET') {
    return json({ ok: true, schemaVersion: 1, time: new Date().toISOString() });
  }

  requireSameOrigin(request);
  await requireAuthentication(request, env);

  if (url.pathname === `${API_PREFIX}/vault`) {
    if (request.method === 'GET') return getVault(env);
    if (request.method === 'POST') return createVault(request, env);
  }
  if (url.pathname === `${API_PREFIX}/vault/rewrap` && request.method === 'PUT') {
    return rewrapVault(request, env);
  }
  if (url.pathname === `${API_PREFIX}/uploads` && request.method === 'POST') {
    return createUpload(request, env);
  }

  let match = url.pathname.match(/^\/api\/v1\/uploads\/([^/]+)\/chunks\/(\d+)$/);
  if (match && request.method === 'PUT') return putChunk(request, env, match[1], match[2]);
  match = url.pathname.match(/^\/api\/v1\/uploads\/([^/]+)\/complete$/);
  if (match && request.method === 'POST') return completeUpload(request, env, match[1]);
  match = url.pathname.match(/^\/api\/v1\/uploads\/([^/]+)$/);
  if (match && request.method === 'DELETE') return cancelUpload(env, match[1]);

  if (url.pathname === `${API_PREFIX}/objects` && request.method === 'GET') return listObjects(env);
  match = url.pathname.match(/^\/api\/v1\/objects\/([^/]+)\/chunks\/(\d+)$/);
  if (match && request.method === 'GET') return getObjectChunk(env, match[1], match[2]);
  match = url.pathname.match(/^\/api\/v1\/objects\/([^/]+)$/);
  if (match && request.method === 'GET') return getObject(env, match[1]);
  if (match && request.method === 'DELETE') return deleteObject(env, match[1]);

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    return errorResponse(405, 'Method or API route is not allowed.');
  }
  return errorResponse(404, 'API route was not found.');
}

export default {
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(cleanupExpiredUploads(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    let response;
    try {
      if (url.pathname.startsWith(API_PREFIX)) {
        response = await handleApi(request, env);
      } else {
        if (!['GET', 'HEAD'].includes(request.method)) response = errorResponse(405, 'Method not allowed.');
        else response = await env.ASSETS.fetch(request);
      }
    } catch (error) {
      const status = Number.isInteger(error?.status) ? error.status : 500;
      const message = status >= 500 ? 'Internal service error.' : error.message;
      response = errorResponse(status, message);
    }
    return withSecurityHeaders(response, url.pathname);
  }
};
