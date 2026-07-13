import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Worker } from 'node:worker_threads';

const root = fileURLToPath(new URL('../', import.meta.url));
const stateDir = await mkdtemp(join(tmpdir(), 'blackpine-vault-integration-'));
const port = 18787 + Math.floor(Math.random() * 1000);
const origin = `http://127.0.0.1:${port}`;
const token = randomBytes(48).toString('base64url');
let devProcess;

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    stdio: options.stdio || 'pipe',
    env: { ...process.env, NO_COLOR: '1' }
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed:\n${result.stdout || ''}\n${result.stderr || ''}`);
  }
  return result;
}

async function waitForServer() {
  let lastError;
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await fetch(`${origin}/api/v1/health`, { cache: 'no-store' });
      if (response.ok) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Local Wrangler server did not start: ${lastError?.message || 'unknown error'}`);
}

function authHeaders(extra = {}) {
  return {
    Authorization: `Bearer ${token}`,
    Origin: origin,
    'Sec-Fetch-Site': 'same-origin',
    ...extra
  };
}

async function expectStatus(url, options, expected) {
  const response = await fetch(url, options);
  assert.equal(response.status, expected, `${options?.method || 'GET'} ${url} returned ${response.status}`);
  return response;
}

function pass(value) {
  return new TextEncoder().encode(value).buffer;
}

function fileSpec(bytes, name, type = 'text/plain') {
  return {
    bytes: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    name,
    type,
    lastModified: Date.now()
  };
}

function combine(chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function runCryptoFlow() {
  const worker = new Worker(new URL('./worker-node-wrapper.mjs', import.meta.url), {
    type: 'module',
    workerData: {
      origin,
      moduleUrl: pathToFileURL(join(root, 'src/client/crypto-worker.js')).href
    }
  });

  let counter = 0;
  const pending = new Map();
  let readyResolve;
  let readyReject;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });

  worker.on('message', (message) => {
    if (message.kind === 'wrapper-ready') {
      readyResolve();
      return;
    }
    const job = pending.get(message.id);
    if (!job) return;
    if (message.kind === 'event') {
      if (message.event === 'output-chunk') {
        try {
          job.chunks.push(new Uint8Array(message.data.chunk));
          worker.postMessage({
            kind: 'stream-ack',
            id: message.id,
            sequence: message.data.sequence,
            ok: true
          });
        } catch (error) {
          worker.postMessage({
            kind: 'stream-ack',
            id: message.id,
            sequence: message.data.sequence,
            ok: false,
            error: error.message
          });
        }
      } else if (message.event === 'output-abort') {
        job.abort = message.data.reason;
      } else if (message.event === 'progress') {
        job.lastProgress = message.data;
      }
      return;
    }
    pending.delete(message.id);
    if (message.kind === 'result') {
      job.resolve({ result: message.result, chunks: job.chunks, abort: job.abort, lastProgress: job.lastProgress });
    } else {
      job.reject(new Error(message.error || 'Worker operation failed.'));
    }
  });

  worker.on('error', (error) => {
    readyReject(error);
    for (const [, job] of pending) job.reject(error);
    pending.clear();
  });

  function run(type, payload = {}, transfer = []) {
    const id = `integration-${++counter}`;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, chunks: [], abort: null, lastProgress: null });
      worker.postMessage({ id, type, payload }, transfer);
    });
  }

  const sample = new Uint8Array([
    ...new TextEncoder().encode('Blackpine end-to-end integration test\n'),
    0, 1, 2, 3, 255
  ]);
  const vaultPassphrase = 'Blackpine vault passphrase with six random words 2026';
  const replacementPassphrase = 'Blackpine replacement passphrase with six random words';
  const packagePassphrase = 'Blackpine package passphrase with six random words';

  try {
    await ready;
    const tokenResult = await run('set-token', { token });
    assert.equal(tokenResult.result.tokenSet, true);

    let buffer = pass(vaultPassphrase);
    const setup = await run('setup', { passphrase: buffer }, [buffer]);
    assert.match(setup.result.recoveryCode, /^[A-F0-9-]+$/);

    const upload = await run('upload', { fileSpec: fileSpec(sample, 'blackpine-integration.bin', 'application/octet-stream') });
    assert.match(upload.result.objectId, /^[0-9a-f-]{36}$/);
    assert.equal(upload.lastProgress.completed, 1);

    const listed = await run('list');
    assert.equal(listed.result.files.length, 1);
    assert.equal(listed.result.files[0].filename, 'blackpine-integration.bin');
    assert.equal(listed.result.files[0].corrupt, false);

    const downloaded = await run('download', { objectId: upload.result.objectId });
    assert.deepEqual(combine(downloaded.chunks), sample);
    assert.equal(downloaded.abort, null);

    await run('lock');
    buffer = pass('definitely the wrong vault passphrase');
    await assert.rejects(run('unlock', { passphrase: buffer }, [buffer]));

    buffer = pass(vaultPassphrase);
    await run('unlock', { passphrase: buffer }, [buffer]);

    buffer = pass(packagePassphrase);
    const encryptedPackage = await run('local-encrypt', {
      fileSpec: fileSpec(sample, 'blackpine-integration.bin', 'application/octet-stream'),
      passphrase: buffer
    }, [buffer]);
    const packageBytes = combine(encryptedPackage.chunks);
    assert.ok(packageBytes.byteLength > sample.byteLength);

    buffer = pass('wrong standalone package passphrase 2026');
    await assert.rejects(run('local-decrypt-prepare', {
      fileSpec: fileSpec(packageBytes, 'blackpine-integration.bpv', 'application/octet-stream'),
      passphrase: buffer
    }, [buffer]));

    const tampered = packageBytes.slice();
    tampered[Math.floor(tampered.byteLength / 2)] ^= 1;
    buffer = pass(packagePassphrase);
    let tamperRejected = false;
    try {
      await run('local-decrypt-prepare', {
        fileSpec: fileSpec(tampered, 'tampered.bpv', 'application/octet-stream'),
        passphrase: buffer
      }, [buffer]);
      await run('local-decrypt-run');
    } catch {
      tamperRejected = true;
    }
    assert.equal(tamperRejected, true, 'Tampered package must be rejected during preparation or authenticated streaming.');

    buffer = pass(packagePassphrase);
    const prepared = await run('local-decrypt-prepare', {
      fileSpec: fileSpec(packageBytes, 'blackpine-integration.bpv', 'application/octet-stream'),
      passphrase: buffer
    }, [buffer]);
    assert.equal(prepared.result.filename, 'blackpine-integration.bin');
    const localDecrypted = await run('local-decrypt-run');
    assert.deepEqual(combine(localDecrypted.chunks), sample);

    await run('lock');
    buffer = pass(replacementPassphrase);
    await run('recover', { recoveryCode: setup.result.recoveryCode, newPassphrase: buffer }, [buffer]);
    await run('lock');
    buffer = pass(replacementPassphrase);
    await run('unlock', { passphrase: buffer }, [buffer]);

    await run('delete', { objectId: upload.result.objectId });
    const empty = await run('list');
    assert.equal(empty.result.files.length, 0);

    await run('clear-token');
    await assert.rejects(run('list'));

    return {
      plaintextBytes: sample.byteLength,
      downloadedBytes: combine(downloaded.chunks).byteLength,
      packageBytes: packageBytes.byteLength,
      localDecryptedBytes: combine(localDecrypted.chunks).byteLength
    };
  } finally {
    await worker.terminate();
  }
}

async function runApiBoundaryTests() {
  await expectStatus(`${origin}/api/v1/vault`, {}, 401);
  await expectStatus(`${origin}/api/v1/uploads`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Origin: 'https://evil.example',
      'Content-Type': 'application/json'
    },
    body: '{}'
  }, 403);

  const objectId = crypto.randomUUID();
  const create = await fetch(`${origin}/api/v1/uploads`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ objectId, version: 1, expectedChunks: 1 })
  });
  assert.equal(create.status, 201);
  const { sessionId } = await create.json();

  await expectStatus(`${origin}/api/v1/uploads/${sessionId}/chunks/0`, {
    method: 'PUT',
    headers: authHeaders({
      'Content-Type': 'text/plain',
      'X-Chunk-SHA256': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    }),
    body: new Uint8Array(17)
  }, 415);

  await expectStatus(`${origin}/api/v1/uploads/${sessionId}`, {
    method: 'DELETE',
    headers: authHeaders()
  }, 204);

  const home = await fetch(`${origin}/`, { redirect: 'error' });
  assert.match(home.headers.get('content-security-policy') || '', /default-src 'none'/);
  assert.match(home.headers.get('strict-transport-security') || '', /max-age=63072000/);
}


try {
  runCommand('npx', [
    'wrangler', 'd1', 'execute', 'VAULT_DB', '--local', '--persist-to', stateDir, '--file=./schema.sql'
  ]);

  devProcess = spawn('npx', [
    'wrangler', 'dev', '--ip', '127.0.0.1', '--port', String(port), '--persist-to', stateDir,
    '--test-scheduled', '--log-level', 'error', '--var', `VAULT_API_TOKEN:${token}`
  ], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: { ...process.env, NO_COLOR: '1' }
  });

  let devErrors = '';
  devProcess.stderr.on('data', (chunk) => { devErrors += chunk.toString(); });
  devProcess.stdout.on('data', () => {});

  await waitForServer();
  const cryptoResult = await runCryptoFlow();
  await runApiBoundaryTests();
  console.log(JSON.stringify({
    integration: 'passed',
    ...cryptoResult,
    apiBoundaryTests: 'passed'
  }));

  if (devProcess.exitCode && devProcess.exitCode !== 0) {
    throw new Error(`Wrangler exited unexpectedly: ${devErrors}`);
  }
} finally {
  if (devProcess && devProcess.exitCode === null) {
    try {
      process.kill(-devProcess.pid, 'SIGTERM');
    } catch {
      devProcess.kill('SIGTERM');
    }
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 3000);
      devProcess.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
    if (devProcess.exitCode === null) {
      try {
        process.kill(-devProcess.pid, 'SIGKILL');
      } catch {
        devProcess.kill('SIGKILL');
      }
    }
  }
  await rm(stateDir, { recursive: true, force: true });
}
