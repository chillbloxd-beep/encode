import { formatBytes, safeFilename } from './crypto-core.js';

const terminal = document.querySelector('#terminal');
const form = document.querySelector('#command-form');
const input = document.querySelector('#command-input');
const promptLabel = document.querySelector('#prompt-label');
const filePicker = document.querySelector('#file-picker');
const encoder = new TextEncoder();
const cryptoWorker = new Worker(new URL('./crypto-worker.js', import.meta.url), { type: 'module', name: 'blackpine-crypto' });

const DEFAULT_PROMPT = 'C:\\BLACKPINE\\VAULT>';
const MAX_MEMORY_OUTPUT = 256 * 1024 * 1024;
const IDLE_LOCK_MS = 10 * 60 * 1000;

let jobCounter = 0;
let busy = false;
let answerRequest = null;
let tokenSet = false;
let unlocked = false;
let fileCache = [];
let pendingRecoveryCode = null;
let idleTimer = null;

const jobs = new Map();

function addLine(text = '', className = '') {
  const line = document.createElement('div');
  line.className = `line${className ? ` ${className}` : ''}`;
  line.textContent = String(text);
  terminal.append(line);
  terminal.scrollTop = terminal.scrollHeight;
  return line;
}

function setPrompt(text = DEFAULT_PROMPT, sensitive = false) {
  promptLabel.textContent = text;
  input.type = sensitive ? 'password' : 'text';
  input.autocomplete = sensitive ? 'new-password' : 'off';
  input.value = '';
  input.focus({ preventScroll: true });
}

function resetPrompt() {
  setPrompt(DEFAULT_PROMPT, false);
}

function resetIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    if (busy || !unlocked) return resetIdleTimer();
    try {
      await commandDeauth({ quiet: true });
    } catch {
      tokenSet = false;
      unlocked = false;
      fileCache = [];
      pendingRecoveryCode = null;
    }
    addLine('Vault auto-locked and API token cleared after 10 minutes of inactivity.', 'warning');
  }, IDLE_LOCK_MS);
}

function ask(prompt, { sensitive = false } = {}) {
  if (answerRequest) throw new Error('Another answer is already pending.');
  return new Promise((resolve) => {
    answerRequest = { resolve, prompt, sensitive };
    setPrompt(prompt, sensitive);
    input.disabled = false;
  });
}

function chooseFile(accept = '') {
  return new Promise((resolve, reject) => {
    filePicker.accept = accept;
    filePicker.value = '';
    const onChange = () => {
      filePicker.removeEventListener('change', onChange);
      const file = filePicker.files?.[0];
      file ? resolve(file) : reject(new Error('No file was selected.'));
    };
    filePicker.addEventListener('change', onChange, { once: true });
    filePicker.click();
  });
}

function runWorker(type, payload = {}, transfer = [], onEvent = null) {
  const id = `job-${Date.now()}-${++jobCounter}`;
  return new Promise((resolve, reject) => {
    jobs.set(id, { resolve, reject, onEvent, eventError: null });
    cryptoWorker.postMessage({ id, type, payload }, transfer);
  });
}

cryptoWorker.addEventListener('message', async (event) => {
  const message = event.data || {};
  const job = jobs.get(message.id);
  if (!job) return;
  if (message.kind === 'event') {
    try {
      if (job.onEvent) await job.onEvent(message.event, message.data || {});
      if (message.event === 'output-chunk') {
        cryptoWorker.postMessage({
          kind: 'stream-ack',
          id: message.id,
          sequence: message.data.sequence,
          ok: true
        });
      }
    } catch (error) {
      job.eventError = error instanceof Error ? error : new Error('Output event handling failed.');
      if (message.event === 'output-chunk') {
        cryptoWorker.postMessage({
          kind: 'stream-ack',
          id: message.id,
          sequence: message.data.sequence,
          ok: false,
          error: job.eventError.message
        });
      }
    }
    return;
  }
  jobs.delete(message.id);
  if (job.eventError) job.reject(job.eventError);
  else if (message.kind === 'result') job.resolve(message.result);
  else job.reject(new Error(message.error || 'Cryptographic worker failed.'));
});

cryptoWorker.addEventListener('error', () => {
  for (const [, job] of jobs) job.reject(new Error('Cryptographic worker crashed. Reload the page before continuing.'));
  jobs.clear();
  unlocked = false;
  addLine('FATAL: Cryptographic worker crashed. No further operation is trusted in this page session.', 'error');
});

function makeProgressLine(action) {
  const line = addLine(`${action}: starting...`, 'dim');
  return (progress) => {
    const percent = progress.totalBytes > 0
      ? Math.min(100, Math.floor((progress.bytesProcessed / progress.totalBytes) * 100))
      : Math.floor((progress.completed / progress.total) * 100);
    line.textContent = `${action}: ${percent}% (${formatBytes(progress.bytesProcessed)} / ${formatBytes(progress.totalBytes)})`;
    terminal.scrollTop = terminal.scrollHeight;
  };
}

async function createOutputSink(suggestedName, mimeType, expectedSize = null) {
  const cleanName = safeFilename(suggestedName, 'blackpine-output.bin');
  if ('showSaveFilePicker' in window && window.isSecureContext) {
    const handle = await window.showSaveFilePicker({
      suggestedName: cleanName,
      excludeAcceptAllOption: false
    });
    const writable = await handle.createWritable({ keepExistingData: false });
    let closed = false;
    return {
      async write(buffer) {
        if (closed) throw new Error('Output stream is already closed.');
        await writable.write(new Uint8Array(buffer));
      },
      async close() {
        if (!closed) {
          closed = true;
          await writable.close();
        }
      },
      async abort(reason) {
        if (!closed) {
          closed = true;
          await writable.abort(reason).catch(() => {});
        }
      }
    };
  }

  if (expectedSize !== null && expectedSize > MAX_MEMORY_OUTPUT) {
    throw new Error('This browser cannot stream directly to disk. Use current Chrome or Edge over HTTPS, or choose a file under 256 MB.');
  }
  const chunks = [];
  let total = 0;
  let closed = false;
  return {
    async write(buffer) {
      if (closed) throw new Error('Output stream is already closed.');
      total += buffer.byteLength;
      if (total > MAX_MEMORY_OUTPUT) throw new Error('Fallback browser download exceeded the 256 MB memory safety limit.');
      chunks.push(buffer);
    },
    async close() {
      if (closed) return;
      closed = true;
      const blob = new Blob(chunks, { type: mimeType || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = cleanName;
      anchor.rel = 'noopener';
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      chunks.length = 0;
    },
    async abort() {
      closed = true;
      chunks.length = 0;
    }
  };
}

async function runStreamJob(type, payload, sink, transfer, progressLabel) {
  const updateProgress = makeProgressLine(progressLabel);
  let started = false;
  let completed = false;
  try {
    const result = await runWorker(type, payload, transfer, async (event, data) => {
      if (event === 'output-start') started = true;
      else if (event === 'output-chunk') await sink.write(data.chunk);
      else if (event === 'output-complete') completed = true;
      else if (event === 'output-abort') await sink.abort(data.reason);
      else if (event === 'progress') updateProgress(data);
    });
    if (!started) throw new Error('Output did not start.');
    if (!completed) throw new Error('Output did not complete its authenticated stream.');
    await sink.close();
    return result;
  } catch (error) {
    await sink.abort(error.message);
    throw error;
  }
}

function bytesForSecret(secret) {
  const bytes = encoder.encode(secret);
  return bytes;
}

function requireAuth() {
  if (!tokenSet) throw new Error('Run AUTH first. The API token is separate from the vault passphrase.');
}

function requireUnlocked() {
  requireAuth();
  if (!unlocked) throw new Error('Vault is locked. Run UNLOCK first.');
}

function resolveObjectId(value) {
  const needle = String(value || '').trim().toLowerCase();
  if (!needle) throw new Error('Provide an object ID or unique ID prefix.');
  const exact = fileCache.find((item) => item.objectId.toLowerCase() === needle);
  if (exact) return exact;
  const matches = fileCache.filter((item) => item.objectId.toLowerCase().startsWith(needle));
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) throw new Error('ID prefix is ambiguous. Use more characters.');
  if (/^[0-9a-f-]{36}$/i.test(needle)) {
    return { objectId: needle, filename: `${needle}.bin`, size: null, mimeType: 'application/octet-stream' };
  }
  throw new Error('Object was not found in the current LIST cache. Run LIST first.');
}

function printHelp() {
  addLine('AVAILABLE COMMANDS');
  addLine('  AUTH                 Enter the server access token (hidden).');
  addLine('  SETUP                Create the one-time server vault and recovery code.');
  addLine('  UNLOCK               Unlock the server vault in this browser session.');
  addLine('  LOCK                 Erase in-memory vault keys and decrypted file index.');
  addLine('  DEAUTH               Erase the API token and lock the vault.');
  addLine('  STATUS               Check backend reachability and local lock state.');
  addLine('  UPLOAD               Encrypt a file locally, then upload ciphertext only.');
  addLine('  LIST                 Decrypt stored filenames locally and show object IDs.');
  addLine('  DOWNLOAD <id>        Fetch ciphertext, decrypt locally, and save the file.');
  addLine('  DELETE <id>          Delete the server object and its ciphertext chunks.');
  addLine('  ENCRYPT              Create a standalone .bpv encrypted package locally.');
  addLine('  DECRYPT              Decrypt a standalone .bpv package locally.');
  addLine('  RECOVERY             Save the recovery code created during SETUP.');
  addLine('  RECOVER              Reset the vault passphrase using the recovery code.');
  addLine('  CLEAR                 Clear terminal output.');
  addLine('  ABOUT                 Show security boundaries and limitations.');
  addLine('  HELP                  Show this command list.');
}

function printAbout() {
  addLine('BLACKPINE PERSONAL VAULT - SECURITY BOUNDARY');
  addLine('  File contents, filenames, root keys and file keys are encrypted/decrypted in a dedicated browser worker.');
  addLine('  The server is designed to receive only ciphertext, wrapped keys and opaque object identifiers.');
  addLine('  The API token authorizes storage access but cannot decrypt the vault by itself.');
  addLine('  A compromised browser, operating system, browser extension or malicious frontend deployment can steal plaintext.');
  addLine('  JavaScript cannot guarantee perfect memory erasure; LOCK overwrites reachable key buffers on a best-effort basis.');
  addLine('  This build has automated checks but has not received an independent professional cryptographic audit.');
}

async function commandAuth() {
  const token = await ask('API TOKEN>', { sensitive: true });
  if (token.length < 48) throw new Error('API token must be at least 48 characters. Generate a random token, not a normal password.');
  const result = await runWorker('set-token', { token });
  tokenSet = Boolean(result.tokenSet);
  addLine('Server access token loaded into worker memory for this page session.', 'success');
}

async function commandSetup() {
  requireAuth();
  const first = await ask('NEW VAULT PASSPHRASE>', { sensitive: true });
  if (encoder.encode(first).byteLength < 20) throw new Error('Use at least 20 UTF-8 bytes; five or more random words are strongly preferred.');
  const second = await ask('CONFIRM PASSPHRASE>', { sensitive: true });
  if (first !== second) throw new Error('Passphrases did not match.');
  const bytes = bytesForSecret(first);
  const result = await runWorker('setup', { passphrase: bytes.buffer }, [bytes.buffer]);
  unlocked = true;
  pendingRecoveryCode = result.recoveryCode;
  addLine('Vault created and unlocked. The server received only wrapped key material.', 'success');
  addLine('CRITICAL: Run RECOVERY now. The recovery code is shown only through that save operation.', 'warning');
}

async function commandUnlock() {
  requireAuth();
  const passphrase = await ask('VAULT PASSPHRASE>', { sensitive: true });
  const bytes = bytesForSecret(passphrase);
  await runWorker('unlock', { passphrase: bytes.buffer }, [bytes.buffer]);
  unlocked = true;
  fileCache = [];
  addLine('Vault unlocked in cryptographic worker memory.', 'success');
}

async function commandLock({ quiet = false } = {}) {
  await runWorker('lock');
  unlocked = false;
  fileCache = [];
  pendingRecoveryCode = null;
  if (!quiet) addLine('Vault locked. Reachable in-memory key buffers were overwritten on a best-effort basis.', 'success');
}


async function commandDeauth({ quiet = false } = {}) {
  await runWorker('clear-token');
  tokenSet = false;
  unlocked = false;
  fileCache = [];
  pendingRecoveryCode = null;
  if (!quiet) addLine('API token cleared and vault locked for this page session.', 'success');
}

async function commandStatus() {
  const [health, lockState] = await Promise.all([
    runWorker('health'),
    runWorker('is-unlocked')
  ]);
  unlocked = Boolean(lockState.unlocked);
  addLine(`Backend: ${health.ok ? 'reachable' : 'unhealthy'} | schema=${health.schemaVersion} | time=${health.time}`);
  addLine(`API token: ${tokenSet ? 'loaded in memory' : 'not set'} | vault: ${unlocked ? 'UNLOCKED' : 'LOCKED'}`);
}

async function commandUpload() {
  requireUnlocked();
  const file = await chooseFile();
  addLine(`Selected: ${safeFilename(file.name)} (${formatBytes(file.size)})`);
  const result = await runWorker('upload', { file }, [], (event, data) => {
    if (event === 'progress') uploadProgress(data);
  });
  fileCache = [];
  addLine(`Upload complete. Object ID: ${result.objectId}`, 'success');
  addLine('The server stored ciphertext and encrypted metadata only.');
}

let uploadProgress = () => {};

async function commandList() {
  requireUnlocked();
  const response = await runWorker('list');
  fileCache = response.files;
  if (!fileCache.length) {
    addLine('Vault contains no active objects.');
    return;
  }
  addLine('OBJECT ID     SIZE       CREATED                  NAME');
  for (const item of fileCache) {
    const id = item.objectId.slice(0, 12);
    const size = item.corrupt ? 'N/A' : formatBytes(item.size).padEnd(10);
    const date = String(item.createdAt || '').slice(0, 19).replace('T', ' ');
    addLine(`${id}  ${size} ${date.padEnd(20)} ${item.filename}`, item.corrupt ? 'error' : '');
  }
}

async function commandDownload(argument) {
  requireUnlocked();
  const record = resolveObjectId(argument);
  const sink = await createOutputSink(record.filename, record.mimeType, record.size);
  const result = await runStreamJob(
    'download',
    { objectId: record.objectId },
    sink,
    [],
    'DECRYPTING DOWNLOAD'
  );
  addLine(`Download verified and saved: ${result.filename} (${formatBytes(result.size)})`, 'success');
}

async function commandDelete(argument) {
  requireUnlocked();
  const record = resolveObjectId(argument);
  const confirmation = await ask(`TYPE DELETE FOR ${record.objectId.slice(0, 12)}>`);
  if (confirmation !== 'DELETE') throw new Error('Deletion cancelled. Confirmation must match exactly.');
  await runWorker('delete', { objectId: record.objectId });
  fileCache = fileCache.filter((item) => item.objectId !== record.objectId);
  addLine('Ciphertext object deleted. Existing external copies or provider backups cannot be proven erased.', 'warning');
}

async function commandEncrypt() {
  const file = await chooseFile();
  addLine(`Selected: ${safeFilename(file.name)} (${formatBytes(file.size)})`);
  const first = await ask('PACKAGE PASSPHRASE>', { sensitive: true });
  if (encoder.encode(first).byteLength < 20) throw new Error('Use at least 20 UTF-8 bytes; five or more random words are strongly preferred.');
  const second = await ask('CONFIRM PASSPHRASE>', { sensitive: true });
  if (first !== second) throw new Error('Passphrases did not match.');
  const confirmation = await ask('TYPE SAVE TO CHOOSE ENCRYPTED OUTPUT>');
  if (confirmation.toUpperCase() !== 'SAVE') throw new Error('Encryption cancelled.');
  const sink = await createOutputSink(`${safeFilename(file.name)}.bpv`, 'application/octet-stream', file.size + 2 * 1024 * 1024);
  const bytes = bytesForSecret(first);
  const result = await runStreamJob(
    'local-encrypt',
    { file, passphrase: bytes.buffer },
    sink,
    [bytes.buffer],
    'ENCRYPTING PACKAGE'
  );
  addLine(`Encrypted package saved: ${result.filename}`, 'success');
}

async function commandDecrypt() {
  const file = await chooseFile('.bpv,application/octet-stream');
  const passphrase = await ask('PACKAGE PASSPHRASE>', { sensitive: true });
  const bytes = bytesForSecret(passphrase);
  const metadata = await runWorker(
    'local-decrypt-prepare',
    { file, passphrase: bytes.buffer },
    [bytes.buffer]
  );
  addLine(`Authenticated package: ${metadata.filename} (${formatBytes(metadata.size)})`, 'success');
  const confirmation = await ask('TYPE SAVE TO CHOOSE DECRYPTED OUTPUT>');
  if (confirmation.toUpperCase() !== 'SAVE') {
    await runWorker('local-decrypt-cancel');
    throw new Error('Decryption cancelled.');
  }
  const sink = await createOutputSink(metadata.filename, metadata.mimeType, metadata.size);
  const result = await runStreamJob('local-decrypt-run', {}, sink, [], 'DECRYPTING PACKAGE');
  addLine(`Decrypted file verified and saved: ${result.filename}`, 'success');
}

async function commandRecovery() {
  if (!pendingRecoveryCode) throw new Error('No unsaved setup recovery code exists in this page session.');
  const confirmation = await ask('TYPE SAVE TO WRITE RECOVERY CODE>');
  if (confirmation.toUpperCase() !== 'SAVE') throw new Error('Recovery-code save cancelled.');
  const sink = await createOutputSink('blackpine-vault-recovery.txt', 'text/plain', 2048);
  const body = [
    'BLACKPINE PERSONAL VAULT RECOVERY CODE',
    '',
    pendingRecoveryCode,
    '',
    'Store this file offline in a secure location.',
    'Anyone with this code, the API token, and access to the service can reset the vault passphrase.',
    'Blackpine cannot recover the vault if both the passphrase and this code are lost.',
    ''
  ].join('\n');
  await sink.write(encoder.encode(body).buffer);
  await sink.close();
  pendingRecoveryCode = null;
  addLine('Recovery code saved. The in-page copy was cleared.', 'success');
}

async function commandRecover() {
  requireAuth();
  const code = await ask('RECOVERY CODE>', { sensitive: true });
  const first = await ask('NEW VAULT PASSPHRASE>', { sensitive: true });
  if (encoder.encode(first).byteLength < 20) throw new Error('Use at least 20 UTF-8 bytes; five or more random words are strongly preferred.');
  const second = await ask('CONFIRM PASSPHRASE>', { sensitive: true });
  if (first !== second) throw new Error('Passphrases did not match.');
  const bytes = bytesForSecret(first);
  await runWorker('recover', {
    recoveryCode: code,
    newPassphrase: bytes.buffer
  }, [bytes.buffer]);
  unlocked = true;
  fileCache = [];
  addLine('Vault passphrase replaced and vault unlocked. Recovery key was not changed.', 'success');
}

async function executeCommand(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return;
  const firstSpace = trimmed.indexOf(' ');
  const command = (firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace)).toUpperCase();
  const argument = firstSpace === -1 ? '' : trimmed.slice(firstSpace + 1).trim();
  switch (command) {
    case 'HELP': printHelp(); break;
    case 'ABOUT': printAbout(); break;
    case 'AUTH': await commandAuth(); break;
    case 'SETUP': await commandSetup(); break;
    case 'UNLOCK': await commandUnlock(); break;
    case 'LOCK': await commandLock(); break;
    case 'DEAUTH': await commandDeauth(); break;
    case 'STATUS': await commandStatus(); break;
    case 'UPLOAD': {
      uploadProgress = makeProgressLine('ENCRYPTING + UPLOADING');
      await commandUpload();
      break;
    }
    case 'LIST': await commandList(); break;
    case 'DOWNLOAD': await commandDownload(argument); break;
    case 'DELETE': await commandDelete(argument); break;
    case 'ENCRYPT': await commandEncrypt(); break;
    case 'DECRYPT': await commandDecrypt(); break;
    case 'RECOVERY': await commandRecovery(); break;
    case 'RECOVER': await commandRecover(); break;
    case 'CLEAR': terminal.replaceChildren(); break;
    default: throw new Error(`'${command}' is not recognized. Type HELP.`);
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resetIdleTimer();
  const value = input.value;
  input.value = '';

  if (answerRequest) {
    const request = answerRequest;
    answerRequest = null;
    addLine(`${request.prompt} ${request.sensitive ? '[hidden]' : value}`, 'command');
    resetPrompt();
    request.resolve(value);
    return;
  }

  if (busy) {
    addLine('Another operation is still running.', 'warning');
    return;
  }

  addLine(`${DEFAULT_PROMPT} ${value}`, 'command');
  busy = true;
  input.disabled = true;
  try {
    await executeCommand(value);
  } catch (error) {
    addLine(`ERROR: ${error instanceof Error ? error.message : 'Operation failed.'}`, 'error');
  } finally {
    busy = false;
    if (!answerRequest) {
      input.disabled = false;
      resetPrompt();
    }
  }
});

window.addEventListener('pointerdown', resetIdleTimer, { passive: true });
window.addEventListener('keydown', resetIdleTimer, { passive: true });
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState === 'hidden' && (unlocked || tokenSet) && !busy) {
    try {
      await commandDeauth({ quiet: true });
    } catch {
      tokenSet = false;
      unlocked = false;
    }
  }
});

addLine('Microsoft Windows [Version 10.0.19045.0000]');
addLine('(c) Blackpine Cybersecurity. Personal zero-knowledge vault prototype.');
addLine('');
addLine('Type HELP for commands. Start with STATUS, then AUTH.');
addLine('WARNING: This web build cannot protect plaintext from a compromised browser, device, extension, or malicious frontend deployment.', 'warning');
resetPrompt();
resetIdleTimer();
