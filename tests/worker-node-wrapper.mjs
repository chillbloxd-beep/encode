import { parentPort, workerData } from 'node:worker_threads';
import { File } from 'node:buffer';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.File = File;
globalThis.self = globalThis;
Object.defineProperty(globalThis, 'location', { value: { origin: workerData.origin }, configurable: true });
globalThis.postMessage = (message, transfer = []) => parentPort.postMessage(message, transfer);

const queued = [];
let loaded = false;

function materializeFile(data) {
  if (data?.payload?.fileSpec) {
    const spec = data.payload.fileSpec;
    data.payload.file = new File([new Uint8Array(spec.bytes)], spec.name, {
      type: spec.type || 'application/octet-stream',
      lastModified: spec.lastModified || Date.now()
    });
    delete data.payload.fileSpec;
  }
  return data;
}

parentPort.on('message', (incoming) => {
  const data = materializeFile(incoming);
  if (!loaded || typeof globalThis.onmessage !== 'function') queued.push(data);
  else globalThis.onmessage({ data });
});

await import(workerData.moduleUrl);
loaded = true;
for (const data of queued.splice(0)) globalThis.onmessage({ data });
parentPort.postMessage({ kind: 'wrapper-ready' });
