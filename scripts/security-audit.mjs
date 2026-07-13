import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const failures = [];
const checks = [];

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else files.push(path);
  }
  return files;
}

function check(condition, description) {
  checks.push(description);
  if (!condition) failures.push(description);
}

const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
const app = await readFile(new URL('../src/client/app.js', import.meta.url), 'utf8');
const worker = await readFile(new URL('../src/client/crypto-worker.js', import.meta.url), 'utf8');
const core = await readFile(new URL('../src/client/crypto-core.js', import.meta.url), 'utf8');
const config = await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
const source = `${app}\n${worker}\n${core}`;
const distFiles = await walk(dist);

check(!/<script[^>]+src=["']https?:\/\//i.test(html), 'No remotely hosted scripts in generated HTML');
check(!/<link[^>]+href=["']https?:\/\//i.test(html), 'No remotely hosted styles or fonts in generated HTML');
check(!/\blocalStorage\b|\bsessionStorage\b/.test(source), 'No browser persistent storage APIs in vault client');
check(!/\.innerHTML\s*=|insertAdjacentHTML|document\.write/.test(source), 'No dynamic HTML injection sinks in vault client');
check(!/\beval\s*\(|new Function\s*\(/.test(source), 'No application-level eval or Function constructor');
check(!/console\.(log|debug|info)\s*\(/.test(source), 'No informational console logging in vault client');
check(server.includes("frame-ancestors 'none'"), 'CSP denies framing');
check(server.includes("default-src 'none'"), 'CSP starts from default deny');
check(server.includes("require-trusted-types-for 'script'"), 'CSP requires Trusted Types for script sinks');
check(server.includes("Cross-Origin-Embedder-Policy': 'require-corp'"), 'Cross-origin embedder isolation enabled');
check(server.includes("Authorization"), 'API requires bearer authorization');
check(worker.includes('crypto_pwhash') || core.includes('crypto_pwhash'), 'Argon2id password derivation is present');
check(worker.includes('crypto_secretstream_xchacha20poly1305'), 'Authenticated secretstream file encryption is present');
check(source.includes('crypto_aead_xchacha20poly1305_ietf'), 'XChaCha20-Poly1305 key and metadata wrapping is present');
check(distFiles.every((file) => !file.endsWith('.map')), 'Production build contains no source maps');
const workerBundle = await readFile(distFiles.find((file) => /crypto-worker-.*\.js$/.test(file)), 'utf8');
check(workerBundle.includes('WebAssembly.instantiate') && workerBundle.includes('crypto_aead_xchacha20poly1305_ietf'), 'Pinned libsodium WebAssembly/runtime is bundled into the local worker asset');
check(distFiles.some((file) => file.endsWith('release-manifest.json')), 'Release file hash manifest exists');
check(!source.includes('VAULT_API_TOKEN='), 'No API token value is embedded in client source');
check(core.includes('memLimit: 128 * 1024 * 1024') && core.includes('opsLimit: 4'), 'Default Argon2id cost is 128 MiB and four operations');
check(worker.includes("case 'clear-token'") && app.includes('DEAUTH'), 'Explicit API-token erasure command is present');
check(server.includes('readBodyWithLimit') && server.includes('application/octet-stream'), 'Chunk uploads use content-type validation and a bounded streaming reader');
check(server.includes('cleanupExpiredUploads') && config.includes('17 * * * *'), 'Expired upload cleanup has an hourly scheduled trigger');
check(config.includes('"workers_dev": false') && config.includes('"preview_urls": false'), 'Public workers.dev and preview URLs are disabled');
check(config.includes('vault.blackpinecybersecurity.com') && config.includes('"custom_domain": true'), 'Dedicated custom domain is configured');
check(/\"observability\"\s*:\s*\{\s*\"enabled\"\s*:\s*false/.test(config), 'Automatic Worker observability is disabled to reduce metadata retention');
check(server.includes("worker-src 'self'; child-src 'none'"), 'CSP restricts workers to same-origin and denies child contexts');

if (failures.length) {
  console.error(`Security audit failed ${failures.length}/${checks.length} checks:`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Security audit passed ${checks.length} automated checks.`);
