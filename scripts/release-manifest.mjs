import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../dist/', import.meta.url));

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (entry.name !== 'release-manifest.json') files.push(path);
  }
  return files;
}

const files = await walk(root);
const manifest = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  files: {}
};

for (const file of files.sort()) {
  const content = await readFile(file);
  manifest.files[relative(root, file).replaceAll('\\', '/')] = {
    sha256: createHash('sha256').update(content).digest('hex'),
    bytes: content.byteLength
  };
}

await writeFile(new URL('../dist/release-manifest.json', import.meta.url), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Wrote release manifest for ${files.length} files.`);
