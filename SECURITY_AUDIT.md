# Security Audit Record

## Scope and honesty statement

This is an internal engineering review of the source and generated build in this package. It is not an independent professional cryptographic audit, certification, formal proof, or penetration test. No claim of being “CIA-grade” or unbreakable is made.

Review date: 2026-07-12.

## Architecture reviewed

- dedicated browser Web Worker for cryptography;
- Cloudflare Worker API;
- D1 ciphertext metadata and state;
- R2 encrypted chunks;
- Windows Command Prompt-style interface;
- standalone `.bpv` package encryption/decryption;
- Cloudflare deployment and security configuration.

## Controls verified in source

- Pinned `libsodium-wrappers-sumo` dependency.
- Argon2id with a 128 MiB memory limit, operations limit 4, unique salt and 256-bit output.
- Random 256-bit vault root and independent random per-file keys.
- Purpose-separated libsodium KDF keys.
- XChaCha20-Poly1305 for root/file-key/manifest wrapping.
- XChaCha20-Poly1305 secretstream for chunked files.
- Authenticated chunk position, count, object identity, version and plaintext size.
- Final-tag, chunk-hash, total-size and whole-file hash verification.
- Encrypted filename, MIME type, plaintext size and content hashes.
- No plaintext browser persistence APIs.
- No external scripts, fonts, analytics or remote assets.
- No dynamic HTML injection sinks in the client.
- Strict default-deny CSP and cross-origin isolation.
- Hidden secret prompts with no command-history echo.
- API token/vault passphrase separation.
- Explicit token erasure plus automatic deauthentication on inactivity or hidden page.
- Same-origin state-change checks and authenticated API routes.
- Bounded streaming body reader and strict encrypted-chunk content type.
- One-time upload sessions, duplicate rejection and atomic D1 completion batch.
- Scheduled cleanup for abandoned encrypted chunks.
- Public workers.dev and preview URLs disabled.
- Automatic Worker observability disabled in the supplied configuration.

## Automated results

### Unit tests

`npm run test`: **5/5 passed**.

Covered:

- correct/wrong passphrase behavior;
- recovery-code checksum;
- object-bound file-key and manifest authentication;
- secretstream corruption and order rejection;
- final stream-tag state;
- protected-record hash changes.

### Production build checks

`npm run check`: **passed**.

- JavaScript syntax checks passed.
- Production Vite build passed.
- No source maps were emitted.
- Pinned libsodium runtime/WASM was bundled locally.
- Release SHA-256 manifest was generated.
- **26 automated source/build assertions passed.**

### Dependency audit

- `npm audit --omit=dev --audit-level=moderate`: **0 vulnerabilities**.
- `npm audit --audit-level=high`: **0 vulnerabilities** at review time.

This result can change after publication and must be rerun before each release.

### Wrangler deployment validation

`npm run deploy:dry`: **passed** with D1, R2 and static-assets bindings recognized. This does not prove that the user's real Cloudflare account, D1 ID, custom domain, secret or Access policy is configured correctly.

### Cryptographic worker/backend integration

A Node worker-thread harness ran the actual crypto Web Worker against a local Wrangler D1/R2 environment. **Passed**:

- token loading;
- one-time vault setup;
- recovery-code creation;
- client-side encrypted upload;
- local manifest decryption/listing;
- ciphertext download and byte-for-byte plaintext recovery;
- lock and passphrase unlock;
- standalone `.bpv` encryption/decryption;
- recovery-based passphrase replacement;
- deletion and empty-list verification.

Reproducible integration sample: 43 plaintext bytes; 43 recovered bytes; 1,421-byte encrypted package. Wrong vault and package passphrases and a tampered package were also rejected.

### HTTP/API integration

Verified locally:

- unauthenticated vault access returned 401;
- cross-origin state change returned 403;
- incorrect chunk content type returned 415;
- security headers included CSP and HSTS;
- duplicate chunks were rejected;
- ciphertext body hashes were checked;
- completed encrypted objects could be listed, fetched and deleted;
- expired upload session and R2 chunk cleanup ran through the scheduled handler.

### Browser UI validation limitation

The HTML/CSS/client source and generated build were reviewed, but automated Chromium navigation was blocked by the managed execution environment's URL policy. Therefore, no claim is made that a full real-browser visual/E2E suite passed. The actual cryptographic Web Worker and backend were tested independently as described above. A final manual browser test on the deployed HTTPS domain remains mandatory.

## Findings fixed during review

1. File keys now wipe even when upload-session creation fails.
2. Prepared local decryption retains only the per-file key instead of the vault root and derived keys.
3. Output write/close failures now fail the operation rather than being silently ignored.
4. Output completion is awaited outside the asynchronous message event to avoid a close/result race.
5. Hostile package framing now has strict UUID, version, chunk-count, chunk-size, total-size and trailing-data checks.
6. Decrypted manifests now receive structural, size and hash-length validation.
7. Encrypted request bodies now use an explicit streaming size cap.
8. Abandoned upload chunks now have scheduled cleanup.
9. Default Argon2id settings were raised from 64 MiB/3 operations to 128 MiB/4 operations.
10. API token minimum length was raised to 48 characters.
11. Automatic observability, workers.dev and preview URLs were disabled.
12. CSP worker/child directives and HSTS duration were tightened.

## Remaining risks

1. **Malicious frontend release:** control of the deployment can replace JavaScript and capture secrets before encryption. Web-only operation cannot fully remove this risk.
2. **Endpoint compromise:** malware, extensions, accessibility tooling, screen capture and keyloggers can access plaintext.
3. **JavaScript memory semantics:** reachable typed arrays are overwritten, but strings, engine copies and reclaimed memory cannot be guaranteed erased.
4. **Rollback:** authenticated records detect alteration, but a malicious backend can replay a complete previously valid state because no independent external checkpoint is implemented.
5. **Metadata:** the server sees timing, opaque IDs, object count, ciphertext size, chunk count and access patterns.
6. **Deletion:** the active service deletes its references and R2 objects, but external copies and provider backups cannot be proven erased.
7. **Availability:** the service or account owner can delete or withhold ciphertext. Encryption does not guarantee availability.
8. **API token model:** a stolen token permits ciphertext access and destructive actions. It does not decrypt data. Cloudflare Access should be added as another gate.
9. **No external review:** automated testing cannot replace independent protocol review and penetration testing.

## Deployment blockers

- Replace the placeholder D1 database ID.
- Create the R2 bucket.
- Set `VAULT_API_TOKEN` as a Cloudflare secret.
- Apply `schema.sql` remotely.
- Configure Cloudflare Access for the exact owner identity.
- Confirm the dedicated custom domain.
- Run the mandatory deployed-browser tests in `DEPLOYMENT_CHECKLIST.md`.
