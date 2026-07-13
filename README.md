# Blackpine Personal Vault

A single-user, zero-knowledge file vault designed for Cloudflare Workers, D1 and R2. The interface deliberately resembles Windows Command Prompt. Encryption and decryption run inside a dedicated browser Web Worker; the backend is designed to receive ciphertext, wrapped keys and opaque identifiers only.

## Security design

- Argon2id password derivation through pinned `libsodium-wrappers-sumo` using the supplied 128 MiB / operations-limit-4 profile.
- A random 256-bit vault root key wrapped by the passphrase-derived key.
- Separate libsodium KDF subkeys for file-key wrapping and metadata encryption.
- A fresh random secretstream key per file.
- XChaCha20-Poly1305 secretstream encryption in 4 MiB chunks.
- Encrypted filenames, MIME types, plaintext sizes and chunk hashes. The server still sees ciphertext size, chunk count, timestamps and access patterns.
- Authenticated object identity, version and chunk position.
- Final-tag, chunk-hash and complete-file SHA-256 verification during decryption.
- Recovery code wraps the vault root separately; the server never receives the recovery key.
- API token and vault passphrase are separate. The minimum 48-character token authorizes ciphertext access but cannot decrypt files. `DEAUTH`, tab hiding and inactivity clear it from the page session on a best-effort basis.
- No third-party scripts, analytics, fonts, remote assets, localStorage or sessionStorage.
- Strict default-deny CSP, cross-origin isolation, no framing, no production source maps, no workers.dev/preview URLs and no automatic Worker observability in the supplied configuration.

## Important limitations

This is not formally certified or independently audited. A malicious or compromised frontend deployment can replace the JavaScript and steal secrets before encryption. A compromised browser, device, extension, keyboard, display or operating system can also expose plaintext. JavaScript cannot guarantee perfect erasure of all historical memory copies. Server deletion cannot prove that no provider backup or attacker copy exists.

The supplied route is `vault.blackpinecybersecurity.com`. Protect GitHub and Cloudflare with hardware-backed passkeys, place Cloudflare Access in front of the vault for the exact owner identity, and keep the marketing site on a separate deployment.

## Browser-only deployment from GitHub Codespaces

All commands below can run in the browser-based Codespaces terminal; no local development installation is required.

1. Open this repository in GitHub Codespaces.
2. Install pinned dependencies:

   ```bash
   npm ci
   ```

3. Authenticate Wrangler to Cloudflare:

   ```bash
   npx wrangler login
   ```

4. Create the D1 database:

   ```bash
   npx wrangler d1 create blackpine-personal-vault
   ```

   Replace the zero UUID in `wrangler.jsonc` with the returned database ID.

5. Create the private R2 bucket:

   ```bash
   npx wrangler r2 bucket create blackpine-personal-vault
   ```

6. Generate a high-entropy API token in Codespaces, then save it as a Worker secret:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   npx wrangler secret put VAULT_API_TOKEN
   ```

   Paste the generated value at the prompt. Store a separate offline copy because the website requires it for `AUTH`.

7. Create the D1 tables:

   ```bash
   npm run db:init:remote
   ```

8. Run the full checks and deploy:

   ```bash
   npm run deploy
   ```

9. The custom domain is already declared in `wrangler.jsonc`; confirm it is the intended subdomain before deployment. Configure Cloudflare Access for that hostname and allow only the owner. Do not place HTML rewriting, analytics or third-party scripts in front of it.

10. Visit the vault and run:

    ```text
    STATUS
    AUTH
    SETUP
    RECOVERY
    ```

## Development checks

```bash
npm run check
npm run deploy:dry
```

`npm run check` runs syntax validation, unit tests, a local Wrangler D1/R2 integration test, a production build and automated security assertions. `dist/release-manifest.json` contains SHA-256 hashes for the generated release files.

## Command reference

- `AUTH` — load the separate server API token into worker memory.
- `SETUP` — create the vault and one-time recovery code.
- `UNLOCK` / `LOCK` — load or erase the vault keys for the current page session.
- `DEAUTH` — erase the API token and lock the vault.
- `UPLOAD` / `LIST` / `DOWNLOAD <id>` / `DELETE <id>` — ciphertext-backed server vault operations.
- `ENCRYPT` / `DECRYPT` — standalone streaming `.bpv` packages without server storage.
- `RECOVERY` / `RECOVER` — save the setup recovery code or replace a lost passphrase.

## Recommended operational controls

- Require two-person review for changes to `crypto-core.js`, `crypto-worker.js`, `server.js`, dependency versions and CSP.
- Disable force pushes and require passing checks on the deployment branch.
- Pin GitHub Actions by commit SHA if CI is added.
- Enable Cloudflare account audit logs and alerts.
- Rotate the API token after suspected exposure.
- Do not add analytics, tag managers, chat widgets, remote fonts, file previews or arbitrary HTML rendering.

## Further documentation

- `ARCHITECTURE.md` — trust boundary, data flow, key hierarchy and threat model.
- `DEPLOYMENT_CHECKLIST.md` — browser-only Cloudflare deployment and production checks.
- `SECURITY_AUDIT.md` — tests performed, findings fixed, residual risks and untested boundaries.
