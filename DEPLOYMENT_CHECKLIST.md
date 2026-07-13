# Cloudflare Deployment Checklist

All steps can be completed in a browser using GitHub Codespaces and the Cloudflare dashboard.

## Before deployment

- Use a private GitHub repository.
- Protect GitHub and Cloudflare with hardware-backed passkeys.
- Require review for changes to `crypto-core.js`, `crypto-worker.js`, `server.js`, dependencies, CSP and Wrangler configuration.
- Confirm that `vault.blackpinecybersecurity.com` is the intended dedicated subdomain. Change the route in `wrangler.jsonc` before deployment if not.
- Do not commit `.dev.vars`, `.env`, recovery codes, API tokens or decrypted test files.

## Provision resources

```bash
npm ci
npx wrangler login
npx wrangler d1 create blackpine-personal-vault
npx wrangler r2 bucket create blackpine-personal-vault
```

Replace the zero UUID in `wrangler.jsonc` with the D1 database ID returned by Cloudflare.

Generate and store a random API token:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
npx wrangler secret put VAULT_API_TOKEN
```

Keep an offline copy. This token is separate from the vault passphrase and recovery code.

Create the remote schema:

```bash
npm run db:init:remote
```

## Verify before release

```bash
npm run check
npm audit --omit=dev --audit-level=moderate
npm run deploy:dry
```

Review `dist/release-manifest.json`. A hash manifest detects accidental build changes; it does not protect against a malicious signer or compromised deployment account.

## Deploy

```bash
npm run deploy
```

The supplied configuration disables workers.dev and preview URLs and routes only the dedicated custom domain.

## Add Cloudflare Access

Before putting sensitive data in the vault, create a Cloudflare Access self-hosted application for `vault.blackpinecybersecurity.com` and allow only the owner's exact identity. Deny all other users. Keep the API token enabled as a second, independent authorization secret.

## First use

Open the dedicated vault domain and run:

```text
STATUS
AUTH
SETUP
RECOVERY
```

Save the recovery file offline and test recovery using non-sensitive sample data before relying on the service.

## Production checks

- Confirm the browser shows a valid HTTPS certificate.
- Confirm `workers.dev` and preview URLs are inaccessible.
- Confirm Cloudflare Access blocks an unauthorised browser.
- Confirm D1 and R2 are private and are bound only to this Worker.
- Confirm no analytics, HTML rewriting, third-party scripts or cache rules have been added.
- Upload a test file, download it and compare it byte-for-byte.
- Corrupt a local `.bpv` copy and confirm decryption fails.
- Lock and hide the tab; confirm the site requires `AUTH` and `UNLOCK` again.
- Export and securely retain Cloudflare/GitHub recovery methods separately from the vault recovery code.
