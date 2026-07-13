# Architecture and Threat Model

## Security objective

Blackpine Personal Vault is a single-user encrypted file service. The browser is the cryptographic trust boundary. The Cloudflare Worker, D1 database and R2 bucket are treated as potentially observable storage infrastructure and are not given plaintext vault keys.

This design aims to preserve confidentiality and detect modification if D1, R2, a database export, an object-store export, an API session, or the Worker backend is exposed. It does not make a compromised browser, operating system, browser extension, keyboard, display, or malicious frontend release safe.

## Data flow

```text
User file
  -> browser File object
  -> dedicated crypto Web Worker
  -> 4 MiB authenticated encrypted chunks
  -> Cloudflare Worker API
  -> private R2 bucket

Filename, MIME type, plaintext size and chunk hashes
  -> encrypted manifest in browser
  -> Cloudflare Worker API
  -> D1
```

D1 also receives unavoidable operational metadata: opaque object IDs, ciphertext size, chunk count, timestamps, upload state and hash-chain values. It does not receive the decrypted filename, MIME type, plaintext bytes, vault passphrase, recovery key, unwrapped vault root, or unwrapped per-file key.

## Key hierarchy

```text
Vault passphrase
  -> Argon2id (128 MiB, operations limit 4, unique 128-bit salt)
  -> unlock key
  -> XChaCha20-Poly1305 unwraps random 256-bit vault root

Vault root
  -> libsodium KDF context BPWRAP01 -> file-key wrapping key
  -> libsodium KDF context BPMETA01 -> metadata encryption key

Each file
  -> fresh random 256-bit secretstream key
  -> XChaCha20-Poly1305 secretstream chunks
```

The recovery code contains a separate random 256-bit recovery key plus a short typo-detection checksum. The recovery key wraps the same vault root independently. The server stores only that wrapped root.

## Authentication boundary

A high-entropy `VAULT_API_TOKEN` authorizes access to ciphertext storage. It is not a decryption key. The UI requires the token to be at least 48 printable characters and keeps it only in Web Worker memory for the page session. `DEAUTH`, page hiding, and ten minutes of inactivity clear the token and vault keys on a best-effort basis.

Cloudflare Access should be configured in front of the custom domain as an additional edge authentication layer restricted to the owner's identity. The API token remains necessary as a separate storage authorization secret.

## File integrity

Each encrypted chunk is bound through authenticated additional data to:

- object ID;
- format version;
- object version;
- chunk index;
- total chunk count;
- plaintext file size.

Decryption verifies each ciphertext SHA-256 value, secretstream authentication, chunk order, final stream tag, total plaintext size and whole-file SHA-256 value. Metadata and wrapped keys are independently authenticated with object identity and version.

## Standalone package format

`ENCRYPT` writes a versioned `.bpv` package containing:

- fixed magic and format version;
- Argon2id parameters and salt;
- passphrase-wrapped package root;
- wrapped per-file key;
- secretstream header;
- length-prefixed ciphertext chunks;
- encrypted manifest;
- framing checksum values and final magic.

The parser bounds header/footer sizes, validates UUID/version/chunk framing, limits file size and chunk count, checks declared ciphertext totals, rejects trailing data, and verifies all authenticated content before reporting success.

## Server controls

- default-deny CSP and same-origin-only Worker execution;
- no third-party code or remote assets;
- bearer authentication with hashed constant-time comparison;
- same-origin checks for state-changing requests;
- strict JSON, UUID, base64url, KDF, size and schema validation;
- bounded streaming request reader for encrypted chunks;
- one-time upload sessions and duplicate-chunk rejection;
- R2 object keys contain only opaque IDs and indexes;
- D1 batch commits for object creation state;
- hourly cleanup of expired/incomplete uploads;
- no automatic Worker observability in the supplied configuration;
- workers.dev and preview URLs disabled;
- custom domain restricted to `vault.blackpinecybersecurity.com`.

## Residual risks

1. A malicious frontend deployment can steal the passphrase or plaintext before encryption. A web-only service cannot fully remove this risk.
2. JavaScript cannot prove complete memory erasure. Typed arrays are overwritten where reachable, but strings and engine copies may remain until garbage collection.
3. The backend can delete, withhold or replay an entirely valid older vault state. Independent client checkpoints are not yet implemented.
4. The backend learns timing, object count, ciphertext size, chunk count and access patterns.
5. R2/D1 deletion cannot prove that no external copy or provider backup exists.
6. A stolen API token permits ciphertext retrieval and denial-of-service actions, although it does not decrypt files. Cloudflare Access materially reduces exposure when correctly configured.
7. This code has not received independent professional cryptographic review, formal verification, penetration testing, or certification.
