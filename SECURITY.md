# Security Model

This document describes what `@ubgo/crypt` (crypt-ts) defends against, what it doesn't, and the design choices behind its security guarantees. The wire format is shared with the Go counterpart [`github.com/ubgo/crypt`](https://github.com/ubgo/crypt); its [`SECURITY.md`](https://github.com/ubgo/crypt/blob/main/SECURITY.md) covers the same model in more depth and applies equally.

## Threat model

We assume an adversary who can:

- Read network traffic between services (i.e., is on the wire).
- Read or modify the database where ciphertexts are stored.
- Submit arbitrary inputs to the application.
- Make timing observations on responses.

We assume the adversary cannot:

- Read process memory of a running server (a different threat — a KMS would address it).
- Subvert the Node.js `node:crypto` implementations of AES, HMAC, etc.
- Compromise the kernel-level CSPRNG (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows).

## Guarantees

### Confidentiality

Anything sealed with `seal` (or `Sealer.seal`) is computationally indistinguishable from random to anyone without the key. AES-256 in GCM mode provides 256-bit security against brute-force attack — well beyond any feasible attack budget.

### Authenticity

Anything sealed with `seal` is bound to its key, nonce, and AAD via a 128-bit GCM authentication tag. Modifying any part of the ciphertext, key, or AAD before `open` throws `TamperedError`. The tag has a 2^-128 false-positive rate for an attacker guessing tags blindly.

### Replay resistance via AAD

Binding ciphertext to a context (user ID, tenant ID, message type) using AAD prevents cross-context replay. A token issued for user A is not valid as user B if the AAD is `user:<id>`.

### Constant-time operations

- `verify` (HMAC) and `constantTimeEqual` are backed by `crypto.timingSafeEqual`, which is constant-time.
- Length is checked before the constant-time compare so mismatched-length inputs return `false` without a throw that leaks timing.

### Key length validation

- AEAD operations require exactly 32 bytes. Other lengths throw `InvalidKeyError` rather than silently downgrading.
- AES-CBC accepts 16/24/32 bytes (AES-128/192/256). Choose the size that matches the system you're interoperating with; AES-256 is the conservative default for new CBC use.

### Modern algorithms

- AEAD: AES-256-GCM (NIST SP 800-38D) and ChaCha20-Poly1305 (RFC 8439)
- MAC: HMAC-SHA256 (RFC 2104)
- Signatures: Ed25519 (RFC 8032)
- Key agreement: X25519 (RFC 7748)
- Random: OS CSPRNG via `node:crypto`

No deprecated algorithms ship: no MD5, no SHA-1, no DES/3DES, no ECB mode (ever), no raw RSA.

## Non-guarantees

### Compromised process memory

If an attacker has read access to the process's memory, every key in memory is exposed. We do not proactively zero buffers; the V8 GC will eventually reclaim them but the timing is non-deterministic. If your threat model includes memory disclosure, use a Key Management Service (AWS KMS, GCP KMS, HashiCorp Vault) with envelope encryption at the service boundary.

### Side-channel attacks on AES

We rely on Node's `node:crypto` (OpenSSL) AES implementation. On modern Intel and AMD CPUs, AES-NI provides hardware constant-time AES. On CPUs without AES-NI, prefer ChaCha20-Poly1305 (`sealChaCha20`), whose implementation is naturally constant-time.

### Password hashing is out of scope

This package does not hash passwords — that is a server-side concern best done where argon2/bcrypt run natively. Use the Go counterpart's `HashPassword`, or `argon2` directly if you must hash in Node. Do not use `seal`/`sign` as a password hash.

### Operational concerns

The package does not protect against logging plaintext secrets, printing keys held in environment variables, sharing keys over unencrypted channels, or reusing a key across dev/staging/prod. These are operational disciplines outside the library's scope.

### Length leakage

Ciphertext overhead is fixed; an attacker who sees a ciphertext can determine the plaintext length within one byte. If your threat model requires hiding length (e.g., distinguishing "yes" from "no"), pad the plaintext to a fixed size before encryption.

## Security design choices

### No global mutable key

There is no package-level key and no `loadKey()`. A `Sealer` (or `KeyRing`) takes its key at construction and validates it immediately, so there is no default-key footgun, no race between "set key" and "encrypt," and nothing global for parallel tests to trip over.

### Version-tagged wire format

Every ciphertext carries a version byte, and decoders explicitly enumerate the versions they accept. When an algorithm needs upgrading, a new version byte is added; old ciphertext keeps working while new writes use the new algorithm. One byte of overhead buys cryptographic agility.

### HMAC-SHA256, not raw SHA-256

Raw SHA-256 is vulnerable to length-extension: given `H(secret || message)`, an attacker can compute `H(secret || message || padding || extension)` without the secret. HMAC structurally prevents this.

### base64url-no-pad for AEAD output

URL-safe characters with no `=` padding: safe in URLs, headers, and cookies without escaping, compact, and byte-identical across Node's `Buffer.from(s, "base64url")` and Go's `base64.RawURLEncoding`.

## Reporting a vulnerability

We use GitHub Private Security Advisories:

1. Visit https://github.com/ubgo/crypt-ts/security/advisories/new
2. Describe the issue, reproduction, and impact.

We aim to acknowledge within 48 hours, assess severity within 7 days, and ship a patch for P0 issues within 7 days of confirmed reproduction. Please do not file public GitHub issues for security vulnerabilities.

## Audit status

`crypt-ts` has not been independently audited. The implementation is small and depends only on Node's standard-library `node:crypto`. We welcome external review — if you find issues, please report via the security advisory process above.

## References

- [NIST SP 800-38D — GCM specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 8439 — ChaCha20-Poly1305](https://datatracker.ietf.org/doc/rfc8439/)
- [RFC 2104 — HMAC](https://datatracker.ietf.org/doc/rfc2104/)
- [RFC 8032 — Ed25519](https://datatracker.ietf.org/doc/rfc8032/)
- [Node.js crypto documentation](https://nodejs.org/api/crypto.html)
