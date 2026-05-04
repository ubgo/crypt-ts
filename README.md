# @ubgo/crypt

[![npm](https://img.shields.io/badge/npm-%40ubgo%2Fcrypt-blue)](https://www.npmjs.com/package/@ubgo/crypt) [![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> Authenticated encryption, webhook signing, and secure random for Node.js — wrapped around `node:crypto` with safe defaults and byte-for-byte interop with the Go counterpart at [`github.com/ubgo/crypt`](https://github.com/ubgo/crypt).

```ts
import { seal, open, randomBytes, AEAD_KEY_SIZE } from "@ubgo/crypt"

const key = randomBytes(AEAD_KEY_SIZE)
const ct = seal(key, "hello, world")
const pt = open(key, ct).toString("utf8")
// pt === "hello, world"
```

That's the whole API for the most common case.

---

## Is this for you?

`@ubgo/crypt` is built for Node.js applications that need a curated set of cryptography primitives done well, with safe defaults, no foot-guns, and (optionally) byte-for-byte interop with a Go service. **Reach for it when you're about to write any of the following:**

- Encrypt a value before storing it (database column, cookie, file) and decrypt it back later.
- Sign outgoing webhooks and verify incoming ones — HMAC-SHA256 or Ed25519 (public-key).
- Generate cryptographically-random API keys, magic-link tokens, CSRF tokens.
- Issue stateless time-locked tokens (password reset, email verify, magic login) with embedded expiry.
- Decrypt in Node what a Go service encrypted (or vice versa) — same wire format.
- Compare an API key in constant time without leaking timing.
- Interoperate with an existing AES-CBC system, or read ciphertext you already wrote in CBC.
- Derive per-tenant or per-purpose sub-keys from a single master with HKDF.
- Rotate keys gracefully — `KeyRing` with embedded kid; old data still readable, new writes use the active key.
- Use ChaCha20-Poly1305 instead of AES-GCM (no AES-NI hardware, or defense-in-depth diversity).
- Encrypt to a recipient's public key — X25519 + ChaCha20-Poly1305 (sealed-box), age-style.
- Sign with Ed25519 — public-key signatures where verifiers don't share the signing key.
- Stop fighting Node's mutable Cipher API and use a clean wrapper.

If any of those are on your plate, this is the package.

**Not for you if:** you need browser/WebCrypto (this targets Node.js only), JWT/JOSE (use `@panva/jose`), TLS, PKI, password hashing in Node (do it server-side in Go via the Go counterpart's `HashPassword`), or KMS adapters / streaming AEAD (Go-only in v1.2).

---

## 30-second tour

### Encrypt before storing

```ts
import { Sealer } from "@ubgo/crypt"

const sealer = new Sealer(loadAppKey()) // 32 bytes from env / secrets manager

const enc = sealer.seal("sk_live_4242deadbeef")
await db.query(`UPDATE partners SET secret = $1 WHERE id = $2`, [enc, id])

const plain = sealer.open(row.secret).toString("utf8")
```

### Bind a token to a user

```ts
const ct = sealer.seal(payload, Buffer.from(`user:${userID}`))

const pt = sealer.open(ct, Buffer.from(`user:${userID}`))
// throws TamperedError if userID differs from issue time
```

### Sign and verify a webhook

```ts
import { sign, verify } from "@ubgo/crypt"

const mac = sign(secret, body)              // signer
const ok = verify(secret, body, mac)        // verifier (constant-time)
```

### Generate an API token

```ts
import { randomToken } from "@ubgo/crypt"

const apiKey = randomToken(32) // 43-char URL-safe string
```

### Cross-language: Go encrypts, Node decrypts

```go
// Go side
ct, _ := crypt.Seal(sharedKey, payload, nil)
return ct
```

```ts
// Node side, this package
import { open } from "@ubgo/crypt"
const plaintext = open(sharedKey, ct)
```

Same wire format, byte-for-byte. Verified by shared test vectors in CI.

---

## Why this exists

The previous implementation in our codebase, `aitoolscrypt.ts`, was hand-rolled around `node:crypto` and had two latent bugs that silently corrupted any plaintext longer than 16 bytes (one AES block):

```ts
// BUG 1: passes the full hex including IV to update()
const _decrypted = decipher.update(cipherText, "hex", "utf8")
// BUG 2: discards _decrypted, returns only final()
return decipher.final("utf8")
```

The Cipher API in Node is mutable-builder — `update()` returns part of the output and `final()` returns the rest. Forgetting to concatenate is a quiet bug, with no error and no warning. The original author tested with 16-byte test data, which happened to land on the boundary where the bug doesn't manifest, and shipped.

The fix isn't more careful hand-rolling. It's one well-tested wrapper that removes the foot-gun:

```ts
import { open } from "@ubgo/crypt"
const plaintext = open(key, ciphertext)
// Internally handles update/final correctly. Caller cannot get this wrong.
```

Plus a sibling in Go using the same wire format, with a shared test vector file enforcing parity in CI. That's `@ubgo/crypt`.

---

## What's included

**Authenticated encryption (AES-256-GCM)** — `seal`, `open`, `Sealer`. Modern AEAD with a versioned wire format so future algorithms slot in without breaking decrypt of old data.

**HMAC signing** — `sign`, `verify`. Constant-time verification.

**Secure random** — `randomBytes`, `randomToken` (URL-safe base64), `randomHex`. Node CSPRNG.

**Constant-time compare** — `constantTimeEqual`. Wraps `crypto.timingSafeEqual`.

**AES-CBC** at `@ubgo/crypt` — `encryptCbc`, `decryptCbc` (16/24/32-byte keys for AES-128/192/256). First-class peer of AES-GCM; use it when interop with an existing AES-CBC system is required, or when reading ciphertext you already wrote in this format. CBC has no built-in authentication; pair with HMAC if you need tamper detection. An `openAuto` helper auto-detects AEAD vs CBC for migration scripts.

**ChaCha20-Poly1305 AEAD** — `sealChaCha20`, `openChaCha20`. Wire version 0x02. Use for hardware without AES-NI.

**HKDF key derivation** — `deriveKey`. Per-tenant or per-purpose sub-keys from a single master.

**KeyRing for rotation** — `KeyRing` class with embedded kid. Active key for new writes; retired keys remain readable until natural turnover.

**Time-locked tokens** — `issueToken`, `verifyToken`. Stateless one-time tokens with embedded expiry. Returns `ExpiredError` on expiry.

**Ed25519 signatures** — `generateEd25519`, `signEd25519`, `verifyEd25519`. Public-key signing where verifiers don't share the signing key.

**Asymmetric encryption (sealed-box)** — `generateKeyPair`, `sealAsymmetric`, `openAsymmetric`. X25519 + ChaCha20-Poly1305. Wire version 0x05.

**Cross-language wire format** — every AEAD and HMAC output is byte-identical to the Go counterpart at [`github.com/ubgo/crypt`](https://github.com/ubgo/crypt).

**Strict TypeScript** — full types, no `any`, dual ESM + CJS build.

**Zero runtime dependencies** — only `node:crypto` from the standard library.

Password hashing is intentionally not included; it's a server-side concern. Use the Go counterpart's `HashPassword` from your auth service, or pull `argon2` directly if you must hash in Node.

---

## API at a glance

```ts
// AEAD
function seal(key: Buffer | Uint8Array, plaintext: string | Buffer | Uint8Array, aad?: Buffer | Uint8Array): string
function open(key: Buffer | Uint8Array, ciphertext: string, aad?: Buffer | Uint8Array): Buffer

class Sealer {
  constructor(key: Buffer | Uint8Array)
  seal(plaintext: string | Buffer | Uint8Array, aad?: Buffer | Uint8Array): string
  open(ciphertext: string, aad?: Buffer | Uint8Array): Buffer
}

// Random
function randomBytes(n: number): Buffer
function randomToken(n: number): string   // URL-safe base64-no-pad
function randomHex(n: number): string

// Signing
function sign(key: Buffer | Uint8Array, data: Buffer | Uint8Array): Buffer
function verify(key: Buffer | Uint8Array, data: Buffer | Uint8Array, mac: Buffer | Uint8Array): boolean
function constantTimeEqual(a: Buffer | Uint8Array, b: Buffer | Uint8Array): boolean

// AES-CBC (16/24/32-byte keys; no built-in auth — pair with HMAC if needed)
import { encryptCbc, decryptCbc, openAuto } from "@ubgo/crypt"

// ChaCha20-Poly1305 (alternative AEAD; wire version 0x02)
function sealChaCha20(key: Buffer | Uint8Array, plaintext: string | Buffer | Uint8Array, aad?: Buffer | Uint8Array): string
function openChaCha20(key: Buffer | Uint8Array, ciphertext: string, aad?: Buffer | Uint8Array): Buffer

// HKDF key derivation
function deriveKey(masterKey: Buffer | Uint8Array, salt: Buffer | Uint8Array | undefined, info: Buffer | Uint8Array, length: number): Buffer

// KeyRing for rotation
class KeyRing {
  constructor(activeKid: string, activeKey: Buffer | Uint8Array)
  add(kid: string, key: Buffer | Uint8Array): void
  remove(kid: string): void
  setActive(kid: string): void
  activeKid(): string
  seal(plaintext: string | Buffer | Uint8Array, aad?: Buffer | Uint8Array): string
  open(ciphertext: string, aad?: Buffer | Uint8Array): Buffer
}

// Time-locked tokens (ExpiredError on expiry)
function issueToken(key: Buffer | Uint8Array, payload: Buffer | string, ttlMs: number, aad?: Buffer | Uint8Array): string
function verifyToken(key: Buffer | Uint8Array, token: string, aad?: Buffer | Uint8Array): Buffer

// Ed25519 signatures
function generateEd25519(): { publicKey: Buffer; privateKey: Buffer }
function signEd25519(privateKey: Buffer | Uint8Array, data: Buffer | Uint8Array): Buffer
function verifyEd25519(publicKey: Buffer | Uint8Array, data: Buffer | Uint8Array, signature: Buffer | Uint8Array): boolean

// Asymmetric (X25519 + ChaCha20-Poly1305 sealed-box)
function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer }
function sealAsymmetric(recipientPublicKey: Buffer | Uint8Array, plaintext: Buffer | string | Uint8Array): string
function openAsymmetric(recipientPrivateKey: Buffer | Uint8Array, ciphertext: string): Buffer
```

---

## Documentation

- **[RECIPES.md](./RECIPES.md)** — copy-pasteable patterns by task
- **[examples/](./examples)** — 16 runnable end-to-end TypeScript programs
- **[BENCHMARKS.md](./BENCHMARKS.md)** — real numbers and what they mean
- **[FAQ.md](./FAQ.md)** — answers to questions you'll have
- **[Go counterpart](https://github.com/ubgo/crypt)** — `USAGE.md`, `SECURITY.md`, `WIRE_FORMAT.md`, `MIGRATION.md` apply equally
- **[CHANGELOG.md](./CHANGELOG.md)**

---

## Cross-language with the Go counterpart

[`github.com/ubgo/crypt`](https://github.com/ubgo/crypt) is the Go sibling. Same API shape, same wire format, byte-identical output for the same input. Tested in CI by a shared `testdata/vectors.json`.

Three concrete patterns:

1. **Go signs, Node verifies.** Go service emits a webhook; Node receiver validates with `verify`.
2. **Go encrypts, Node decrypts.** Go API issues a session token; Node service reads it with `open`.
3. **Either side can do either side.** No "primary" — both are first-class.

If you're shipping a polyglot stack, this is the difference between "Node and Go services that mostly agree" and "Node and Go services that have correctness as a CI invariant."

---

## Install

```sh
pnpm add @ubgo/crypt
# or
npm install @ubgo/crypt
# or
yarn add @ubgo/crypt
```

Requires Node.js 18 or later.

ESM and CJS dual-published. Strict-mode TypeScript types. Zero runtime dependencies (`node:crypto` only).

---

## Status

- **v0.x** — pre-stable. Wire format is finalized but the surface API may receive small tweaks until v1.0.
- **v1.0** — frozen API. Same wire format guarantees as the Go side.

## Reporting vulnerabilities

Open a private security advisory: https://github.com/ubgo/crypt-ts/security/advisories/new

We aim to acknowledge within 48 hours and patch P0 issues within 7 days.

## License

[Apache License 2.0](./LICENSE)
