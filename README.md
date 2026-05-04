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

`@ubgo/crypt` is built for Node.js applications that need a small set of cryptography primitives done well, with safe defaults, no foot-guns, and (optionally) byte-for-byte interop with a Go service. **Reach for it when you're about to write any of the following:**

- I need to encrypt a value before storing it (database column, cookie, file) and decrypt it back later.
- I need to sign outgoing webhooks and verify incoming ones with HMAC-SHA256.
- I need to generate cryptographically-random API keys, magic-link tokens, CSRF tokens.
- I need a stateless session token (JWT-like, smaller, no algorithm confusion).
- I need a Node service to decrypt data my Go service encrypted (or vice versa).
- I need to compare an API key in constant time, without leaking timing.
- I need to migrate AES-CBC ciphertext from a previous system to authenticated AES-GCM.
- I'm tired of fighting Node's mutable Cipher API and want a clean wrapper.

If any of those are on your plate, this is the package.

**Not for you if:** you need browser/WebCrypto (this targets Node.js only), JWT/JOSE (use `@panva/jose`), TLS, PKI, password hashing in Node (do that server-side in Go via the Go counterpart's `HashPassword`).

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

**Legacy AES-CBC support** at `@ubgo/crypt/legacy` — `encryptCbc`, `decryptCbc`, plus `openAuto` migration helper that detects format and dispatches. For reading existing v0.x data only.

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

// Legacy CBC (Deprecated — migration only)
import { encryptCbc, decryptCbc, openAuto } from "@ubgo/crypt/legacy"
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
