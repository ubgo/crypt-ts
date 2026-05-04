# Recipes

Short, copy-pasteable patterns. For runnable demos see [`examples/`](./examples). The Go counterpart's [`RECIPES.md`](https://github.com/ubgo/crypt/blob/main/RECIPES.md) covers the same patterns and the explanations apply identically.

## Index

- [Encrypting and decrypting](#encrypting-and-decrypting)
- [Key management](#key-management)
- [Tokens and signing](#tokens-and-signing)
- [Authentication](#authentication)
- [Sessions and cookies](#sessions-and-cookies)
- [Webhooks](#webhooks)
- [Files and blobs](#files-and-blobs)
- [Multi-tenancy](#multi-tenancy)
- [Migrating between ciphertext formats](#migrating-between-ciphertext-formats)
- [Operational patterns](#operational-patterns)

---

## Encrypting and decrypting

### Encrypt a string

```ts
import { seal, open, randomBytes, AEAD_KEY_SIZE } from "@ubgo/crypt"

const key = randomBytes(AEAD_KEY_SIZE)
const ct = seal(key, "hello")
const pt = open(key, ct).toString("utf8")
```

### Encrypt a JSON object

```ts
const ct = sealer.seal(JSON.stringify(myObject))
const pt = JSON.parse(sealer.open(ct).toString("utf8"))
```

### Encrypt with context binding

```ts
const ct = sealer.seal(payload, Buffer.from(`user:${userID}`))
const pt = sealer.open(ct, Buffer.from(`user:${userID}`))
// open() with a different userID throws TamperedError.
```

### Encrypt a database column

```ts
// Save
const enc = sealer.seal(value)
await db.query(`UPDATE users SET secret = $1 WHERE id = $2`, [enc, userID])

// Load
const { rows } = await db.query(`SELECT secret FROM users WHERE id = $1`, [userID])
const plain = sealer.open(rows[0].secret).toString("utf8")
```

### Use a Sealer for repeated ops

```ts
import { Sealer } from "@ubgo/crypt"

const sealer = new Sealer(loadAppKey())
// Reuse `sealer` everywhere — no need to validate the key per call.
```

---

## Key management

### Load a key from environment safely

```ts
const keyHex = process.env.APP_ENCRYPTION_KEY
if (!keyHex) {
  throw new Error("APP_ENCRYPTION_KEY required")
}
const key = Buffer.from(keyHex, "hex")
if (key.length !== 32) {
  throw new Error("APP_ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
}
const sealer = new Sealer(key)
// Avoid logging keyHex — set up redaction in your logger.
```

### Generate a fresh key

```ts
import { randomBytes } from "@ubgo/crypt"
console.log(randomBytes(32).toString("hex")) // paste into secrets manager
```

### Derive per-tenant key (HKDF)

```ts
import { AEAD_KEY_SIZE } from "@ubgo/crypt"
import { hkdfSync } from "node:crypto"

function tenantKey(rootKey: Buffer, tenantID: string): Buffer {
  return Buffer.from(
    hkdfSync("sha256", rootKey, Buffer.alloc(0), Buffer.from(`tenant:${tenantID}`), AEAD_KEY_SIZE),
  )
}
```

### Multi-key reader for rotation

```ts
class MultiKeyReader {
  constructor(private readonly keys: Buffer[]) {}
  open(ct: string, aad?: Buffer): Buffer {
    let last: Error | null = null
    for (const k of this.keys) {
      try { return open(k, ct, aad) } catch (e) { last = e as Error }
    }
    throw last ?? new Error("no keys")
  }
}
const reader = new MultiKeyReader([newKey, oldKey])
```

See [`examples/key-rotation`](./examples/key-rotation).

---

## Tokens and signing

### Generate an API key

```ts
import { randomToken } from "@ubgo/crypt"
import { createHash } from "node:crypto"

const token = randomToken(32)
// Show to user once, store hash for verification.
const hash = createHash("sha256").update(token).digest("hex")
await db.query(`INSERT INTO api_keys(user_id, hash) VALUES($1, $2)`, [userID, hash])
return token
```

### Generate a magic-link token

```ts
import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

interface LinkPayload { u: string; e: number }

function magicLink(sealer: Sealer, userID: string, ttlS: number): string {
  const payload: LinkPayload = { u: userID, e: Math.floor(Date.now() / 1000) + ttlS }
  return sealer.seal(JSON.stringify(payload), Buffer.from("magic-link-v1"))
}
```

### Sign URL parameters

```ts
import { sign } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const data = `u=${userID}&exp=${Math.floor(Date.now() / 1000) + 3600}`
const mac = sign(serverSecret, Buffer.from(data))
const url = `/unsubscribe?${data}&sig=${mac.toString("base64url")}`
```

---

## Authentication

### Constant-time API key check

```ts
import { constantTimeEqual } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const provided = Buffer.from(req.headers["x-api-key"] ?? "")
if (!constantTimeEqual(provided, expectedKey)) {
  return res.status(401).end()
}
```

---

## Sessions and cookies

### Stateless session token

```ts
interface Session { u: string; e: number }

function issueSession(sealer: Sealer, userID: string, ttlS: number): string {
  return sealer.seal(
    JSON.stringify({ u: userID, e: Math.floor(Date.now() / 1000) + ttlS } satisfies Session),
    Buffer.from("session-v1"),
  )
}

function readSession(sealer: Sealer, token: string): Session {
  const pt = sealer.open(token, Buffer.from("session-v1"))
  const s = JSON.parse(pt.toString("utf8")) as Session
  if (Math.floor(Date.now() / 1000) >= s.e) throw new Error("expired")
  return s
}
```

See [`examples/session-token`](./examples/session-token).

### Encrypted session cookie

```ts
const value = sealer.seal(
  JSON.stringify({ u: userID, e: Math.floor(Date.now() / 1000) + 3600 }),
  Buffer.from("cookie-v1"),
)
res.setHeader(
  "Set-Cookie",
  `_session=${value}; HttpOnly; Path=/; SameSite=Lax`,
)
```

See [`examples/encrypted-cookie`](./examples/encrypted-cookie).

### CSRF token

```ts
// On render: seal session ID, embed in form, set as cookie.
const csrf = sealer.seal(sessionID, Buffer.from("csrf-v1"))

// On submit: verify form value matches cookie + verify seal.
if (formCSRF !== cookieCSRF) throw new Error("csrf mismatch")
const pt = sealer.open(formCSRF, Buffer.from("csrf-v1"))
```

See [`examples/csrf-token`](./examples/csrf-token).

---

## Webhooks

### Sign an outgoing webhook

```ts
import { sign } from "@ubgo/crypt"

const mac = sign(secret, body)
await fetch(url, {
  method: "POST",
  headers: {
    "X-Signature": mac.toString("base64"),
    "X-Signature-Algorithm": "hmac-sha256",
    "Content-Type": "application/json",
  },
  body,
})
```

### Verify an incoming webhook

```ts
import { verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const sig = Buffer.from((req.headers["x-signature"] as string) ?? "", "base64")
if (!verify(secret, body, sig)) {
  return res.status(401).end()
}
```

### Webhook with timestamp tolerance (Stripe-style)

See [`examples/webhook-with-timestamp`](./examples/webhook-with-timestamp).

---

## Files and blobs

### Encrypt a file before writing

```ts
import { writeFile, readFile } from "node:fs/promises"

const ct = sealer.seal(fileBytes, Buffer.from(`file:${filename}`))
await writeFile(path, ct, "utf8")

const raw = await readFile(path, "utf8")
const plain = sealer.open(raw, Buffer.from(`file:${filename}`))
```

See [`examples/encrypted-file`](./examples/encrypted-file).

### Encrypt before S3 upload (with @aws-sdk/client-s3)

```ts
const ct = sealer.seal(fileBytes, Buffer.from(`s3:${bucket}:${key}`))
await s3.send(new PutObjectCommand({
  Bucket: bucket,
  Key: key,
  Body: ct,
}))
```

---

## Multi-tenancy

### Per-tenant derived keys

```ts
import { hkdfSync } from "node:crypto"
import { AEAD_KEY_SIZE, Sealer } from "@ubgo/crypt"

function tenantSealer(rootKey: Buffer, tenantID: string): Sealer {
  const k = Buffer.from(
    hkdfSync("sha256", rootKey, Buffer.alloc(0), Buffer.from(`tenant:${tenantID}`), AEAD_KEY_SIZE),
  )
  return new Sealer(k)
}
```

See [`examples/tenant-keys`](./examples/tenant-keys).

### Bind ciphertext to tenant via AAD

```ts
const ct = sealer.seal(payload, Buffer.from(`tenant:${tenantID}`))
const pt = sealer.open(ct, Buffer.from(`tenant:${tenantID}`))
```

---

## Migrating between ciphertext formats

### Read mixed-format ciphertexts

```ts
import { openAuto } from "@ubgo/crypt"

const plain = openAuto(key, ciphertext)
```

### Batch migration script

```ts
import { seal } from "@ubgo/crypt"
import { openAuto } from "@ubgo/crypt"

const rows = await db.query(`SELECT id, ciphertext FROM partner_apps`)
for (const r of rows) {
  try {
    const plain = openAuto(key, r.ciphertext)
    const sealed = seal(key, plain)
    await db.query(`UPDATE partner_apps SET ciphertext = $1 WHERE id = $2`, [sealed, r.id])
  } catch (e) {
    console.warn(`row ${r.id}: ${(e as Error).message}`)
  }
}
```

See [`examples/migrate-cbc-to-gcm`](./examples/migrate-cbc-to-gcm).

---

## Operational patterns

### Audit log integrity (HMAC-chained)

```ts
let prev = Buffer.alloc(0)
for (const e of entries) {
  const signed = Buffer.concat([prev, e.payload])
  e.mac = sign(auditSecret, signed)
  prev = e.mac
}
```

See [`examples/audit-log-chain`](./examples/audit-log-chain).

### Inject Sealer for testing

```ts
import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const testKey = Buffer.alloc(32, 0x01)
const sealer = new Sealer(testKey)
const svc = new Service(sealer)
```

### Decrypt error handling

```ts
import { CryptError, TamperedError, open } from "@ubgo/crypt"

try {
  return open(key, ciphertext, aad)
} catch (e) {
  if (e instanceof TamperedError) {
    logger.warn("ciphertext tampered, wrong key, or wrong aad")
    return null
  }
  if (e instanceof CryptError) {
    logger.warn(`crypt error: ${e.message}`)
    return null
  }
  throw e
}
```

### Cross-language interop

```ts
// Decrypt something Go's crypt.Seal produced.
import { open } from "@ubgo/crypt"

const plaintext = open(sharedKey, goCiphertext)
```

```go
// Decrypt something @ubgo/crypt sealed.
plaintext, err := crypt.Open(sharedKey, tsCiphertext, nil)
```

---

## Anti-patterns to avoid

| Don't | Do instead |
|---|---|
| Hard-code keys | Load from secrets manager / env |
| `===` to compare secrets | `constantTimeEqual` |
| Decrypt on every request when cacheable | Cache carefully — defeats encryption otherwise |
| Encrypt a password | Use `HashPassword` (Go side, server only) |
| Log decryption errors with plaintext | Log error class + correlation ID only |
| Same key in dev and prod | Per-environment keys |
| Catch all errors and silently retry | Each error class signals different action |

---

## v1.1 features

### HKDF derived keys

```ts
import { AEAD_KEY_SIZE, deriveKey, Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const tenantKey = deriveKey(rootKey, undefined, Buffer.from(`tenant:${tid}`), AEAD_KEY_SIZE)
const sealer = new Sealer(tenantKey)
```

### ChaCha20-Poly1305 alternative

```ts
import { sealChaCha20, openChaCha20 } from "@ubgo/crypt"
const ct = sealChaCha20(key, plaintext, aad)
const pt = openChaCha20(key, ct, aad)
```

### KeyRing for graceful rotation

```ts
import { KeyRing } from "@ubgo/crypt"

const ring = new KeyRing("2025", oldKey)
ring.add("2026", newKey)
ring.setActive("2026")

const fresh = ring.seal(payload)        // tagged "2026"
const pt = ring.open(oldCiphertext)     // dispatches by kid
ring.remove("2025")                     // after rotation
```

---

## v1.2 features

### Time-locked tokens

```ts
import { ExpiredError, issueToken, verifyToken } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const tok = issueToken(key, `user_id=${u.id}`, 60 * 60 * 1000, Buffer.from("pwreset-v1"))

try {
  const payload = verifyToken(key, tok, Buffer.from("pwreset-v1"))
} catch (e) {
  if (e instanceof ExpiredError) return res.status(410).end("link expired")
  return res.status(400).end("invalid link")
}
```

---

## v2 features

### Public-key signatures (Ed25519)

```ts
import { generateEd25519, signEd25519, verifyEd25519 } from "@ubgo/crypt"

const { publicKey, privateKey } = generateEd25519()
const sig = signEd25519(privateKey, body)
verifyEd25519(publicKey, body, sig) // boolean
```

### Asymmetric encryption (sealed-box)

```ts
import { generateKeyPair, openAsymmetric, sealAsymmetric } from "@ubgo/crypt"

const { publicKey, privateKey } = generateKeyPair()
const ct = sealAsymmetric(publicKey, "secret message")
const pt = openAsymmetric(privateKey, ct).toString("utf8")
```

For sender authentication, sign the plaintext with Ed25519 first, then seal.
