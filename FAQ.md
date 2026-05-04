# FAQ

## What does this package replace?

Hand-rolled wrappers around `node:crypto`. Most Node services need a small subset — encrypt-at-rest, sign webhooks, generate API tokens — and most reinvent the wrappers. This package provides them, audited, tested, and byte-for-byte compatible with the Go counterpart.

## Why not just use `node:crypto` directly?

You can. But Node's Cipher API is mutable-builder-pattern, which has a notorious foot-gun: forgetting to concatenate `update()` and `final()` outputs. The buggy `aitoolscrypt.ts` sibling that motivated this package made exactly that mistake. The clean wrapper API removes the foot-gun.

## Does this work in the browser?

No, this targets Node.js (`node:crypto` only). A browser/WebCrypto build is on the future roadmap. For now, decrypt server-side and send plaintext over HTTPS.

## Does this work on Cloudflare Workers / Vercel Edge?

Not directly — those runtimes don't ship `node:crypto`. They use WebCrypto, which has a different API. Use the package on the Node side; if you need Edge crypto, use WebCrypto directly.

Vercel Serverless functions (Node.js runtime) work fine. AWS Lambda Node runtime works fine.

## Why no password hashing?

Password hashing belongs server-side, and "server-side" in our typical setup means the Go service. If a Node service genuinely needs to hash passwords, pull in the `argon2` npm package directly. We don't ship it under this brand because we want a single, well-tuned implementation in Go.

## Why no JWT?

JWT has well-documented foot-guns: `alg=none`, algorithm confusion. Our `examples/session-token` shows the same stateless-token shape (small payload + expiry) using `seal` directly — no JOSE header, no algorithm negotiation. If you need real JWT, use `@panva/jose`.

## What if I lose the key?

You lose the data. There is no recovery. Operationally:

- Store keys in a secrets manager (AWS Secrets Manager, Vercel env vars marked Sensitive, etc.).
- Have a rotation policy so any single key loss doesn't lose all data.
- Don't store keys in source-controlled `.env` files.

## Can I use `Buffer` and `Uint8Array` interchangeably?

Yes. All public functions accept `Buffer | Uint8Array` for keys, AAD, and binary plaintext. `Buffer` is preferred internally for ergonomics; the function will convert if needed.

## Why is `verify` return `boolean` instead of throwing?

Failed signature isn't an exceptional condition — it's a normal outcome the caller is checking for. `if (!verify(...)) abort` is cleaner than `try { verify() } catch`. `open` does throw because it has multiple distinct failure modes.

## How fast is this?

See [`BENCHMARKS.md`](./BENCHMARKS.md) for real numbers. Short version: AEAD seal/open at 150-300k ops/sec, sign/verify at 350-400k ops/sec. Network/DB will bottleneck your service before crypto.

## Why is `Sealer` a class but `seal` is a free function?

The class binds the key once at construction; the free function takes the key per call. Use `Sealer` in long-running services, free functions in scripts and one-shots.

## Can I encrypt large files?

Up to a few hundred MB with the buffer-based approach in `examples/encrypted-file`. Streaming AEAD for arbitrary-size files is on the v1.2 roadmap.

## Why does the import include `/legacy`?

The legacy subpath holds backward-compat shims for AES-CBC ciphertext. The two-import-path pattern makes it easy to grep `@ubgo/crypt/legacy` to find every site that needs to be migrated to AEAD.

## How do I test code that uses crypt?

Inject a `Sealer` constructed with a fixed test key:

```ts
import { Sealer } from "@ubgo/crypt"

const sealer = new Sealer(Buffer.alloc(32, 0x01)) // deterministic test key
const svc = new Service(sealer)
```

The package itself has no I/O; nothing to mock. Just call the real functions.

## Does this work with TypeScript strict mode?

Yes. We compile under `strict: true`, `noUncheckedIndexedAccess: true`, and other strict flags. All public types are non-`any`.

## Does this work with CommonJS?

Yes. We ship dual ESM + CJS via `tsup`. Both `import { seal } from "@ubgo/crypt"` (ESM) and `const { seal } = require("@ubgo/crypt")` (CJS) work.

## Can I use this with Bun / Deno?

Bun: yes, fully compatible with `node:crypto`.

Deno: works under the Node compatibility layer (`npm:@ubgo/crypt`). Native Deno crypto has a different API; we're not yet a first-class Deno package.

## Will Go-encrypted ciphertext decrypt here, and vice versa?

Yes. That's the entire point. Both sides target the same wire format, validated by shared test vectors in CI.

```ts
// Decrypt something Go's crypt.Seal produced:
import { open } from "@ubgo/crypt"
const pt = open(sharedKey, ciphertextFromGo)
```

## How do I report a security vulnerability?

Open a private GitHub security advisory: https://github.com/ubgo/crypt-ts/security/advisories/new

We aim to acknowledge within 48 hours and patch P0 issues within 7 days.

## Where's the design rationale?

The Go counterpart has `SECURITY.md`, `WIRE_FORMAT.md`, and `USAGE.md` covering the design in depth. They apply equally to this package. Read [`github.com/ubgo/crypt`](https://github.com/ubgo/crypt) for the long form.
