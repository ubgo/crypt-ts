# Example: ed25519-sign

Ed25519 public-key signatures.

## When to use this pattern

- Webhook signing where partners verify with your public key (no shared secret to leak).
- Software update / licence-file signing.
- Distributed verification: publish a public key once, anyone can validate.

For symmetric (shared-secret) signing, prefer `sign` / `verify` (HMAC-SHA256). HMAC is faster.

## Run

```sh
cd examples/ed25519-sign
node --import tsx main.ts
```

## What it does

1. Generates an Ed25519 keypair.
2. Signs a webhook body — produces a 64-byte signature.
3. Verifies with the public key.
4. Demonstrates rejection of tampered body, tampered signature, wrong public key.

## HTTP integration

Outgoing:

```ts
import { signEd25519 } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const sig = signEd25519(privateKey, body)
fetch(url, {
  method: "POST",
  headers: {
    "X-Signature": sig.toString("base64"),
    "X-Signature-Algorithm": "ed25519",
  },
  body,
})
```

Incoming:

```ts
import { verifyEd25519 } from "@ubgo/crypt"

const sig = Buffer.from((req.headers["x-signature"] as string) ?? "", "base64")
if (!verifyEd25519(publicKey, body, sig)) {
  return res.status(401).end()
}
```

## Cross-language

Sign in Go (`SignEd25519`), verify here (`verifyEd25519`), and vice versa — same Ed25519 algorithm, byte-identical output.
