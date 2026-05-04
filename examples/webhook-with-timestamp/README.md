# Example: webhook-with-timestamp

Stripe-style webhook signing with a timestamp tolerance to defend against replay attacks.

## When to use this pattern

- Emitting webhooks where you want to prevent attackers from replaying captured-but-still-valid signed requests.
- Receiving webhooks from a partner (Stripe, GitHub, etc.) that uses this pattern.

## When the simpler [`sign-webhook`](../sign-webhook) is enough

If your transport already prevents replay (TLS-pinned, internal-only network), you don't need the timestamp dance. Just sign + verify the body.

## Run

```sh
cd examples/webhook-with-timestamp
node --import tsx main.ts
```

## What it does

1. Signer builds the header `t=<unix-seconds>,v1=<hex-mac>` where the MAC is computed over `<unix-seconds>.<body>`.
2. Verifier parses the header, checks (a) the MAC matches and (b) the timestamp is within tolerance (default 5 min).
3. Demonstrates rejection paths: timestamp 10 minutes old (replay), wrong secret, tampered body.

## Wire format (header)

```
X-Signature: t=1700000000,v1=<64-hex-char-mac>
```

The signed payload is `t.body` — concatenation of the timestamp string, a literal period, and the request body bytes.

## Adapting to your code

```ts
import { sign, verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const REPLAY_TOLERANCE_MS = 5 * 60 * 1000

export function signWebhook(secret: Buffer, body: Buffer): string {
  const ts = Math.floor(Date.now() / 1000).toString()
  const signed = Buffer.concat([Buffer.from(`${ts}.`), body])
  const mac = sign(secret, signed)
  return `t=${ts},v1=${mac.toString("hex")}`
}

export function verifyWebhook(secret: Buffer, body: Buffer, header: string): void {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=") as [string, string]))
  const ts = parts.t!
  const tsInt = parseInt(ts, 10)
  if (!Number.isFinite(tsInt)) throw new Error("malformed timestamp")
  if (Math.abs(Date.now() - tsInt * 1000) > REPLAY_TOLERANCE_MS) {
    throw new Error("timestamp outside tolerance — possible replay")
  }
  const mac = Buffer.from(parts.v1!, "hex")
  const signed = Buffer.concat([Buffer.from(`${ts}.`), body])
  if (!verify(secret, signed, mac)) throw new Error("signature mismatch")
}
```
