# Example: sign-webhook

Sign and verify outgoing webhooks with HMAC-SHA256.

## When to use this pattern

- Emitting webhooks where partner integrations need to verify the request came from you.
- Receiving webhooks that come signed (Stripe, GitHub, etc.).
- Service-to-service calls within infrastructure where authenticity matters but encryption isn't required.

## Run

```sh
cd examples/sign-webhook
node --import tsx main.ts
```

## What it does

1. Signer computes HMAC-SHA256 over a JSON request body.
2. Encodes the MAC as base64 for the signature header.
3. Verifier reproduces the MAC and compares constant-time.
4. Demonstrates body-tamper rejection and wrong-key rejection.

## Production middleware

```ts
import { verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

export function verifyWebhook(secret: Buffer): RequestHandler {
  return async (req, res, next) => {
    const sig = Buffer.from((req.headers["x-signature"] as string) ?? "", "base64")
    const body = await readRawBody(req)
    if (!verify(secret, body, sig)) {
      return res.status(401).end()
    }
    ;(req as any).rawBody = body
    next()
  }
}
```

## See also

- [`webhook-with-timestamp`](../webhook-with-timestamp) — Stripe-style signing with replay-defense timestamp tolerance.
