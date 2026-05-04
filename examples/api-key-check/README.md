# Example: api-key-check

Constant-time API key authentication using only `node:http` (no framework).

## When to use this pattern

- Internal service-to-service auth where a static shared key gates a route group.
- Webhook receivers where the partner sends a fixed key in a header.
- Admin endpoints behind an `X-Internal-Key` check.

## Run

```sh
cd examples/api-key-check
node --import tsx main.ts
```

## What it does

1. Wraps an HTTP handler with `requireAPIKey(expected, next)`.
2. Each request reads `X-API-Key` and calls `constantTimeEqual` against the configured key.
3. Demonstrates the three outcomes: correct (200), wrong (401), missing (401).

## Why constant-time

Native `===` or naive byte comparison short-circuits at the first differing byte, leaking timing that an attacker can exploit to recover the key one byte at a time. `constantTimeEqual` always processes both inputs in full, length-equal — wraps `crypto.timingSafeEqual`.

## Adapting to your code

```ts
import { constantTimeEqual } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

export function requireAPIKey(expected: Buffer): RequestHandler {
  return (req, res, next) => {
    const got = Buffer.from((req.headers["x-api-key"] as string) ?? "")
    if (!constantTimeEqual(got, expected)) {
      return res.status(401).end()
    }
    next()
  }
}
```
