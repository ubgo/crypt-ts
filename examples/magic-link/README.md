# Example: magic-link

Stateless password-reset / email-verify links built around `Sealer.seal` / `Sealer.open`. For a built-in helper, see the [`time-locked-token`](../time-locked-token) example.

## When to use this pattern

- Password reset emails (~1h TTL).
- Email verification on signup (~24h TTL).
- Passwordless login (~5min TTL).

## Run

```sh
cd examples/magic-link
node --import tsx main.ts
```

## What it does

1. Issues a token by JSON-encoding `{u: userID, e: expiry}` and sealing with a purpose-binding AAD ("pwreset-v1").
2. Verifies on click: opens, parses, checks expiry.
3. Demonstrates cross-purpose replay rejection.
4. Demonstrates expired-token rejection.

## Adapting to your code

```ts
import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const PURPOSE_RESET = "pwreset-v1"
const RESET_TTL_MS = 60 * 60 * 1000

interface LinkPayload {
  u: string
  e: number
}

export function issueResetLink(sealer: Sealer, userID: string): string {
  const payload: LinkPayload = {
    u: userID,
    e: Math.floor((Date.now() + RESET_TTL_MS) / 1000),
  }
  return sealer.seal(JSON.stringify(payload), Buffer.from(PURPOSE_RESET))
}

export function verifyResetLink(sealer: Sealer, token: string): string {
  const pt = sealer.open(token, Buffer.from(PURPOSE_RESET))
  const p = JSON.parse(pt.toString("utf8")) as LinkPayload
  if (Math.floor(Date.now() / 1000) >= p.e) {
    throw new Error("link expired")
  }
  return p.u
}
```

## See also

- [`time-locked-token`](../time-locked-token) — same pattern, less boilerplate, distinct `ExpiredError`.
