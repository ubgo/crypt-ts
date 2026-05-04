# Example: session-token

Stateless session token with embedded expiry — JWT-like pattern, smaller, no algorithm-confusion foot-gun.

## When to use this pattern

- API tokens for service-to-service auth where you want statelessness.
- Browser session tokens (often paired with the [`encrypted-cookie`](../encrypted-cookie) pattern).
- Mobile app session tokens.

## Why not JWT

JWT has well-documented foot-guns (`alg=none`, algorithm confusion). Sealing a struct with `seal` avoids all of this — no algorithm header, no negotiation, no "trust the header for which key to use." If you need standard JWT, use `@panva/jose`.

## Run

```sh
cd examples/session-token
node --import tsx main.ts
```

## What it does

1. Issues a token sealing `{user_id, scopes, issued_at, expires_at}`.
2. Opens, validates expiry + clock-skew tolerance.
3. Demonstrates tamper rejection.

## Adapting to your code

```ts
import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

interface Session {
  u: string
  s?: string[]
  i: number
  e: number
}
const SESSION_AAD = "session-v1"

export function issueSession(
  sealer: Sealer,
  userID: string,
  scopes: string[],
  ttlS: number,
): string {
  const now = Math.floor(Date.now() / 1000)
  return sealer.seal(
    JSON.stringify({ u: userID, s: scopes, i: now, e: now + ttlS } satisfies Session),
    Buffer.from(SESSION_AAD),
  )
}

export function readSession(sealer: Sealer, token: string): Session {
  const pt = sealer.open(token, Buffer.from(SESSION_AAD))
  const s = JSON.parse(pt.toString("utf8")) as Session
  if (Math.floor(Date.now() / 1000) >= s.e) throw new Error("session expired")
  return s
}
```

## See also

- [`time-locked-token`](../time-locked-token) — built-in `issueToken` / `verifyToken` (less boilerplate, binary expiry encoding).
