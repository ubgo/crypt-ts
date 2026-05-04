# Example: encrypted-cookie

Encrypted session cookie — entire session payload lives in the cookie value, sealed with the server's key. No DB / Redis lookups per request.

## When to use this pattern

- Stateless web apps where session is small (< 4KB) and you want zero session-store latency.
- Horizontally-scaled services without sticky sessions.
- Edge functions where DB hops are expensive.

## When NOT to use

- Sessions that need server-side revocation.
- Sessions with large payloads (cookies are sent on every request).

## Run

```sh
cd examples/encrypted-cookie
node --import tsx main.ts
```

## What it does

1. Spins up a stdlib `node:http` server with `/login` and `/me`.
2. `/login` seals `{user_id, expires_at}`, sets `HttpOnly` cookie.
3. `/me` reads the cookie, opens the seal, returns user ID.
4. Demonstrates the unauthenticated case (no cookie → 401).

## Cookie attributes for production

- `HttpOnly` — no JS access (XSS defense).
- `Secure` — HTTPS-only.
- `SameSite=Lax` (or `Strict`) — limits cross-origin sending.
- `Path=/` (or scoped).
- `Expires` matching the embedded payload TTL.

## Adapting to your code (Express)

```ts
import { Sealer } from "@ubgo/crypt"

export function sessionMiddleware(sealer: Sealer): RequestHandler {
  return (req, res, next) => {
    const cookie = req.cookies?._session
    if (!cookie) return next()
    try {
      const pt = sealer.open(cookie, Buffer.from("cookie-v1"))
      const session = JSON.parse(pt.toString("utf8"))
      if (Math.floor(Date.now() / 1000) >= session.e) return next()
      ;(req as any).user = session.u
    } catch {
      // invalid or tampered — treat as anonymous
    }
    next()
  }
}
```
