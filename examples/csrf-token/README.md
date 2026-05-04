# Example: csrf-token

CSRF token issue + verify, double-submit pattern with a sealed-value token.

## When to use this pattern

- Web app with HTML forms that mutate state.
- Any case where you set a cookie and want to confirm the form submitter has it.

## Run

```sh
cd examples/csrf-token
node --import tsx main.ts
```

## What it does

1. Issues a CSRF token sealed with `{session_id, issued_at}`.
2. Verifies on submission: opens the seal, checks session match, checks TTL.
3. Demonstrates rejection paths: foreign session, tampered token.

## Adapting to your code

```ts
import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

interface CsrfPayload {
  s: string
  i: number
}
const CSRF_AAD = "csrf-v1"
const CSRF_TTL_S = 15 * 60

export function issueCSRF(sealer: Sealer, sessionID: string): string {
  const payload: CsrfPayload = { s: sessionID, i: Math.floor(Date.now() / 1000) }
  return sealer.seal(JSON.stringify(payload), Buffer.from(CSRF_AAD))
}

export function verifyCSRF(sealer: Sealer, token: string, expectedSession: string): void {
  const pt = sealer.open(token, Buffer.from(CSRF_AAD))
  const p = JSON.parse(pt.toString("utf8")) as CsrfPayload
  if (p.s !== expectedSession) throw new Error("csrf token does not belong to this session")
  if (Math.floor(Date.now() / 1000) - p.i > CSRF_TTL_S) throw new Error("csrf token expired")
}
```
