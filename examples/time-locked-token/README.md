# Example: time-locked-token

Built-in `issueToken` / `verifyToken` for stateless one-time tokens with embedded expiry.

## When to use this pattern

- Password reset emails (~1h TTL).
- Email verification (~24h TTL).
- Magic-link login (~5min TTL).
- Any single-use one-time-action token where you don't want a server-side store.

## Run

```sh
cd examples/time-locked-token
node --import tsx main.ts
```

## What it does

1. Issues a token: payload + 1-hour TTL, sealed with a purpose-binding AAD ("pwreset-v1").
2. Verifies on the click endpoint: opens, checks the embedded expiry.
3. Demonstrates cross-purpose replay rejection (AAD mismatch).
4. Demonstrates expired-token rejection — distinct `ExpiredError` so the caller can return a specific user-facing message.

## How it works

`issueToken` packs the expiry as 8 BE bytes ahead of the payload, then seals:

```
sealed = seal(key, [expiry:8 BE][payload:N], aad)
```

`verifyToken` opens, checks the expiry, returns the payload. Wire format on the network is the same as plain `seal` output.

## Adapting to your code

```ts
import { ExpiredError, issueToken, verifyToken } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const PWRESET_AAD = "pwreset-v1"
const PWRESET_TTL_MS = 60 * 60 * 1000

async function sendResetEmail(sealer: Buffer, email: string) {
  const user = await findUserByEmail(email)
  if (!user) return // don't leak existence
  const tok = issueToken(sealer, user.id, PWRESET_TTL_MS, Buffer.from(PWRESET_AAD))
  await sendMail(email, "Reset password", `https://app.example.com/reset?t=${tok}`)
}

async function handleReset(token: string, newPassword: string) {
  let payload: Buffer
  try {
    payload = verifyToken(key, token, Buffer.from(PWRESET_AAD))
  } catch (e) {
    if (e instanceof ExpiredError) return errLinkExpired
    return errInvalidLink
  }
  const userID = payload.toString("utf8")
  // ... reset password
}
```

## Comparison with [`magic-link`](../magic-link)

The `magic-link` example builds the same shape by hand (JSON-encode + seal). `issueToken/verifyToken` packages it with binary expiry encoding for less boilerplate. Both are valid; pick by preference.
