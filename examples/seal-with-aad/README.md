# Example: seal-with-aad

Bind ciphertext to a context using additional authenticated data (AAD).

## When to use AAD

Whenever a ciphertext should only be valid in a specific context:

- Session tokens bound to a user ID
- Per-tenant data bound to a tenant ID
- Per-row encryption bound to a primary key
- Per-route tokens bound to an HTTP path

If the AAD differs at decrypt time, `open` throws `TamperedError` — even when the key is correct.

## Run

```sh
cd examples/seal-with-aad
node --import tsx main.ts
```

## What it does

1. Issues a session token for "alice" with AAD = `"user:alice"`.
2. Opens as alice → succeeds.
3. Opens the same token as "bob" → throws `TamperedError`.

## How it works

GCM authenticates AAD into the cipher tag. The 16-byte tag at the end of every ciphertext is computed over (nonce + ciphertext + aad). If `open` is called with different aad, the recomputed tag won't match and decryption rejects.

The AAD is **not** encrypted — only authenticated. It stays cleartext alongside the ciphertext, or (more usefully) is reconstructed at decrypt time from external state (the user ID from the session, etc.).

## What this protects against

- Token replay across users (alice's token isn't valid for bob).
- Token replay across tenants.
- Token replay across endpoints.

## What it does NOT protect against

- Replay against the same user (use a one-time nonce or expiry inside the plaintext).
- Token leakage through logs or headers (operational concern).
- Stolen server key (defense-in-depth: KMS, key rotation).
