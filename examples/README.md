# Examples

Runnable example programs for `@ubgo/crypt`. Each subdirectory has a `main.ts` runnable with `tsx` or `node --import tsx`.

| Example                                       | Demonstrates                                      |
| --------------------------------------------- | ------------------------------------------------- |
| [`encrypt-field/`](./encrypt-field)           | Encrypt-at-rest pattern for a database column.    |
| [`sign-webhook/`](./sign-webhook)             | Sign and verify webhooks with HMAC-SHA256.        |
| [`random-token/`](./random-token)             | API keys, magic-link tokens, log correlation IDs. |
| [`seal-with-aad/`](./seal-with-aad)           | Bind ciphertext to a user/tenant via AAD.         |
| [`sealer/`](./sealer)                         | Application-wide bound-key Sealer.                |
| [`migrate-cbc-to-gcm/`](./migrate-cbc-to-gcm) | One-shot migration from legacy AES-CBC to AEAD.   |

## Running

```sh
pnpm install -g tsx
tsx examples/encrypt-field/main.ts
```

Or from the repo root with `pnpm`:

```sh
pnpm exec tsx examples/encrypt-field/main.ts
```
