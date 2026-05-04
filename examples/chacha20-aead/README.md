# Example: chacha20-aead

ChaCha20-Poly1305 AEAD as an alternative to AES-256-GCM.

## When to use this pattern

- Hardware without AES-NI (older ARM, embedded). Software ChaCha20 is faster than software AES.
- Defense-in-depth: mixing cipher families across services.

For typical x86_64 / ARMv8 cloud servers, prefer `seal` (AES-256-GCM).

## Run

```sh
cd examples/chacha20-aead
node --import tsx main.ts
```

## What it does

1. Generates a 32-byte key.
2. Round-trips through `sealChaCha20` / `openChaCha20`.
3. Demonstrates that `open` rejects v2 ciphertext (and vice versa) — wire format version byte distinguishes them.
4. Tamper detection.

## Wire format

Version byte `0x02` (vs `0x01` for AES-GCM). Same nonce + tag layout. Cross-language with the Go counterpart's `SealChaCha20` / `OpenChaCha20`.

## Adapting to your code

```ts
import { sealChaCha20, openChaCha20 } from "@ubgo/crypt"

const ct = sealChaCha20(key, plaintext, aad)
const pt = openChaCha20(key, ct, aad)
```

For most apps, just pick AES-GCM (`seal`/`open`) consistently. ChaCha20 is for the specific edge cases above.
