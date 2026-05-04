# Example: cross-lang-ts

End-to-end demo: TypeScript encrypts, Go decrypts (and vice versa). Same shared key, same AAD, byte-for-byte interoperable wire format.

## Run

### TS encrypts → Go decrypts

```sh
# 1. From this repo:
node --import tsx examples/cross-lang-ts/encrypt.ts

# 2. Copy the printed ciphertext.

# 3. In the Go repo:
cd ../crypt
go run ./examples/cross_lang_go/decrypt -ct '<paste>'
```

### Go encrypts → TS decrypts

```sh
# 1. From the Go repo:
cd ../crypt
go run ./examples/cross_lang_go

# 2. Copy the printed ciphertext.

# 3. Back in this repo:
node --import tsx examples/cross-lang-ts/decrypt.ts <paste-ciphertext-here>
```

The plaintext on the receiving side is byte-identical to what was encrypted on the sending side.

## Why this works

Both implementations target the same wire format ([WIRE_FORMAT.md](https://github.com/ubgo/crypt/blob/main/WIRE_FORMAT.md)):

```
base64url-no-pad( 0x01 || nonce[12] || ciphertext || tag[16] )
```

Both use AES-256-GCM under the hood (Go's `crypto/cipher.NewGCM`, Node's `crypto.createCipheriv("aes-256-gcm", ...)`). They produce byte-identical output when given the same `(key, nonce, aad, plaintext)` — the contract verified by `testdata/vectors.json` in CI.

## Files

- `encrypt.ts` — TS-side encrypt, prints ciphertext for Go to consume.
- `decrypt.ts` — TS-side decrypt; pass the Go-emitted ciphertext as a CLI arg.
