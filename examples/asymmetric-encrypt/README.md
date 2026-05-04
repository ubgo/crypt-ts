# Example: asymmetric-encrypt

X25519 + ChaCha20-Poly1305 sealed-box. Anyone with the recipient's public key can encrypt; only the recipient (with the matching private key) can decrypt.

## When to use this pattern

- End-to-end encrypted messages where the server should not be able to read.
- Distributing config files with secrets to multiple recipients.
- Sending data to a partner you've exchanged public keys with.

## Run

```sh
cd examples/asymmetric-encrypt
node --import tsx main.ts
```

## What it does

1. Generates a recipient X25519 keypair.
2. Sender encrypts under the public key — does not need the private key.
3. Recipient decrypts with the private key.
4. Demonstrates a different private key cannot decrypt.
5. Adds a sender-authentication layer: signs with Ed25519 before sealing, recipient unwraps and verifies the signature against a known sender public key.

## Sender authentication

Sealed-box semantics are anonymous-sender by design. To authenticate the sender, sign with Ed25519 first:

```ts
const sig = signEd25519(senderPriv, payload)
const ct = sealAsymmetric(recipientPub, Buffer.concat([sig, payload]))

// Recipient
const opened = openAsymmetric(recipientPriv, ct)
const gotSig = opened.subarray(0, ED25519_SIGNATURE_SIZE)
const gotMsg = opened.subarray(ED25519_SIGNATURE_SIZE)
const ok = verifyEd25519(senderPub, gotMsg, gotSig)
```

## Cross-language

Wire format (version 0x05) is byte-identical to the Go counterpart's `SealAsymmetric` / `OpenAsymmetric`. Anything sealed in Go can be opened here with the matching private key, and vice versa.
