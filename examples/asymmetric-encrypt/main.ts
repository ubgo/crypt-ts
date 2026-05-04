/**
 * Asymmetric (sealed-box) encryption: X25519 ECDH + ChaCha20-Poly1305.
 *
 * Anyone with the recipient's public key can encrypt; only the
 * recipient (with the matching private key) can decrypt. Sender
 * identity NOT authenticated — sign the plaintext with Ed25519 first
 * if you need that.
 */

import {
  ED25519_SIGNATURE_SIZE,
  generateEd25519,
  generateKeyPair,
  openAsymmetric,
  sealAsymmetric,
  signEd25519,
  TamperedError,
  verifyEd25519,
} from "@ubgo/crypt"
import { Buffer } from "node:buffer"

// Recipient publishes their public key.
const { publicKey: recipientPub, privateKey: recipientPriv } = generateKeyPair()
console.log(`recipient public key (publish):  ${recipientPub.toString("base64")}`)
console.log(
  `recipient private key (keep):    ${recipientPriv.toString("base64").slice(0, 24)}...\n`,
)

const plaintext = Buffer.from("only the recipient can read this")
const ct = sealAsymmetric(recipientPub, plaintext)
console.log(`ciphertext (anyone can produce, only recipient can open):\n  ${ct}\n`)

const pt = openAsymmetric(recipientPriv, ct)
console.log(`decrypted by recipient: ${pt.toString("utf8")}`)

// Wrong recipient cannot decrypt.
const { privateKey: otherPriv } = generateKeyPair()
try {
  openAsymmetric(otherPriv, ct)
} catch (e) {
  if (e instanceof TamperedError) {
    console.log(`\nwrong recipient: ${e.message} (correctly rejected)`)
  } else {
    throw e
  }
}

// To authenticate the SENDER, sign first then encrypt.
const { publicKey: senderPub, privateKey: senderPriv } = generateEd25519()
const sig = signEd25519(senderPriv, plaintext)
const signed = Buffer.concat([sig, plaintext])
const signedCT = sealAsymmetric(recipientPub, signed)

const opened = openAsymmetric(recipientPriv, signedCT)
const gotSig = opened.subarray(0, ED25519_SIGNATURE_SIZE)
const gotMsg = opened.subarray(ED25519_SIGNATURE_SIZE)
const ok = verifyEd25519(senderPub, gotMsg, gotSig)
console.log(
  `\nsigned + encrypted message:\n  authenticated sender: ${ok}\n  message: ${gotMsg.toString("utf8")}`,
)
