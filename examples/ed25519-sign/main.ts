/**
 * Ed25519 public-key signatures.
 *
 * Use case: emit a signed artifact (webhook, software update,
 * licence file) where verifiers don't have the signing key. Signer
 * holds the private key; verifiers hold the public key.
 *
 * Compare with HMAC sign/verify (shared secret). Ed25519 separates
 * the roles: the signer's private key never leaves the signing
 * service.
 */

import { generateEd25519, signEd25519, verifyEd25519 } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

// Boot: generate or load from secrets manager.
const { publicKey, privateKey } = generateEd25519()
console.log(`public key  (publish freely): ${publicKey.toString("base64")}`)
console.log(`private key (keep secret):    ${privateKey.toString("base64").slice(0, 24)}...\n`)

// Signer side.
const body = Buffer.from(`{"event":"order.created","id":"ord_42"}`)
const sig = signEd25519(privateKey, body)

console.log("--- outgoing webhook ---")
console.log("X-Signature-Algorithm: ed25519")
console.log(`X-Signature: ${sig.toString("base64")}`)
console.log(`Body: ${body.toString("utf8")}\n`)

// Verifier side.
console.log(`verified: ${verifyEd25519(publicKey, body, sig)}`)

const tampered = Buffer.from(body.toString().replace("ord_42", "ord_99"))
console.log(`verify tampered body: ${verifyEd25519(publicKey, tampered, sig)}`)

const { publicKey: otherPub } = generateEd25519()
console.log(`verify wrong public key: ${verifyEd25519(otherPub, body, sig)}`)
