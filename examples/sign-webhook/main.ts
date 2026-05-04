/**
 * Sign and verify outgoing webhooks with HMAC-SHA256.
 *
 * Pattern: signer and verifier share a secret. Signer computes HMAC
 * over the request body, sends it as a header. Verifier reproduces
 * the HMAC and compares constant-time.
 */

import { sign, verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const secret = Buffer.from("partner-webhook-secret")

// --- Signer side ---
const body = Buffer.from(`{"event":"order.created","data":{"id":"ord_42"}}`)
const mac = sign(secret, body)
const signature = mac.toString("base64")

console.log("--- outgoing request ---")
console.log(`X-Signature-Algorithm: hmac-sha256`)
console.log(`X-Signature: ${signature}`)
console.log(`Body: ${body.toString("utf8")}\n`)

// --- Verifier side ---
const receivedSig = Buffer.from(signature, "base64")
console.log("verified:", verify(secret, body, receivedSig))

// --- Tamper detection ---
const tamperedBody = Buffer.from(body)
tamperedBody[10]! ^= 0x01
console.log("tampered body verified:", verify(secret, tamperedBody, receivedSig))

// --- Wrong key rejection ---
console.log("wrong-key verified:", verify(Buffer.from("wrong"), body, receivedSig))
