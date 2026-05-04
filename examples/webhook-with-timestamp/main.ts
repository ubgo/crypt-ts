/**
 * Stripe-style webhook verification with timestamp tolerance to
 * defend against replay attacks.
 *
 * Header format: "t=<unix-seconds>,v1=<hex-mac>"
 * Signed payload: <unix-seconds>.<body>
 */

import { sign, verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

export function signWebhook(secret: Buffer, body: Buffer, now: Date = new Date()): string {
  const ts = Math.floor(now.getTime() / 1000).toString()
  const signed = Buffer.concat([Buffer.from(`${ts}.`), body])
  const mac = sign(secret, signed)
  return `t=${ts},v1=${mac.toString("hex")}`
}

export function verifyWebhook(
  secret: Buffer,
  body: Buffer,
  header: string,
  now: Date = new Date(),
  toleranceMs: number = 5 * 60 * 1000,
): void {
  const parts = header.split(",")
  if (parts.length !== 2) throw new Error("malformed signature header")
  let ts = ""
  let v1 = ""
  for (const p of parts) {
    if (p.startsWith("t=")) ts = p.slice(2)
    else if (p.startsWith("v1=")) v1 = p.slice(3)
  }
  if (!ts || !v1) throw new Error("malformed signature header")
  const tsInt = parseInt(ts, 10)
  if (!Number.isFinite(tsInt)) throw new Error("malformed timestamp")
  const delta = Math.abs(now.getTime() - tsInt * 1000)
  if (delta > toleranceMs) {
    throw new Error("timestamp outside tolerance — possible replay")
  }
  const mac = Buffer.from(v1, "hex")
  const signed = Buffer.concat([Buffer.from(`${ts}.`), body])
  if (!verify(secret, signed, mac)) throw new Error("signature mismatch")
}

const secret = Buffer.from("partner-webhook-secret")
const body = Buffer.from(`{"event":"order.created","id":"ord_42"}`)
const now = new Date()

const header = signWebhook(secret, body, now)
console.log(`--- outgoing ---\nX-Signature: ${header}\nBody: ${body.toString("utf8")}\n`)

try {
  verifyWebhook(secret, body, header, new Date(now.getTime() + 1000))
  console.log("verify within window: ok")
} catch (e) {
  console.log(`verify within window: ${(e as Error).message}`)
}

try {
  verifyWebhook(secret, body, header, new Date(now.getTime() + 10 * 60 * 1000))
} catch (e) {
  console.log(`replay 10m later: ${(e as Error).message}`)
}

try {
  verifyWebhook(Buffer.from("wrong"), body, header, now)
} catch (e) {
  console.log(`wrong secret: ${(e as Error).message}`)
}

try {
  verifyWebhook(secret, Buffer.from(body.toString().replace("ord_42", "ord_99")), header, now)
} catch (e) {
  console.log(`tampered body: ${(e as Error).message}`)
}
