/**
 * Magic-link / password-reset link, stateless.
 *
 * A user requests a password-reset email. We issue a URL like
 *   https://app.com/reset?t=<token>
 * where <token> is a sealed payload containing { user_id, expires_at }.
 * No DB write needed. When the user clicks, we open the token, check
 * expiry, admit them.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const PURPOSE_PWRESET = "pwreset-v1"
const PURPOSE_EMAILVERIFY = "email-verify-v1"
const RESET_TTL_MS = 60 * 60 * 1000 // 1 hour

interface LinkPayload {
  u: string // user id
  e: number // expires-at unix seconds
}

function issueLink(sealer: Sealer, userID: string, purpose: string, ttlMs: number): string {
  const payload: LinkPayload = {
    u: userID,
    e: Math.floor((Date.now() + ttlMs) / 1000),
  }
  return sealer.seal(JSON.stringify(payload), Buffer.from(purpose))
}

function verifyLink(sealer: Sealer, token: string, purpose: string): string {
  let pt: Buffer
  try {
    pt = sealer.open(token, Buffer.from(purpose))
  } catch {
    throw new Error("invalid token")
  }
  let payload: LinkPayload
  try {
    payload = JSON.parse(pt.toString("utf8")) as LinkPayload
  } catch {
    throw new Error("invalid token")
  }
  if (Math.floor(Date.now() / 1000) >= payload.e) {
    throw new Error("token expired")
  }
  return payload.u
}

const key = Buffer.from("01234567890123456789012345678901")
const sealer = new Sealer(key)

const token = issueLink(sealer, "usr_42", PURPOSE_PWRESET, RESET_TTL_MS)
const url = `https://app.example.com/reset?t=${token}`
console.log(`emailed link:\n  ${url}\n`)

console.log(`link valid for user: ${verifyLink(sealer, token, PURPOSE_PWRESET)}`)

try {
  verifyLink(sealer, token, PURPOSE_EMAILVERIFY)
} catch (e) {
  console.log(`cross-purpose replay: ${(e as Error).message}`)
}

const expired = issueLink(sealer, "usr_99", PURPOSE_PWRESET, -3600 * 1000)
try {
  verifyLink(sealer, expired, PURPOSE_PWRESET)
} catch (e) {
  console.log(`expired token: ${(e as Error).message}`)
}
