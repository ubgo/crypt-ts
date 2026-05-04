/**
 * CSRF token issue + verify, double-submit pattern.
 *
 * Token is sealed and bound to the session ID + expiry. Comparison
 * is byte-equal on the token string; the seal itself prevents
 * forgery.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const CSRF_AAD = "csrf-v1"
const CSRF_TTL_S = 15 * 60

interface CSRFPayload {
  s: string // session id
  i: number // issued-at unix seconds
}

export function issueCSRF(sealer: Sealer, sessionID: string): string {
  return sealer.seal(
    JSON.stringify({ s: sessionID, i: Math.floor(Date.now() / 1000) } satisfies CSRFPayload),
    Buffer.from(CSRF_AAD),
  )
}

export function verifyCSRF(sealer: Sealer, token: string, expectedSession: string): void {
  let pt: Buffer
  try {
    pt = sealer.open(token, Buffer.from(CSRF_AAD))
  } catch {
    throw new Error("invalid csrf token")
  }
  const p = JSON.parse(pt.toString("utf8")) as CSRFPayload
  if (p.s !== expectedSession) {
    throw new Error("csrf token does not belong to this session")
  }
  if (Math.floor(Date.now() / 1000) - p.i > CSRF_TTL_S) {
    throw new Error("csrf token expired")
  }
}

const sealer = new Sealer(Buffer.from("01234567890123456789012345678901"))
const sessionID = "sess_abc123"
const tok = issueCSRF(sealer, sessionID)
console.log(`CSRF token: ${tok}\n`)

try {
  verifyCSRF(sealer, tok, sessionID)
  console.log("genuine submit: ok")
} catch (e) {
  console.log(`genuine submit: ${(e as Error).message}`)
}

try {
  verifyCSRF(sealer, tok, "sess_attacker")
} catch (e) {
  console.log(`foreign session: ${(e as Error).message}`)
}

try {
  verifyCSRF(sealer, tok.slice(0, -2) + "XX", sessionID)
} catch (e) {
  console.log(`tampered token: ${(e as Error).message}`)
}
