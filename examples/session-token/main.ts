/**
 * Stateless session token with embedded expiry — a JWT-like pattern
 * implemented as a sealed payload, smaller and without algorithm
 * confusion.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

interface Session {
  u: string
  s?: string[]
  i: number // issued-at unix seconds
  e: number // expires-at unix seconds
}

const SESSION_AAD = "session-v1"
const SESSION_TTL_S = 24 * 60 * 60 // 24 hours
const CLOCK_SKEW_S = 30

export function issueSession(sealer: Sealer, userID: string, scopes: string[] = []): string {
  const now = Math.floor(Date.now() / 1000)
  const payload: Session = {
    u: userID,
    s: scopes.length > 0 ? scopes : undefined,
    i: now,
    e: now + SESSION_TTL_S,
  }
  return sealer.seal(JSON.stringify(payload), Buffer.from(SESSION_AAD))
}

export function openSession(sealer: Sealer, token: string): Session {
  let pt: Buffer
  try {
    pt = sealer.open(token, Buffer.from(SESSION_AAD))
  } catch {
    throw new Error("invalid session")
  }
  let s: Session
  try {
    s = JSON.parse(pt.toString("utf8")) as Session
  } catch {
    throw new Error("invalid session")
  }
  const now = Math.floor(Date.now() / 1000)
  if (now >= s.e) throw new Error("session expired")
  if (s.i > now + CLOCK_SKEW_S) throw new Error("session in the future")
  return s
}

const sealer = new Sealer(Buffer.from("01234567890123456789012345678901"))
const tok = issueSession(sealer, "usr_42", ["read", "write"])
console.log(`session token (${tok.length} chars):\n  ${tok}\n`)

const s = openSession(sealer, tok)
console.log(
  `opened: user=${s.u} scopes=${(s.s ?? []).join(",")} expires=${new Date(s.e * 1000).toISOString()}`,
)

try {
  openSession(sealer, tok.slice(0, -3) + "XYZ")
} catch (e) {
  console.log(`tampered: ${(e as Error).message}`)
}
