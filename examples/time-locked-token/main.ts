/**
 * Time-locked tokens — built-in issueToken / verifyToken with
 * embedded expiry. Stateless one-time tokens.
 */

import { ExpiredError, issueToken, verifyToken } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const key = Buffer.from("01234567890123456789012345678901")
const PURPOSE_RESET = "pwreset-v1"
const PURPOSE_VERIFY = "email-verify-v1"

// Issue a 1-hour token.
const tok = issueToken(key, "user_id=usr_42", 60 * 60 * 1000, Buffer.from(PURPOSE_RESET))
console.log(`emailed link:\n  https://app.example.com/reset?t=${tok}\n`)

// Verify and get payload.
const payload = verifyToken(key, tok, Buffer.from(PURPOSE_RESET))
console.log(`token valid, payload: ${payload.toString("utf8")}`)

// Cross-purpose replay.
try {
  verifyToken(key, tok, Buffer.from(PURPOSE_VERIFY))
} catch (e) {
  console.log(`\ncross-purpose replay: ${(e as Error).message} (rejected)`)
}

// Expired token. Manually craft one because issueToken rejects
// non-positive TTL.
import("@ubgo/crypt").then(({ seal }) => {
  const past = Math.floor(Date.now() / 1000) - 3600
  const wrapped = Buffer.alloc(8 + 5)
  wrapped.writeBigUInt64BE(BigInt(past), 0)
  Buffer.from("stale").copy(wrapped, 8)
  const expired = seal(key, wrapped, Buffer.from(PURPOSE_RESET))
  try {
    verifyToken(key, expired, Buffer.from(PURPOSE_RESET))
  } catch (e) {
    if (e instanceof ExpiredError) {
      console.log(`\nexpired token: ${e.message} (rejected)`)
    } else {
      throw e
    }
  }
})
