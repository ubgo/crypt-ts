/**
 * Bind ciphertext to a context using AAD (additional authenticated data).
 *
 * AAD is data that is authenticated but not encrypted. The same AAD
 * must be supplied at both seal and open. If the AAD differs, open
 * fails with TamperedError.
 */

import { open, seal, TamperedError } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const serverKey = Buffer.from("01234567890123456789012345678901")

function issueSession(userID: string, payload: string): string {
  return seal(serverKey, payload, Buffer.from(`user:${userID}`))
}

function openSession(userID: string, ciphertext: string): string {
  const pt = open(serverKey, ciphertext, Buffer.from(`user:${userID}`))
  return pt.toString("utf8")
}

const token = issueSession("alice", JSON.stringify({ role: "admin" }))
console.log(`token issued for alice: ${token}\n`)

console.log(`open as alice: ${openSession("alice", token)}`)

try {
  openSession("bob", token)
} catch (e) {
  console.log(`open as bob:   ${(e as Error).message}`)
  console.log(`is TamperedError: ${e instanceof TamperedError}`)
}
