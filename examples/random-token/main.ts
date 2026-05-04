/**
 * Generate cryptographically-random tokens, IDs, and keys.
 */

import { AEAD_KEY_SIZE, randomBytes, randomHex, randomToken } from "@ubgo/crypt"

const apiKey = randomToken(32)
console.log(`API key:        ${apiKey}  (${apiKey.length} chars)`)

const magicTok = randomToken(16)
console.log(`magic token:    ${magicTok}  (${magicTok.length} chars)`)

const csrf = randomToken(24)
console.log(`CSRF token:     ${csrf}  (${csrf.length} chars)`)

const logID = randomHex(8)
console.log(`log id:         ${logID}  (${logID.length} chars)`)

const keyBytes = randomBytes(AEAD_KEY_SIZE)
console.log(
  `AEAD key bytes: ${keyBytes.length} bytes (hex: ${keyBytes.subarray(0, 8).toString("hex")})`,
)
