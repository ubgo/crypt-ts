/**
 * Random helpers wrap node:crypto.randomBytes with typed output
 * formats. All helpers source bytes from the OS-level CSPRNG and
 * are safe for cryptographic use.
 */

import { randomBytes as nodeRandomBytes } from "node:crypto"
import { Buffer } from "node:buffer"

/**
 * Returns n cryptographically-random bytes from the OS CSPRNG.
 * @throws RangeError on n <= 0.
 *
 * @example Generate an AEAD key
 * ```ts
 * import { randomBytes, AEAD_KEY_SIZE } from "@ubgo/crypt"
 * const key = randomBytes(AEAD_KEY_SIZE) // 32 random bytes
 * ```
 */
export function randomBytes(n: number): Buffer {
  if (!Number.isInteger(n) || n <= 0) {
    throw new RangeError(`crypt: RandomBytes n must be a positive integer; got ${n}`)
  }
  return nodeRandomBytes(n)
}

/**
 * Returns n random bytes encoded as URL-safe base64 without padding.
 * Suitable for API keys, magic-link tokens, CSRF, session IDs.
 *
 * Output length is ceil(n * 4 / 3) characters, no '=' padding.
 * - randomToken(16) → 22 chars (~96 bits of entropy)
 * - randomToken(24) → 32 chars (~144 bits)
 * - randomToken(32) → 43 chars (~192 bits)
 *
 * @example Generate an API key
 * ```ts
 * const apiKey = randomToken(32) // 43-char URL-safe string
 * ```
 *
 * @example Magic-link token
 * ```ts
 * const token = randomToken(16)
 * const url = `https://app.example.com/verify?t=${token}`
 * ```
 */
export function randomToken(n: number): string {
  return randomBytes(n).toString("base64url")
}

/**
 * Returns n random bytes encoded as lowercase hexadecimal.
 * Output length is exactly 2 * n characters.
 *
 * @example Log correlation ID
 * ```ts
 * const corrID = randomHex(8) // "1a2b3c4d5e6f7080"
 * logger.info("request received", { corr_id: corrID })
 * ```
 */
export function randomHex(n: number): string {
  return randomBytes(n).toString("hex")
}
