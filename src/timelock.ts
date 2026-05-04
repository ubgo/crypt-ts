/**
 * Time-locked tokens — a sealed payload with a hard expiry. Stateless
 * one-time tokens for password reset, email verify, magic login.
 *
 * Internal layout (inside the AEAD):
 *
 *   [expiry_unix:8 BE][payload:N]
 *
 * The whole thing is sealed; on the wire it's a normal v1 ciphertext.
 */

import { Buffer } from "node:buffer"

import { open, seal } from "./aead.js"
import { CryptError, InvalidCiphertextError } from "./errors.js"

export class ExpiredError extends CryptError {
  override readonly name = "ExpiredError"
}

/**
 * Issue a token sealing payload alongside an expiry under key.
 *
 * @param ttlMs Time-to-live in milliseconds. Must be positive.
 * @param aad   Optional purpose-binding AAD (e.g., "pwreset-v1") to
 *              prevent token-type confusion across endpoints.
 */
export function issueToken(
  key: Buffer | Uint8Array,
  payload: Buffer | string,
  ttlMs: number,
  aad?: Buffer | Uint8Array,
): string {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new RangeError(`crypt: ttlMs must be positive; got ${ttlMs}`)
  }
  const expiry = Math.floor((Date.now() + ttlMs) / 1000)
  const pt = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload)
  const wrapped = Buffer.alloc(8 + pt.length)
  wrapped.writeBigUInt64BE(BigInt(expiry), 0)
  pt.copy(wrapped, 8)
  return seal(key, wrapped, aad)
}

/**
 * Verify a token: opens, checks the embedded expiry, returns payload.
 *
 * Throws ExpiredError if the embedded expiry is in the past.
 */
export function verifyToken(
  key: Buffer | Uint8Array,
  token: string,
  aad?: Buffer | Uint8Array,
): Buffer {
  const wrapped = open(key, token, aad)
  if (wrapped.length < 8) {
    throw new InvalidCiphertextError("crypt: token plaintext too short")
  }
  const expiry = Number(wrapped.readBigUInt64BE(0))
  if (Math.floor(Date.now() / 1000) >= expiry) {
    throw new ExpiredError("crypt: token expired")
  }
  return wrapped.subarray(8)
}
