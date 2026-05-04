/**
 * Format-detecting decrypt: dispatches between AES-GCM and AES-CBC
 * ciphertext shapes.
 *
 * Useful for one-shot migration scripts iterating a table that
 * contains both formats, or read paths during a rollover window
 * when writers are emitting AEAD but historical CBC ciphertext may
 * still be present.
 *
 * For normal application code, call `open` or `decryptCbc` directly
 * — you should know which format the input is in.
 */

import { Buffer } from "node:buffer"

import { open } from "./aead.js"
import { decryptCbc } from "./cbc.js"
import { CBC_BLOCK_SIZE, AEAD_MIN_SIZE, VERSION_AEAD_V1 } from "./format.js"
import { UnknownFormatError } from "./errors.js"

/**
 * Attempts to decrypt ciphertext that may be in either AEAD
 * (base64url, version 0x01 prefix) or AES-CBC (hex) format.
 *
 * Dispatch:
 *   1. If ciphertext base64url-decodes AND first byte is 0x01 AND
 *      length >= 29 → call open(key, ciphertext, aad).
 *   2. Else if ciphertext hex-decodes AND length looks like CBC →
 *      call decryptCbc(key, ciphertext). AAD is ignored (CBC has
 *      no AAD).
 *   3. Else throw UnknownFormatError.
 *
 * Use cases:
 *   - One-shot migration scripts re-encrypting all rows with seal.
 *   - Read-path during a rollover window when writers emit AEAD but
 *     old AEAD-illiterate data may still be encountered.
 *
 * Anti-use-case: do not call openAuto from normal application code.
 * Production reads should call open directly.
 */
export function openAuto(
  key: Buffer | Uint8Array,
  ciphertext: string,
  aad?: Buffer | Uint8Array,
): Buffer {
  // Try AEAD path first.
  if (looksLikeAEAD(ciphertext)) {
    try {
      return open(key, ciphertext, aad)
    } catch {
      // Fall through to CBC if AEAD detection was a false positive.
    }
  }

  // Try CBC path.
  if (looksLikeCBC(ciphertext)) {
    try {
      return decryptCbc(key, ciphertext)
    } catch {
      // Fall through to UnknownFormatError.
    }
  }

  throw new UnknownFormatError("crypt: ciphertext format not recognized")
}

function looksLikeAEAD(ciphertext: string): boolean {
  let raw: Buffer
  try {
    raw = Buffer.from(ciphertext, "base64url")
  } catch {
    return false
  }
  if (raw.length < AEAD_MIN_SIZE) return false
  return raw[0] === VERSION_AEAD_V1
}

function looksLikeCBC(ciphertext: string): boolean {
  if (ciphertext.length % 2 !== 0) return false
  let raw: Buffer
  try {
    raw = Buffer.from(ciphertext, "hex")
  } catch {
    return false
  }
  if (raw.length * 2 !== ciphertext.length) return false
  if (raw.length < CBC_BLOCK_SIZE) return false
  const body = raw.length - CBC_BLOCK_SIZE
  return body > 0 && body % CBC_BLOCK_SIZE === 0
}
