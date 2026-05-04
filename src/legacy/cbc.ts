/**
 * Legacy AES-CBC implementation for backward compatibility with data
 * encrypted by the v0.x Go API (lace/crypt or github.com/ubgo/crypt
 * EncryptCBC).
 *
 * @deprecated AES-CBC has no message authentication. New code should
 * use {@link seal} from "@ubgo/crypt" (AES-256-GCM). Retained for
 * reading existing CBC ciphertexts.
 *
 * Wire format: hex(IV[16] || PKCS7-padded ciphertext)
 *
 * Key sizes accepted: 16, 24, or 32 bytes (AES-128/192/256).
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"
import { Buffer } from "node:buffer"

import { CBC_BLOCK_SIZE } from "../format.js"
import {
  CiphertextNotBlockAlignedError,
  CiphertextTooShortError,
  InvalidCiphertextError,
  InvalidKeyError,
  InvalidPaddingError,
} from "../errors.js"

function validCBCKeyLen(n: number): boolean {
  return n === 16 || n === 24 || n === 32
}

function aesAlgoForKey(keyLen: number): string {
  switch (keyLen) {
    case 16:
      return "aes-128-cbc"
    case 24:
      return "aes-192-cbc"
    case 32:
      return "aes-256-cbc"
    default:
      throw new InvalidKeyError(`crypt: CBC requires 16/24/32 bytes; got ${keyLen}`)
  }
}

/**
 * PKCS#7-pads the plaintext, AES-CBC encrypts with a fresh random
 * IV, and returns hex(IV || ciphertext).
 *
 * @deprecated Use seal from "@ubgo/crypt".
 */
export function encryptCbc(
  key: Buffer | Uint8Array,
  plaintext: string | Buffer | Uint8Array,
): string {
  const k = Buffer.from(key)
  if (!validCBCKeyLen(k.length)) {
    throw new InvalidKeyError(`crypt: CBC requires 16/24/32 bytes; got ${k.length}`)
  }

  const iv = randomBytes(CBC_BLOCK_SIZE)
  const cipher = createCipheriv(aesAlgoForKey(k.length), k, iv)
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext)
  // Node's CBC cipher applies PKCS7 padding by default when
  // setAutoPadding is left at default true.
  const ct1 = cipher.update(pt)
  const ct2 = cipher.final()
  const out = Buffer.concat([iv, ct1, ct2])
  return out.toString("hex")
}

/**
 * Reverses {@link encryptCbc}: hex-decodes, takes the IV from the
 * first 16 bytes, AES-CBC decrypts the rest, removes PKCS#7 padding.
 *
 * @deprecated Use open from "@ubgo/crypt". CBC cannot detect tampering.
 */
export function decryptCbc(key: Buffer | Uint8Array, ciphertext: string): Buffer {
  const k = Buffer.from(key)
  if (!validCBCKeyLen(k.length)) {
    throw new InvalidKeyError(`crypt: CBC requires 16/24/32 bytes; got ${k.length}`)
  }

  let raw: Buffer
  try {
    raw = Buffer.from(ciphertext, "hex")
  } catch (e) {
    throw new InvalidCiphertextError(`crypt: hex decode: ${(e as Error).message}`)
  }
  // Buffer.from("...", "hex") silently truncates on invalid chars.
  // Detect by checking that the input length is even and matches.
  if (ciphertext.length % 2 !== 0 || raw.length * 2 !== ciphertext.length) {
    throw new InvalidCiphertextError(`crypt: hex decode produced unexpected length`)
  }
  if (raw.length < CBC_BLOCK_SIZE) {
    throw new CiphertextTooShortError(
      `crypt: ciphertext must be >= ${CBC_BLOCK_SIZE} bytes; got ${raw.length}`,
    )
  }

  const iv = raw.subarray(0, CBC_BLOCK_SIZE)
  const body = raw.subarray(CBC_BLOCK_SIZE)
  if (body.length === 0 || body.length % CBC_BLOCK_SIZE !== 0) {
    throw new CiphertextNotBlockAlignedError(
      `crypt: ciphertext body length ${body.length} is not a multiple of ${CBC_BLOCK_SIZE}`,
    )
  }

  const decipher = createDecipheriv(aesAlgoForKey(k.length), k, iv)
  // Node will throw on bad padding by default. Convert to our error.
  try {
    const a = decipher.update(body)
    const b = decipher.final()
    return Buffer.concat([a, b])
  } catch (e) {
    throw new InvalidPaddingError(`crypt: ${(e as Error).message}`)
  }
}
