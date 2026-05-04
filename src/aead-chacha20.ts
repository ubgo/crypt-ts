/**
 * ChaCha20-Poly1305 AEAD (version 0x02) — alternative to AES-256-GCM
 * for hardware without AES-NI. Wire format: same as v1 but with
 * version byte 0x02.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes as nodeRandom,
  type CipherGCM,
  type DecipherGCM,
} from "node:crypto"
import { Buffer } from "node:buffer"

import { AEAD_HEADER_SIZE, AEAD_KEY_SIZE, AEAD_MIN_SIZE, AEAD_NONCE_SIZE } from "./format.js"
import {
  CiphertextTooShortError,
  InvalidCiphertextError,
  InvalidKeyError,
  TamperedError,
  UnsupportedVersionError,
} from "./errors.js"

const VERSION_V2 = 0x02

/**
 * Encrypt under a 32-byte ChaCha20-Poly1305 key.
 */
export function sealChaCha20(
  key: Buffer | Uint8Array,
  plaintext: string | Buffer | Uint8Array,
  aad?: Buffer | Uint8Array,
): string {
  return sealChaCha20WithNonce(key, plaintext, aad, undefined)
}

export function openChaCha20(
  key: Buffer | Uint8Array,
  ciphertext: string,
  aad?: Buffer | Uint8Array,
): Buffer {
  const k = Buffer.from(key)
  if (k.length !== AEAD_KEY_SIZE) {
    throw new InvalidKeyError(`crypt: ChaCha20 requires ${AEAD_KEY_SIZE} bytes; got ${k.length}`)
  }
  let raw: Buffer
  try {
    raw = Buffer.from(ciphertext, "base64url")
  } catch (e) {
    throw new InvalidCiphertextError(`crypt: base64url decode: ${(e as Error).message}`)
  }
  if (raw.length < AEAD_MIN_SIZE) {
    throw new CiphertextTooShortError(`crypt: ciphertext must be >= ${AEAD_MIN_SIZE} bytes`)
  }
  if (raw[0] !== VERSION_V2) {
    throw new UnsupportedVersionError(
      `crypt: unsupported ciphertext version 0x${raw[0]?.toString(16).padStart(2, "0")}`,
    )
  }

  const nonce = raw.subarray(1, AEAD_HEADER_SIZE)
  const tag = raw.subarray(raw.length - 16)
  const body = raw.subarray(AEAD_HEADER_SIZE, raw.length - 16)

  const decipher = createDecipheriv("chacha20-poly1305", k, nonce, {
    authTagLength: 16,
  }) as DecipherGCM
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad))
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch (e) {
    throw new TamperedError(`crypt: ciphertext authentication failed: ${(e as Error).message}`)
  }
}

/**
 * @internal Test-only deterministic nonce form.
 */
export function sealChaCha20WithNonce(
  key: Buffer | Uint8Array,
  plaintext: string | Buffer | Uint8Array,
  aad: Buffer | Uint8Array | undefined,
  nonce: Buffer | Uint8Array | undefined,
): string {
  const k = Buffer.from(key)
  if (k.length !== AEAD_KEY_SIZE) {
    throw new InvalidKeyError(`crypt: ChaCha20 requires ${AEAD_KEY_SIZE} bytes; got ${k.length}`)
  }
  const nonceBuf =
    nonce === undefined ? Buffer.from(nodeRandom(AEAD_NONCE_SIZE)) : Buffer.from(nonce)
  if (nonceBuf.length !== AEAD_NONCE_SIZE) {
    throw new InvalidKeyError(
      `crypt: nonce must be ${AEAD_NONCE_SIZE} bytes; got ${nonceBuf.length}`,
    )
  }

  const cipher = createCipheriv("chacha20-poly1305", k, nonceBuf, {
    authTagLength: 16,
  }) as CipherGCM
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad))
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext)
  const ct1 = cipher.update(pt)
  const ct2 = cipher.final()
  const tag = cipher.getAuthTag()

  return Buffer.concat([Buffer.from([VERSION_V2]), nonceBuf, ct1, ct2, tag]).toString("base64url")
}
