/**
 * KeyRing — graceful key rotation. Writes use the active key, reads
 * dispatch by the embedded kid (key id).
 *
 * Wire format (version 0x03):
 *
 *   [0x03][kid_len:1][kid:kid_len][nonce:12][ciphertext:N][tag:16]
 *
 * Old v1 ciphertexts (no kid) are also openable: KeyRing tries each
 * registered key in turn until one succeeds.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes as nodeRandom,
  type CipherGCM,
  type DecipherGCM,
} from "node:crypto"
import { Buffer } from "node:buffer"

import {
  AEAD_HEADER_SIZE,
  AEAD_KEY_SIZE,
  AEAD_MIN_SIZE,
  AEAD_NONCE_SIZE,
  AEAD_TAG_SIZE,
  VERSION_AEAD_V1,
} from "./format.js"
import {
  CiphertextTooShortError,
  InvalidCiphertextError,
  InvalidKeyError,
  TamperedError,
  UnsupportedVersionError,
} from "./errors.js"

const VERSION_AEAD_V3 = 0x03
const KID_MAX_LEN = 64

export class KeyRing {
  private active: string
  private readonly keys = new Map<string, Buffer>()

  constructor(activeKid: string, activeKey: Buffer | Uint8Array) {
    KeyRing.validateKid(activeKid)
    if (activeKey.length !== AEAD_KEY_SIZE) {
      throw new InvalidKeyError(
        `crypt: KeyRing requires ${AEAD_KEY_SIZE} bytes; got ${activeKey.length}`,
      )
    }
    this.active = activeKid
    this.keys.set(activeKid, Buffer.from(activeKey))
  }

  add(kid: string, key: Buffer | Uint8Array): void {
    KeyRing.validateKid(kid)
    if (this.keys.has(kid)) {
      throw new Error(`crypt: KeyRing already has kid ${JSON.stringify(kid)}`)
    }
    if (key.length !== AEAD_KEY_SIZE) {
      throw new InvalidKeyError(`crypt: KeyRing requires ${AEAD_KEY_SIZE} bytes; got ${key.length}`)
    }
    this.keys.set(kid, Buffer.from(key))
  }

  remove(kid: string): void {
    if (kid === this.active) {
      throw new Error(`crypt: cannot remove active kid ${JSON.stringify(kid)}`)
    }
    if (!this.keys.has(kid)) {
      throw new Error(`crypt: KeyRing has no kid ${JSON.stringify(kid)}`)
    }
    this.keys.delete(kid)
  }

  setActive(kid: string): void {
    if (!this.keys.has(kid)) {
      throw new Error(`crypt: KeyRing has no kid ${JSON.stringify(kid)}`)
    }
    this.active = kid
  }

  activeKid(): string {
    return this.active
  }

  seal(plaintext: string | Buffer | Uint8Array, aad?: Buffer | Uint8Array): string {
    const key = this.keys.get(this.active)!
    const nonce = nodeRandom(AEAD_NONCE_SIZE)
    const cipher = createCipheriv("aes-256-gcm", key, nonce) as CipherGCM
    if (aad !== undefined) cipher.setAAD(Buffer.from(aad))
    const pt =
      typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext)
    const ct1 = cipher.update(pt)
    const ct2 = cipher.final()
    const tag = cipher.getAuthTag()

    const kidBytes = Buffer.from(this.active, "utf8")
    return Buffer.concat([
      Buffer.from([VERSION_AEAD_V3, kidBytes.length]),
      kidBytes,
      nonce,
      ct1,
      ct2,
      tag,
    ]).toString("base64url")
  }

  open(ciphertext: string, aad?: Buffer | Uint8Array): Buffer {
    let raw: Buffer
    try {
      raw = Buffer.from(ciphertext, "base64url")
    } catch (e) {
      throw new InvalidCiphertextError(`crypt: base64url decode: ${(e as Error).message}`)
    }
    if (raw.length < AEAD_MIN_SIZE) {
      throw new CiphertextTooShortError(`crypt: ciphertext too short`)
    }

    if (raw[0] === VERSION_AEAD_V1) {
      // Try each key.
      for (const [, key] of [...this.keys.entries()].sort(([a], [b]) =>
        a === this.active ? -1 : b === this.active ? 1 : 0,
      )) {
        try {
          return openV1(key, raw, aad)
        } catch {
          // continue
        }
      }
      throw new TamperedError("crypt: no key in ring opens this v1 ciphertext")
    }

    if (raw[0] === VERSION_AEAD_V3) {
      if (raw.length < 2) throw new CiphertextTooShortError("crypt: ciphertext too short")
      const kidLen = raw[1]!
      if (kidLen < 1 || kidLen > KID_MAX_LEN) {
        throw new InvalidCiphertextError(`crypt: invalid kid length ${kidLen}`)
      }
      if (raw.length < 2 + kidLen + AEAD_NONCE_SIZE + AEAD_TAG_SIZE) {
        throw new CiphertextTooShortError(`crypt: ciphertext too short`)
      }
      const kid = raw.subarray(2, 2 + kidLen).toString("utf8")
      const key = this.keys.get(kid)
      if (!key) {
        throw new TamperedError(`crypt: no key for kid ${JSON.stringify(kid)} in ring`)
      }
      const nonce = raw.subarray(2 + kidLen, 2 + kidLen + AEAD_NONCE_SIZE)
      const tag = raw.subarray(raw.length - AEAD_TAG_SIZE)
      const body = raw.subarray(2 + kidLen + AEAD_NONCE_SIZE, raw.length - AEAD_TAG_SIZE)

      const decipher = createDecipheriv("aes-256-gcm", key, nonce) as DecipherGCM
      if (aad !== undefined) decipher.setAAD(Buffer.from(aad))
      decipher.setAuthTag(tag)
      try {
        return Buffer.concat([decipher.update(body), decipher.final()])
      } catch (e) {
        throw new TamperedError(`crypt: ${(e as Error).message}`)
      }
    }

    throw new UnsupportedVersionError(
      `crypt: unsupported ciphertext version 0x${raw[0]?.toString(16).padStart(2, "0")}`,
    )
  }

  private static validateKid(kid: string): void {
    if (kid.length === 0) {
      throw new Error("crypt: kid must be non-empty")
    }
    if (kid.length > KID_MAX_LEN) {
      throw new Error(`crypt: kid length ${kid.length} exceeds limit ${KID_MAX_LEN}`)
    }
  }
}

function openV1(key: Buffer, raw: Buffer, aad?: Buffer | Uint8Array): Buffer {
  const nonce = raw.subarray(1, AEAD_HEADER_SIZE)
  const tag = raw.subarray(raw.length - AEAD_TAG_SIZE)
  const body = raw.subarray(AEAD_HEADER_SIZE, raw.length - AEAD_TAG_SIZE)
  const decipher = createDecipheriv("aes-256-gcm", key, nonce) as DecipherGCM
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad))
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}
