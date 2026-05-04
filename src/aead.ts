/**
 * AEAD authenticated encryption using AES-256-GCM.
 *
 * Output of {@link seal} is base64url-no-pad encoding of the binary
 * layout:
 *
 *   [version:1=0x01][nonce:12][ciphertext:N][tag:16]
 *
 * Byte-for-byte parity with `github.com/ubgo/crypt` (Go).
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
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

function toBuffer(input: string | Buffer | Uint8Array): Buffer {
  if (typeof input === "string") return Buffer.from(input, "utf8")
  if (Buffer.isBuffer(input)) return input
  return Buffer.from(input)
}

/**
 * Encrypt plaintext under key with optional additional authenticated
 * data (AAD) and return the ciphertext as a base64url-no-pad string.
 *
 * The AAD is authenticated but not encrypted: it can be any context-
 * binding data (e.g., user ID, tenant ID, message type) that callers
 * also pass to {@link open}. If aad differs at decrypt time, the
 * call fails with {@link TamperedError}.
 *
 * @param key 32-byte key. Throws {@link InvalidKeyError} on wrong length.
 * @param plaintext String (utf8) or Buffer/Uint8Array.
 * @param aad Optional additional authenticated data.
 * @returns base64url-no-pad encoded ciphertext.
 *
 * @example Basic encrypt
 * ```ts
 * import { seal, open, randomBytes, AEAD_KEY_SIZE } from "@ubgo/crypt"
 * const key = randomBytes(AEAD_KEY_SIZE)
 * const ct = seal(key, "hello, world")
 * const pt = open(key, ct).toString("utf8")
 * ```
 *
 * @example Bind ciphertext to a context with AAD
 * ```ts
 * const ct = seal(key, payload, Buffer.from(`user:${userID}`))
 * const pt = open(key, ct, Buffer.from(`user:${userID}`))
 * // open() with a different userID throws TamperedError
 * ```
 */
export function seal(
  key: Buffer | Uint8Array,
  plaintext: string | Buffer | Uint8Array,
  aad?: Buffer | Uint8Array,
): string {
  return sealWithNonce(key, plaintext, aad, undefined)
}

/**
 * Decrypt and authenticate a base64url-no-pad ciphertext produced by
 * {@link seal} (or `crypt.Seal` in Go) under the same key and aad.
 *
 * @param key 32-byte key.
 * @param ciphertext base64url-no-pad output of seal().
 * @param aad Must match the AAD used at seal-time.
 * @returns Plaintext bytes. Caller decodes utf8 if needed.
 *
 * @example
 * ```ts
 * try {
 *   const pt = open(key, ciphertext)
 *   processPayload(pt.toString("utf8"))
 * } catch (e) {
 *   // TamperedError, UnsupportedVersionError, InvalidKeyError, etc.
 *   logger.warn("decrypt failed", e)
 * }
 * ```
 */
export function open(
  key: Buffer | Uint8Array,
  ciphertext: string,
  aad?: Buffer | Uint8Array,
): Buffer {
  const k = Buffer.from(key)
  if (k.length !== AEAD_KEY_SIZE) {
    throw new InvalidKeyError(`crypt: AEAD requires ${AEAD_KEY_SIZE} bytes; got ${k.length}`)
  }

  let raw: Buffer
  try {
    raw = Buffer.from(ciphertext, "base64url")
  } catch (e) {
    throw new InvalidCiphertextError(`crypt: base64url decode: ${(e as Error).message}`)
  }
  // Buffer.from doesn't throw on non-base64; it silently produces a
  // shorter buffer. Detect by re-encoding and comparing length-likely.
  // Easier: just check minimum length.
  if (raw.length < AEAD_MIN_SIZE) {
    throw new CiphertextTooShortError(
      `crypt: ciphertext must be >= ${AEAD_MIN_SIZE} bytes; got ${raw.length}`,
    )
  }
  if (raw[0] !== VERSION_AEAD_V1) {
    throw new UnsupportedVersionError(
      `crypt: unsupported ciphertext version 0x${raw[0]?.toString(16).padStart(2, "0")}`,
    )
  }

  const nonce = raw.subarray(1, AEAD_HEADER_SIZE)
  const tag = raw.subarray(raw.length - AEAD_TAG_SIZE)
  const body = raw.subarray(AEAD_HEADER_SIZE, raw.length - AEAD_TAG_SIZE)

  const decipher = createDecipheriv("aes-256-gcm", k, nonce) as DecipherGCM
  if (aad !== undefined) {
    decipher.setAAD(Buffer.from(aad))
  }
  decipher.setAuthTag(tag)

  try {
    const a = decipher.update(body)
    const b = decipher.final()
    return Buffer.concat([a, b])
  } catch (e) {
    throw new TamperedError(`crypt: ciphertext authentication failed: ${(e as Error).message}`)
  }
}

/**
 * Internal test-injectable form. When nonce is undefined, a fresh
 * random nonce is generated; when provided, it must be exactly 12
 * bytes. Used by deterministic test vectors. Must not be exposed to
 * callers — reusing a nonce with the same key catastrophically breaks
 * GCM.
 *
 * @internal
 */
export function sealWithNonce(
  key: Buffer | Uint8Array,
  plaintext: string | Buffer | Uint8Array,
  aad: Buffer | Uint8Array | undefined,
  nonce: Buffer | Uint8Array | undefined,
): string {
  const k = Buffer.from(key)
  if (k.length !== AEAD_KEY_SIZE) {
    throw new InvalidKeyError(`crypt: AEAD requires ${AEAD_KEY_SIZE} bytes; got ${k.length}`)
  }

  const nonceBuf = nonce === undefined ? randomBytes(AEAD_NONCE_SIZE) : Buffer.from(nonce)
  if (nonceBuf.length !== AEAD_NONCE_SIZE) {
    throw new InvalidKeyError(
      `crypt: nonce must be ${AEAD_NONCE_SIZE} bytes; got ${nonceBuf.length}`,
    )
  }

  const cipher = createCipheriv("aes-256-gcm", k, nonceBuf) as CipherGCM
  if (aad !== undefined) {
    cipher.setAAD(Buffer.from(aad))
  }
  const pt = toBuffer(plaintext)
  const ct1 = cipher.update(pt)
  const ct2 = cipher.final()
  const tag = cipher.getAuthTag()

  const out = Buffer.concat([Buffer.from([VERSION_AEAD_V1]), nonceBuf, ct1, ct2, tag])
  return out.toString("base64url")
}

/**
 * Sealer holds a pre-validated AEAD key and reusable cipher state.
 *
 * Prefer Sealer over the package-level {@link seal}/{@link open}
 * when:
 *   - Encrypting many times with the same key (avoids re-validating
 *     the key on every call).
 *   - Injecting as a service dependency for testing.
 *   - Binding the key into a long-lived component.
 *
 * @example
 * ```ts
 * import { Sealer } from "@ubgo/crypt"
 *
 * // At application boot:
 * const sealer = new Sealer(loadAppKey())
 *
 * // Anywhere in the app:
 * const ct = sealer.seal(plaintext)
 * const pt = sealer.open(ct)
 * ```
 */
export class Sealer {
  readonly #key: Buffer

  constructor(key: Buffer | Uint8Array) {
    const k = Buffer.from(key)
    if (k.length !== AEAD_KEY_SIZE) {
      throw new InvalidKeyError(`crypt: AEAD requires ${AEAD_KEY_SIZE} bytes; got ${k.length}`)
    }
    this.#key = k
  }

  seal(plaintext: string | Buffer | Uint8Array, aad?: Buffer | Uint8Array): string {
    return seal(this.#key, plaintext, aad)
  }

  open(ciphertext: string, aad?: Buffer | Uint8Array): Buffer {
    return open(this.#key, ciphertext, aad)
  }
}
