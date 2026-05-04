/**
 * @ubgo/crypt — TypeScript counterpart to github.com/ubgo/crypt (Go).
 *
 * Same API surface (minus password hashing — server-side only),
 * byte-for-byte parity wire format. Anything sealed in Go opens here
 * and vice versa.
 *
 * Quick start:
 *
 *   import { seal, open, randomBytes, AEAD_KEY_SIZE } from "@ubgo/crypt"
 *
 *   const key = randomBytes(AEAD_KEY_SIZE)
 *   const ct = seal(key, "hello, world")
 *   const pt = open(key, ct).toString("utf8")
 */

export { seal, open, Sealer } from "./aead.js"
export { randomBytes, randomToken, randomHex } from "./random.js"
export { sign, verify, constantTimeEqual } from "./sign.js"

export { AEAD_KEY_SIZE, AEAD_NONCE_SIZE, AEAD_TAG_SIZE, VERSION_AEAD_V1 } from "./format.js"

export {
  CryptError,
  InvalidKeyError,
  TamperedError,
  UnsupportedVersionError,
  InvalidCiphertextError,
  CiphertextTooShortError,
  CiphertextNotBlockAlignedError,
  InvalidPaddingError,
  UnknownFormatError,
} from "./errors.js"
