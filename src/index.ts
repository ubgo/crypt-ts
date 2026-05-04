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
export { sealChaCha20, openChaCha20 } from "./aead-chacha20.js"
export { encryptCbc, decryptCbc } from "./cbc.js"
export { openAuto } from "./auto.js"
export { randomBytes, randomToken, randomHex } from "./random.js"
export { sign, verify, constantTimeEqual } from "./sign.js"
export { deriveKey } from "./hkdf.js"
export { KeyRing } from "./keyring.js"
export { issueToken, verifyToken, ExpiredError } from "./timelock.js"
export {
  generateEd25519,
  signEd25519,
  verifyEd25519,
  generateKeyPair,
  sealAsymmetric,
  openAsymmetric,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  X25519_KEY_SIZE,
  InvalidSignatureError,
  type Ed25519KeyPair,
  type X25519KeyPair,
} from "./asymmetric.js"

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
