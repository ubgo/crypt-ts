/**
 * Error classes thrown by the package. All extend CryptError so a
 * single `instanceof CryptError` catch handles every package-level
 * failure.
 */

export class CryptError extends Error {
  override readonly name: string = "CryptError"
}

/** Thrown when a key has the wrong length for the requested operation. */
export class InvalidKeyError extends CryptError {
  override readonly name = "InvalidKeyError"
}

/** Thrown when GCM authentication fails (tampered, wrong key, or wrong AAD). */
export class TamperedError extends CryptError {
  override readonly name = "TamperedError"
}

/** Thrown when the ciphertext version byte is unknown. */
export class UnsupportedVersionError extends CryptError {
  override readonly name = "UnsupportedVersionError"
}

/** Thrown when ciphertext encoding (base64url, hex) is malformed. */
export class InvalidCiphertextError extends CryptError {
  override readonly name = "InvalidCiphertextError"
}

/** Thrown when ciphertext is shorter than the minimum required. */
export class CiphertextTooShortError extends CryptError {
  override readonly name = "CiphertextTooShortError"
}

/** Thrown when CBC ciphertext (excluding IV) is not a multiple of 16. */
export class CiphertextNotBlockAlignedError extends CryptError {
  override readonly name = "CiphertextNotBlockAlignedError"
}

/** Thrown when PKCS#7 padding cannot be removed. */
export class InvalidPaddingError extends CryptError {
  override readonly name = "InvalidPaddingError"
}

/** Thrown by openAuto when format detection fails. */
export class UnknownFormatError extends CryptError {
  override readonly name = "UnknownFormatError"
}
