/**
 * Wire format constants shared between encoders and decoders.
 *
 * The AEAD output is a base64url-no-pad encoding of:
 *
 *   [version:1][nonce:12][ciphertext:N][tag:16]
 *
 * The version byte enables forward-compatibility: future algorithms
 * receive new version numbers, and decoders explicitly enumerate
 * which versions they understand.
 */

/** AES-256-GCM with 12-byte nonce and 16-byte tag. */
export const VERSION_AEAD_V1 = 0x01

/** Required key length for AEAD operations (AES-256). */
export const AEAD_KEY_SIZE = 32

/** GCM standard nonce length (96 bits). */
export const AEAD_NONCE_SIZE = 12

/** GCM authentication tag length (128 bits). */
export const AEAD_TAG_SIZE = 16

/** version byte + nonce */
export const AEAD_HEADER_SIZE = 1 + AEAD_NONCE_SIZE

/** smallest possible AEAD ciphertext: header + tag, for empty plaintext */
export const AEAD_MIN_SIZE = AEAD_HEADER_SIZE + AEAD_TAG_SIZE

/** Legacy AES-CBC IV size (128 bits). */
export const CBC_BLOCK_SIZE = 16
