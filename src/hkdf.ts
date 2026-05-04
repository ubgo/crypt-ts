/**
 * HKDF-SHA256 key derivation. Use to derive sub-keys from a single
 * master key with a context-binding `info` parameter.
 *
 * Use cases:
 *   - Per-tenant sub-keys (info = `tenant:${tenantID}`)
 *   - Per-purpose sub-keys (`aead-v1`, `mac-v1`) from a single master
 *
 * HKDF assumes a high-entropy input key. Do NOT use it on user
 * passwords — use server-side argon2id (Go counterpart's
 * HashPassword) instead.
 */

import { hkdfSync } from "node:crypto"
import { Buffer } from "node:buffer"

/**
 * Derive a length-byte key from masterKey using HKDF-SHA256.
 *
 * @example Per-tenant key
 * ```ts
 * const tenantKey = deriveKey(rootKey, undefined, Buffer.from(`tenant:${tid}`), AEAD_KEY_SIZE)
 * const sealer = new Sealer(tenantKey)
 * ```
 */
export function deriveKey(
  masterKey: Buffer | Uint8Array,
  salt: Buffer | Uint8Array | undefined,
  info: Buffer | Uint8Array,
  length: number,
): Buffer {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError(`crypt: deriveKey length must be a positive integer; got ${length}`)
  }
  if (masterKey.length === 0) {
    throw new Error("crypt: deriveKey masterKey must be non-empty")
  }
  const out = hkdfSync(
    "sha256",
    Buffer.from(masterKey),
    salt ? Buffer.from(salt) : Buffer.alloc(0),
    Buffer.from(info),
    length,
  )
  return Buffer.from(out)
}
