/**
 * HMAC signing primitives. HMAC-SHA256 is the symmetric MAC of choice
 * for webhook signing, URL parameter integrity, and any case where
 * both signer and verifier hold the same secret key.
 */

import { createHmac, timingSafeEqual } from "node:crypto"
import { Buffer } from "node:buffer"

const SHA256_SIZE = 32

/**
 * Returns an HMAC-SHA256 tag computed over data with key.
 * Output is always 32 bytes.
 *
 * @example Sign a webhook
 * ```ts
 * const mac = sign(secret, body)
 * fetch(url, {
 *   method: "POST",
 *   headers: { "X-Signature": mac.toString("base64") },
 *   body,
 * })
 * ```
 */
export function sign(key: Buffer | Uint8Array, data: Buffer | Uint8Array): Buffer {
  const h = createHmac("sha256", Buffer.from(key))
  h.update(data instanceof Buffer ? data : Buffer.from(data))
  return h.digest()
}

/**
 * Constant-time check that mac is a valid HMAC-SHA256 of data under
 * key.
 *
 * Returns false (without throwing) if mac is the wrong length —
 * avoids forcing callers to wrap every Verify call in try/catch
 * for a malformed-input case that's rare and equivalent to a verify
 * failure anyway.
 *
 * @example Verify an incoming webhook
 * ```ts
 * const sig = Buffer.from(req.headers["x-signature"], "base64")
 * if (!verify(secret, body, sig)) {
 *   return res.status(401).end()
 * }
 * ```
 */
export function verify(
  key: Buffer | Uint8Array,
  data: Buffer | Uint8Array,
  mac: Buffer | Uint8Array,
): boolean {
  if (mac.length !== SHA256_SIZE) return false
  const expected = sign(key, data)
  return timingSafeEqual(expected, Buffer.from(mac))
}

/**
 * Reports whether a and b have equal contents in time independent
 * of contents.
 *
 * Use instead of `===` or naive byte comparison for any comparison
 * involving secret material. Naive comparison short-circuits at the
 * first mismatch and leaks timing information that can be used to
 * recover the secret one byte at a time.
 *
 * Returns false in constant time when inputs are equal-length-but-
 * different. Length check itself is not constant-time (Node's
 * timingSafeEqual throws on length mismatch).
 *
 * @example Compare an API key
 * ```ts
 * const provided = Buffer.from(req.headers["x-api-key"] ?? "")
 * if (!constantTimeEqual(provided, expected)) {
 *   return res.status(401).end()
 * }
 * ```
 */
export function constantTimeEqual(a: Buffer | Uint8Array, b: Buffer | Uint8Array): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a), Buffer.from(b))
}
