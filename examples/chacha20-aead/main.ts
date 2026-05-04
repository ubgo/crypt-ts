/**
 * ChaCha20-Poly1305 AEAD — alternative to AES-256-GCM.
 *
 * Use on hardware without AES-NI (older ARM, embedded). Otherwise
 * prefer seal (AES-256-GCM).
 *
 * Wire format version 0x02 — cross-language parity with the Go
 * counterpart's SealChaCha20 / OpenChaCha20.
 */

import {
  AEAD_KEY_SIZE,
  open,
  openChaCha20,
  sealChaCha20,
  UnsupportedVersionError,
} from "@ubgo/crypt"
import { randomBytes } from "node:crypto"

const key = randomBytes(AEAD_KEY_SIZE)

const ct = sealChaCha20(key, "hello via chacha20", Buffer.from("ctx"))
console.log(`ciphertext (v2): ${ct}`)

const pt = openChaCha20(key, ct, Buffer.from("ctx"))
console.log(`decrypted: ${pt.toString("utf8")}`)

// AES open rejects v2.
try {
  open(key, ct, Buffer.from("ctx"))
} catch (e) {
  if (e instanceof UnsupportedVersionError) {
    console.log(`\nAES open on v2: ${e.message} (correctly rejected)`)
  } else {
    throw e
  }
}

// Tamper detection.
const tampered = ct.slice(0, -2) + "XX"
try {
  openChaCha20(key, tampered, Buffer.from("ctx"))
} catch (e) {
  console.log(`tamper detected: ${(e as Error).message}`)
}
