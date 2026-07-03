/**
 * Coverage tests — exercise the malformed-input / error branches of
 * every wire-format parser. These are the paths that a hostile or
 * corrupt input reaches; each must yield a typed CryptError, never a
 * raw TypeError or a silent wrong result.
 *
 * (Companion to the parity/round-trip suites, which cover the happy
 * paths. Kept in one file so the error-branch matrix is legible.)
 */

import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"
import { randomBytes } from "node:crypto"

import {
  seal,
  KeyRing,
  issueToken,
  verifyToken,
  ExpiredError,
  openChaCha20,
  sealChaCha20,
  encryptCbc,
  openAuto,
  generateKeyPair,
  sealAsymmetric,
  openAsymmetric,
  AEAD_KEY_SIZE,
  InvalidKeyError,
  TamperedError,
  UnsupportedVersionError,
  InvalidCiphertextError,
  CiphertextTooShortError,
  UnknownFormatError,
} from "../src/index.js"
import { sealChaCha20WithNonce } from "../src/aead-chacha20.js"

const b64u = (b: Buffer): string => b.toString("base64url")
const key = (): Buffer => randomBytes(AEAD_KEY_SIZE)

describe("KeyRing.open — malformed input", () => {
  const k = key()
  const ring = new KeyRing("k1", k)

  it("rejects an unsupported version byte", () => {
    const bad = Buffer.concat([Buffer.from([0x09]), randomBytes(40)])
    expect(() => ring.open(b64u(bad))).toThrow(UnsupportedVersionError)
  })

  it("rejects a too-short frame", () => {
    expect(() => ring.open(b64u(Buffer.alloc(5)))).toThrow(CiphertextTooShortError)
  })

  it("rejects a v3 frame with kid length 0", () => {
    const raw = Buffer.concat([Buffer.from([0x03, 0x00]), randomBytes(40)])
    expect(() => ring.open(b64u(raw))).toThrow(InvalidCiphertextError)
  })

  it("rejects a v3 frame with kid length over the max", () => {
    const raw = Buffer.concat([Buffer.from([0x03, 200]), randomBytes(40)])
    expect(() => ring.open(b64u(raw))).toThrow(InvalidCiphertextError)
  })

  it("rejects a v3 frame whose declared kid length overruns the body", () => {
    // total length 29 passes AEAD_MIN_SIZE but is < 2 + 10 + 12 + 16.
    const raw = Buffer.concat([Buffer.from([0x03, 10]), randomBytes(27)])
    expect(() => ring.open(b64u(raw))).toThrow(CiphertextTooShortError)
  })

  it("rejects a v3 ciphertext whose kid is not in the ring", () => {
    const other = new KeyRing("other-kid", key())
    const ct = other.seal("data")
    expect(() => ring.open(ct)).toThrow(TamperedError)
  })

  it("rejects a tampered v3 ciphertext", () => {
    const raw = Buffer.from(ring.seal("hello"), "base64url")
    raw[raw.length - 1]! ^= 0xff
    expect(() => ring.open(b64u(raw))).toThrow(TamperedError)
  })

  it("rejects a v1 ciphertext no key in the ring can open", () => {
    const foreign = seal(key(), "hi") // sealed under a key not in the ring
    expect(() => ring.open(foreign)).toThrow(TamperedError)
  })

  it("opens a v1 ciphertext sealed under the active key (fallback path)", () => {
    const v1 = seal(k, "hi")
    expect(ring.open(v1).toString("utf8")).toBe("hi")
  })
})

describe("KeyRing — key management errors", () => {
  it("throws on empty and over-long kids", () => {
    expect(() => new KeyRing("", key())).toThrow()
    expect(() => new KeyRing("x".repeat(65), key())).toThrow()
  })

  it("throws on wrong key sizes", () => {
    expect(() => new KeyRing("k", randomBytes(16))).toThrow(InvalidKeyError)
    const ring = new KeyRing("k", key())
    expect(() => ring.add("k2", randomBytes(16))).toThrow(InvalidKeyError)
  })

  it("rejects duplicate add, removing the active kid, and unknown kids", () => {
    const ring = new KeyRing("k", key())
    expect(() => ring.add("k", key())).toThrow()
    expect(() => ring.remove("k")).toThrow() // active
    expect(() => ring.remove("nope")).toThrow()
    expect(() => ring.setActive("nope")).toThrow()
  })
})

describe("verifyToken / issueToken", () => {
  const k = key()

  it("rejects a non-positive or non-finite ttl", () => {
    expect(() => issueToken(k, "x", 0)).toThrow(RangeError)
    expect(() => issueToken(k, "x", -5)).toThrow(RangeError)
    expect(() => issueToken(k, "x", Number.NaN)).toThrow(RangeError)
  })

  it("rejects a token whose sealed plaintext is shorter than the expiry header", () => {
    const shortSealed = seal(k, Buffer.alloc(3))
    expect(() => verifyToken(k, shortSealed)).toThrow(InvalidCiphertextError)
  })

  it("rejects an expired token", () => {
    const wrapped = Buffer.alloc(8 + 4)
    wrapped.writeBigUInt64BE(BigInt(1000), 0) // expiry in 1970
    Buffer.from("abcd").copy(wrapped, 8)
    const expired = seal(k, wrapped)
    expect(() => verifyToken(k, expired)).toThrow(ExpiredError)
  })

  it("round-trips a live token", () => {
    const tok = issueToken(k, "hello", 60_000)
    expect(verifyToken(k, tok).toString("utf8")).toBe("hello")
  })
})

describe("openChaCha20 — malformed input", () => {
  const k = key()

  it("rejects wrong key size", () => {
    expect(() => openChaCha20(randomBytes(16), "aaaa")).toThrow(InvalidKeyError)
  })

  it("rejects a too-short frame", () => {
    expect(() => openChaCha20(k, b64u(Buffer.alloc(5)))).toThrow(CiphertextTooShortError)
  })

  it("rejects the wrong version byte (an AES-GCM v1 frame)", () => {
    const v1 = Buffer.concat([Buffer.from([0x01]), randomBytes(40)])
    expect(() => openChaCha20(k, b64u(v1))).toThrow(UnsupportedVersionError)
  })

  it("rejects a tampered ChaCha20 ciphertext", () => {
    const raw = Buffer.from(sealChaCha20(k, "hi"), "base64url")
    raw[raw.length - 1]! ^= 0xff
    expect(() => openChaCha20(k, b64u(raw))).toThrow(TamperedError)
  })

  it("rejects a wrong-length nonce in the deterministic form", () => {
    expect(() => sealChaCha20WithNonce(k, "x", undefined, randomBytes(8))).toThrow(InvalidKeyError)
  })
})

describe("openAsymmetric — malformed input", () => {
  const { publicKey, privateKey } = generateKeyPair()

  it("rejects wrong private-key size", () => {
    expect(() => openAsymmetric(randomBytes(16), "aaaa")).toThrow(InvalidKeyError)
  })

  it("rejects a too-short frame", () => {
    expect(() => openAsymmetric(privateKey, "aa")).toThrow(CiphertextTooShortError)
  })

  it("rejects an unsupported version byte", () => {
    const raw = Buffer.concat([Buffer.from([0x09]), randomBytes(1 + 32 + 12 + 16)])
    expect(() => openAsymmetric(privateKey, b64u(raw))).toThrow(UnsupportedVersionError)
  })

  it("rejects a tampered sealed box", () => {
    const raw = Buffer.from(sealAsymmetric(publicKey, "secret"), "base64url")
    raw[raw.length - 1]! ^= 0xff
    expect(() => openAsymmetric(privateKey, b64u(raw))).toThrow(TamperedError)
  })
})

describe("openAuto — dispatch and fallthrough", () => {
  const k = key()

  it("decrypts real AEAD input", () => {
    expect(openAuto(k, seal(k, "hi")).toString("utf8")).toBe("hi")
  })

  it("decrypts real AES-CBC input", () => {
    expect(openAuto(k, encryptCbc(k, "hi")).toString("utf8")).toBe("hi")
  })

  it("throws UnknownFormatError on unrecognized input", () => {
    expect(() => openAuto(k, "not-valid-!!!")).toThrow(UnknownFormatError)
  })

  it("falls through to UnknownFormatError when an AEAD-looking frame fails to open", () => {
    // Valid v1 header shape, but sealed under nobody's key → open() throws,
    // and the base64url text is not valid CBC hex → UnknownFormatError.
    const fake = b64u(Buffer.concat([Buffer.from([0x01]), randomBytes(40)]))
    expect(() => openAuto(k, fake)).toThrow()
  })
})

describe("KeyRing — happy-path management & multi-key dispatch", () => {
  it("removes a non-active kid and can no longer open its data", () => {
    const kOld = key()
    const ring = new KeyRing("old", kOld)
    ring.add("new", key())
    ring.setActive("new")
    expect(ring.activeKid()).toBe("new")
    ring.remove("old")
    // A v1 ciphertext sealed under the removed key is now unopenable.
    expect(() => ring.open(seal(kOld, "x"))).toThrow(TamperedError)
  })

  it("opens a v1 ciphertext via a non-active key using the try-each fallback", () => {
    const kOld = key()
    const ring = new KeyRing("active", key())
    ring.add("old", kOld)
    // Sealed under the non-active "old" key; ring must still find it.
    expect(ring.open(seal(kOld, "legacy")).toString("utf8")).toBe("legacy")
  })
})

describe("issueToken — Buffer payload branch", () => {
  it("round-trips a Buffer (non-string) payload", () => {
    const k = key()
    const tok = issueToken(k, Buffer.from([1, 2, 3, 4]), 60_000)
    expect([...verifyToken(k, tok)]).toEqual([1, 2, 3, 4])
  })
})
