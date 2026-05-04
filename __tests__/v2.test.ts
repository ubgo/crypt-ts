import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"

import {
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  InvalidCiphertextError,
  InvalidKeyError,
  InvalidSignatureError,
  TamperedError,
  X25519_KEY_SIZE,
  generateEd25519,
  generateKeyPair,
  openAsymmetric,
  sealAsymmetric,
  signEd25519,
  verifyEd25519,
} from "../src/index.js"

// ----- Ed25519 -----

describe("Ed25519", () => {
  it("generates correct-size keys", () => {
    const { publicKey, privateKey } = generateEd25519()
    expect(publicKey.length).toBe(ED25519_PUBLIC_KEY_SIZE)
    expect(privateKey.length).toBe(32) // raw seed
  })

  it("round-trips sign + verify", () => {
    const { publicKey, privateKey } = generateEd25519()
    const sig = signEd25519(privateKey, Buffer.from("the message"))
    expect(sig.length).toBe(ED25519_SIGNATURE_SIZE)
    expect(verifyEd25519(publicKey, Buffer.from("the message"), sig)).toBe(true)
  })

  it("rejects tampered data", () => {
    const { publicKey, privateKey } = generateEd25519()
    const sig = signEd25519(privateKey, Buffer.from("original"))
    expect(verifyEd25519(publicKey, Buffer.from("tampered"), sig)).toBe(false)
  })

  it("rejects tampered signature", () => {
    const { publicKey, privateKey } = generateEd25519()
    const sig = signEd25519(privateKey, Buffer.from("data"))
    sig[0]! ^= 0x01
    expect(verifyEd25519(publicKey, Buffer.from("data"), sig)).toBe(false)
  })

  it("rejects wrong key sizes", () => {
    expect(() => signEd25519(Buffer.alloc(16), Buffer.from("x"))).toThrow(InvalidKeyError)
    expect(() => verifyEd25519(Buffer.alloc(16), Buffer.from("x"), Buffer.alloc(64))).toThrow(
      InvalidKeyError,
    )
  })

  it("rejects wrong signature size", () => {
    const { publicKey } = generateEd25519()
    expect(() => verifyEd25519(publicKey, Buffer.from("x"), Buffer.alloc(32))).toThrow(
      InvalidSignatureError,
    )
  })
})

// ----- Asymmetric encrypt -----

describe("X25519 + ChaCha20-Poly1305 sealed-box", () => {
  it("generates correct-size keypair", () => {
    const { publicKey, privateKey } = generateKeyPair()
    expect(publicKey.length).toBe(X25519_KEY_SIZE)
    expect(privateKey.length).toBe(X25519_KEY_SIZE)
  })

  it("round-trips", () => {
    const { publicKey, privateKey } = generateKeyPair()
    const ct = sealAsymmetric(publicKey, "hello, world")
    expect(openAsymmetric(privateKey, ct).toString("utf8")).toBe("hello, world")
  })

  it("different ciphertext each call", () => {
    const { publicKey } = generateKeyPair()
    const a = sealAsymmetric(publicKey, "hello")
    const b = sealAsymmetric(publicKey, "hello")
    expect(a).not.toEqual(b)
  })

  it("rejects wrong recipient key", () => {
    const { publicKey } = generateKeyPair()
    const { privateKey: otherPriv } = generateKeyPair()
    const ct = sealAsymmetric(publicKey, "hello")
    expect(() => openAsymmetric(otherPriv, ct)).toThrow(TamperedError)
  })

  it("rejects bad key length", () => {
    expect(() => sealAsymmetric(Buffer.alloc(16), "x")).toThrow(InvalidKeyError)
    expect(() => openAsymmetric(Buffer.alloc(16), "x")).toThrow(InvalidKeyError)
  })

  it("rejects bad ciphertext", () => {
    const { privateKey } = generateKeyPair()
    // Node's Buffer.from(s, "base64url") silently returns short bytes
    // for unparseable input, so we hit CiphertextTooShortError, not
    // InvalidCiphertextError. Either is acceptable as "rejected".
    expect(() => openAsymmetric(privateKey, "***")).toThrow()
  })

  it("rejects tampered ciphertext", () => {
    const { publicKey, privateKey } = generateKeyPair()
    const ct = sealAsymmetric(publicKey, "hello")
    const tampered = ct.slice(0, -2) + "XX"
    expect(() => openAsymmetric(privateKey, tampered)).toThrow()
  })
})
