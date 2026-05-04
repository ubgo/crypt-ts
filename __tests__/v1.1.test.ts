import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"

import {
  AEAD_KEY_SIZE,
  InvalidKeyError,
  KeyRing,
  TamperedError,
  UnsupportedVersionError,
  deriveKey,
  open,
  openChaCha20,
  seal,
  sealChaCha20,
} from "../src/index.js"

// ----- HKDF -----

describe("deriveKey", () => {
  const master = Buffer.alloc(32, 0x42)

  it("different info → different keys", () => {
    const a = deriveKey(master, undefined, Buffer.from("tenant:acme"), 32)
    const b = deriveKey(master, undefined, Buffer.from("tenant:globex"), 32)
    expect(a.equals(b)).toBe(false)
  })

  it("same inputs → deterministic", () => {
    const a = deriveKey(master, undefined, Buffer.from("info"), 32)
    const b = deriveKey(master, undefined, Buffer.from("info"), 32)
    expect(a.equals(b)).toBe(true)
  })

  it.each([16, 24, 32, 64])("respects length %i", (n) => {
    const k = deriveKey(master, undefined, Buffer.from("info"), n)
    expect(k.length).toBe(n)
  })

  it("rejects invalid", () => {
    expect(() => deriveKey(Buffer.alloc(0), undefined, Buffer.from("x"), 32)).toThrow()
    expect(() => deriveKey(master, undefined, Buffer.from("x"), 0)).toThrow(RangeError)
    expect(() => deriveKey(master, undefined, Buffer.from("x"), -1)).toThrow(RangeError)
  })

  it("derived key works as AEAD key", () => {
    const k = deriveKey(master, undefined, Buffer.from("aead-v1"), AEAD_KEY_SIZE)
    const ct = seal(k, "hello")
    expect(open(k, ct).toString("utf8")).toBe("hello")
  })

  it("salt matters", () => {
    const a = deriveKey(master, Buffer.from("salt-a"), Buffer.from("info"), 32)
    const b = deriveKey(master, Buffer.from("salt-b"), Buffer.from("info"), 32)
    expect(a.equals(b)).toBe(false)
  })
})

// ----- ChaCha20-Poly1305 -----

describe("ChaCha20-Poly1305", () => {
  const key = Buffer.alloc(32, 0x77)

  it("round-trips", () => {
    const ct = sealChaCha20(key, "hello")
    expect(openChaCha20(key, ct).toString("utf8")).toBe("hello")
  })

  it("AAD is bound", () => {
    const ct = sealChaCha20(key, "hi", Buffer.from("ctx-1"))
    expect(() => openChaCha20(key, ct, Buffer.from("ctx-2"))).toThrow(TamperedError)
  })

  it("rejects v1 (AES-GCM) ciphertext", () => {
    const ct = seal(key, "hi") // v1
    expect(() => openChaCha20(key, ct)).toThrow(UnsupportedVersionError)
  })

  it("AES open rejects v2 (chacha) ciphertext", () => {
    const ct = sealChaCha20(key, "hi") // v2
    expect(() => open(key, ct)).toThrow(UnsupportedVersionError)
  })

  it("rejects invalid key length", () => {
    expect(() => sealChaCha20(Buffer.alloc(16), "x")).toThrow(InvalidKeyError)
  })
})

// ----- KeyRing -----

describe("KeyRing", () => {
  const k1 = Buffer.alloc(32, 0x01)
  const k2 = Buffer.alloc(32, 0x02)

  it("round-trips", () => {
    const r = new KeyRing("v1", k1)
    const ct = r.seal("hello", Buffer.from("ctx"))
    expect(r.open(ct, Buffer.from("ctx")).toString("utf8")).toBe("hello")
  })

  it("rotation: read old + write new", () => {
    const r = new KeyRing("2025", k1)
    const oldCT = r.seal("encrypted in 2025")

    r.add("2026", k2)
    r.setActive("2026")

    const newCT = r.seal("encrypted in 2026")

    expect(r.open(oldCT).toString("utf8")).toBe("encrypted in 2025")
    expect(r.open(newCT).toString("utf8")).toBe("encrypted in 2026")
  })

  it("activeKid reports correctly", () => {
    const r = new KeyRing("v1", k1)
    expect(r.activeKid()).toBe("v1")
    r.add("v2", k2)
    r.setActive("v2")
    expect(r.activeKid()).toBe("v2")
  })

  it("rejects duplicate add", () => {
    const r = new KeyRing("v1", k1)
    expect(() => r.add("v1", k2)).toThrow()
  })

  it("rejects bad key length", () => {
    const r = new KeyRing("v1", k1)
    expect(() => r.add("v2", Buffer.alloc(16))).toThrow(InvalidKeyError)
  })

  it("rejects empty kid", () => {
    expect(() => new KeyRing("", k1)).toThrow()
  })

  it("rejects too-long kid", () => {
    expect(() => new KeyRing("x".repeat(65), k1)).toThrow()
  })

  it("rejects removing active", () => {
    const r = new KeyRing("v1", k1)
    expect(() => r.remove("v1")).toThrow()
  })

  it("rejects unknown kid in setActive", () => {
    const r = new KeyRing("v1", k1)
    expect(() => r.setActive("nonexistent")).toThrow()
  })

  it("opens v1 ciphertext when active key matches", () => {
    const ct = seal(k1, "v1 data")
    const r = new KeyRing("active", k1)
    expect(r.open(ct).toString("utf8")).toBe("v1 data")
  })

  it("rejects unknown kid", () => {
    const r1 = new KeyRing("v1", k1)
    const ct = r1.seal("hello")
    const r2 = new KeyRing("v2", k2)
    expect(() => r2.open(ct)).toThrow(TamperedError)
  })
})
