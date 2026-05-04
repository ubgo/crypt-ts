import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"
import { randomBytes } from "node:crypto"

import {
  open,
  seal,
  Sealer,
  AEAD_KEY_SIZE,
  InvalidKeyError,
  TamperedError,
  CiphertextTooShortError,
  UnsupportedVersionError,
} from "../src/index.js"

describe("seal / open", () => {
  const key = randomBytes(AEAD_KEY_SIZE)

  it.each([
    ["empty plaintext", Buffer.alloc(0)],
    ["short ASCII", Buffer.from("hello, world")],
    ["10 KiB", Buffer.alloc(10_000, 0x42)],
    ["binary", Buffer.from([0x00, 0xff, 0x10, 0x20, 0x30])],
  ])("round-trips %s", (_name, plaintext) => {
    const ct = seal(key, plaintext)
    const pt = open(key, ct)
    expect(pt.equals(plaintext)).toBe(true)
  })

  it("round-trips with AAD", () => {
    const aad = Buffer.from("user:42")
    const ct = seal(key, "data", aad)
    const pt = open(key, ct, aad)
    expect(pt.toString("utf8")).toBe("data")
  })

  it("rejects wrong AAD with TamperedError", () => {
    const ct = seal(key, "hello", Buffer.from("ctx-1"))
    expect(() => open(key, ct, Buffer.from("ctx-2"))).toThrow(TamperedError)
  })

  it("rejects missing AAD when set", () => {
    const ct = seal(key, "hello", Buffer.from("ctx"))
    expect(() => open(key, ct)).toThrow(TamperedError)
  })

  it("two seals of the same plaintext produce different ciphertexts", () => {
    const a = seal(key, "hello")
    const b = seal(key, "hello")
    expect(a).not.toEqual(b)
  })

  it("rejects wrong key with TamperedError", () => {
    const ct = seal(key, "hello")
    expect(() => open(randomBytes(AEAD_KEY_SIZE), ct)).toThrow(TamperedError)
  })

  it("rejects tampered ciphertext bit", () => {
    const ct = seal(key, "hello, longer payload to tamper with")
    const raw = Buffer.from(ct, "base64url")
    raw[20]! ^= 0x01
    const tampered = raw.toString("base64url")
    expect(() => open(key, tampered)).toThrow(TamperedError)
  })

  it("rejects tampered tag bit", () => {
    const ct = seal(key, "hello")
    const raw = Buffer.from(ct, "base64url")
    raw[raw.length - 1]! ^= 0x01
    const tampered = raw.toString("base64url")
    expect(() => open(key, tampered)).toThrow(TamperedError)
  })

  it.each([0, 16, 24, 31, 33])("rejects %d-byte key on seal", (n) => {
    expect(() => seal(Buffer.alloc(n), "x")).toThrow(InvalidKeyError)
  })

  it.each([0, 16, 31, 33])("rejects %d-byte key on open", (n) => {
    const good = randomBytes(AEAD_KEY_SIZE)
    const ct = seal(good, "x")
    expect(() => open(Buffer.alloc(n), ct)).toThrow(InvalidKeyError)
  })

  it("rejects too-short ciphertext", () => {
    const tooShort = Buffer.from([0x01, 0x02, 0x03]).toString("base64url")
    expect(() => open(key, tooShort)).toThrow(CiphertextTooShortError)
  })

  it("rejects unknown version byte", () => {
    const buf = Buffer.alloc(29)
    buf[0] = 0xff
    expect(() => open(key, buf.toString("base64url"))).toThrow(UnsupportedVersionError)
  })
})

describe("Sealer", () => {
  const key = randomBytes(AEAD_KEY_SIZE)

  it("constructor rejects invalid key length", () => {
    expect(() => new Sealer(Buffer.alloc(16))).toThrow(InvalidKeyError)
  })

  it("round-trips through Sealer", () => {
    const s = new Sealer(key)
    const ct = s.seal("payload", Buffer.from("ctx"))
    const pt = s.open(ct, Buffer.from("ctx"))
    expect(pt.toString("utf8")).toBe("payload")
  })

  it("Sealer output opens with package-level open", () => {
    const s = new Sealer(key)
    const ct = s.seal("payload")
    const pt = open(key, ct)
    expect(pt.toString("utf8")).toBe("payload")
  })

  it("package-level seal output opens with Sealer", () => {
    const ct = seal(key, "payload")
    const s = new Sealer(key)
    const pt = s.open(ct)
    expect(pt.toString("utf8")).toBe("payload")
  })
})
