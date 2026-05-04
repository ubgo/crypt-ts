import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"
import { randomBytes } from "node:crypto"

import { open, seal } from "../src/index.js"
import { decryptCbc, encryptCbc, openAuto } from "../src/index.js"
import { InvalidKeyError, TamperedError, UnknownFormatError } from "../src/index.js"

const KEY32 = Buffer.alloc(32, 0x01)
const KEY16 = Buffer.alloc(16, 0x02)
const KEY24 = Buffer.alloc(24, 0x03)

describe("encryptCbc / decryptCbc", () => {
  it.each([
    ["AES-128", KEY16],
    ["AES-192", KEY24],
    ["AES-256", KEY32],
  ])("round-trips with %s", (_name, key) => {
    const ct = encryptCbc(key, "the quick brown fox")
    const pt = decryptCbc(key, ct)
    expect(pt.toString("utf8")).toBe("the quick brown fox")
  })

  it("rejects invalid key length", () => {
    expect(() => encryptCbc(Buffer.alloc(15), "x")).toThrow(InvalidKeyError)
    expect(() => decryptCbc(Buffer.alloc(15), "deadbeef")).toThrow(InvalidKeyError)
  })

  it("rejects non-hex ciphertext", () => {
    expect(() => decryptCbc(KEY32, "not-a-hex-string")).toThrow()
  })

  it("rejects too-short ciphertext", () => {
    expect(() => decryptCbc(KEY32, "deadbeef")).toThrow()
  })

  it("rejects tampered ciphertext (bad padding)", () => {
    const ct = encryptCbc(KEY32, "secret")
    const tampered = ct.slice(0, -2) + "ff"
    expect(() => decryptCbc(KEY32, tampered)).toThrow()
  })
})

describe("openAuto", () => {
  it("opens AEAD ciphertext", () => {
    const key = randomBytes(32)
    const ct = seal(key, "hello via aead", Buffer.from("ctx"))
    const pt = openAuto(key, ct, Buffer.from("ctx"))
    expect(pt.toString("utf8")).toBe("hello via aead")
  })

  it("opens CBC ciphertext", () => {
    const ct = encryptCbc(KEY32, "hello via cbc")
    const pt = openAuto(KEY32, ct)
    expect(pt.toString("utf8")).toBe("hello via cbc")
  })

  it("ignores AAD for CBC", () => {
    const ct = encryptCbc(KEY32, "payload")
    const pt = openAuto(KEY32, ct, Buffer.from("ignored"))
    expect(pt.toString("utf8")).toBe("payload")
  })

  it("rejects garbage input with UnknownFormatError", () => {
    expect(() => openAuto(KEY32, "this-is-not-encrypted")).toThrow(UnknownFormatError)
  })

  it("rejects wrong key on AEAD path", () => {
    const good = randomBytes(32)
    const bad = randomBytes(32)
    const ct = seal(good, "x")
    expect(() => openAuto(bad, ct)).toThrow()
  })
})

describe("Go ↔ TS interop (placeholder until vector-based test runs)", () => {
  it("sanity: TS seals, TS opens — full round-trip", () => {
    const key = randomBytes(32)
    const ct = seal(key, "interop")
    const pt = open(key, ct)
    expect(pt.toString("utf8")).toBe("interop")
  })

  // The full Go-Go-TS / TS-Go cross-language vectors are exercised in
  // vectors.test.ts. This file just sanity-checks the local round-trip.
  it("placeholder so this file isn't empty", () => {
    expect(TamperedError).toBeDefined()
  })
})
