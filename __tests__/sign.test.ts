import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"
import { createHmac } from "node:crypto"

import { constantTimeEqual, sign, verify } from "../src/index.js"

describe("sign", () => {
  it("output is 32 bytes", () => {
    const mac = sign(Buffer.from("k"), Buffer.from("d"))
    expect(mac.length).toBe(32)
  })

  it("deterministic for same inputs", () => {
    const a = sign(Buffer.from("k"), Buffer.from("d"))
    const b = sign(Buffer.from("k"), Buffer.from("d"))
    expect(a.equals(b)).toBe(true)
  })

  it("differs for different keys", () => {
    const a = sign(Buffer.from("k1"), Buffer.from("d"))
    const b = sign(Buffer.from("k2"), Buffer.from("d"))
    expect(a.equals(b)).toBe(false)
  })

  it("differs for different data", () => {
    const a = sign(Buffer.from("k"), Buffer.from("d1"))
    const b = sign(Buffer.from("k"), Buffer.from("d2"))
    expect(a.equals(b)).toBe(false)
  })

  it("matches node:crypto HMAC reference", () => {
    const key = Buffer.from("secret-key")
    const data = Buffer.from("the message")
    const ref = createHmac("sha256", key).update(data).digest()
    const got = sign(key, data)
    expect(got.equals(ref)).toBe(true)
  })
})

describe("verify", () => {
  const key = Buffer.from("k")
  const data = Buffer.from("payload")

  it("accepts valid MAC", () => {
    const mac = sign(key, data)
    expect(verify(key, data, mac)).toBe(true)
  })

  it("rejects tampered data", () => {
    const mac = sign(key, data)
    const tampered = Buffer.from(data)
    tampered[0]! ^= 0x01
    expect(verify(key, tampered, mac)).toBe(false)
  })

  it("rejects tampered MAC", () => {
    const mac = sign(key, data)
    const tampered = Buffer.from(mac)
    tampered[0]! ^= 0x01
    expect(verify(key, data, tampered)).toBe(false)
  })

  it("rejects wrong key", () => {
    const mac = sign(Buffer.from("k1"), data)
    expect(verify(Buffer.from("k2"), data, mac)).toBe(false)
  })

  it("rejects wrong-length MAC", () => {
    expect(verify(key, data, Buffer.alloc(1))).toBe(false)
    expect(verify(key, data, Buffer.alloc(100))).toBe(false)
  })
})

describe("constantTimeEqual", () => {
  it("true for equal contents", () => {
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abc"))).toBe(true)
    expect(constantTimeEqual(Buffer.alloc(0), Buffer.alloc(0))).toBe(true)
  })

  it("false for different contents", () => {
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abd"))).toBe(false)
  })

  it("false for different lengths", () => {
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abcd"))).toBe(false)
  })
})
