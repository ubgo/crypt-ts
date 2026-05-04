import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"

import { ExpiredError, TamperedError, issueToken, verifyToken } from "../src/index.js"

describe("time-locked tokens", () => {
  const key = Buffer.alloc(32, 0x42)

  it("round-trips a token", () => {
    const tok = issueToken(key, "payload", 60_000, Buffer.from("test"))
    expect(verifyToken(key, tok, Buffer.from("test")).toString("utf8")).toBe("payload")
  })

  it("rejects zero/negative TTL", () => {
    expect(() => issueToken(key, "x", 0)).toThrow(RangeError)
    expect(() => issueToken(key, "x", -1)).toThrow(RangeError)
  })

  it("expired tokens fail with ExpiredError", async () => {
    const { seal } = await import("../src/index.js")
    const past = Math.floor(Date.now() / 1000) - 3600
    const wrapped = Buffer.alloc(8 + 5)
    wrapped.writeBigUInt64BE(BigInt(past), 0)
    Buffer.from("stale").copy(wrapped, 8)
    const tok = seal(key, wrapped, Buffer.from("test"))

    expect(() => verifyToken(key, tok, Buffer.from("test"))).toThrow(ExpiredError)
  })

  it("rejects wrong AAD", () => {
    const tok = issueToken(key, "payload", 60_000, Buffer.from("ctx-1"))
    expect(() => verifyToken(key, tok, Buffer.from("ctx-2"))).toThrow(TamperedError)
  })

  it("rejects tampered payload", () => {
    const tok = issueToken(key, "payload", 60_000)
    const tampered = tok.slice(0, -2) + "XX"
    expect(() => verifyToken(key, tampered)).toThrow()
  })
})
