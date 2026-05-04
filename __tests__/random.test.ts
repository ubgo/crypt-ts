import { describe, expect, it } from "vitest"

import { randomBytes, randomHex, randomToken } from "../src/index.js"

describe("randomBytes", () => {
  it.each([1, 8, 16, 32, 64, 256])("returns %d bytes", (n) => {
    const b = randomBytes(n)
    expect(b.length).toBe(n)
  })

  it("returns distinct outputs", () => {
    expect(randomBytes(32).equals(randomBytes(32))).toBe(false)
  })

  it.each([0, -1, 1.5, NaN])("rejects non-positive integer %s", (n) => {
    expect(() => randomBytes(n as number)).toThrow(RangeError)
  })
})

describe("randomToken", () => {
  it.each([
    [1, 2],
    [8, 11],
    [16, 22],
    [24, 32],
    [32, 43],
  ])("randomToken(%d) → %d chars", (n, want) => {
    const s = randomToken(n)
    expect(s.length).toBe(want)
  })

  it("uses URL-safe alphabet, no padding", () => {
    const tok = randomToken(32)
    expect(/^[A-Za-z0-9_-]+$/.test(tok)).toBe(true)
  })

  it("returns distinct outputs", () => {
    expect(randomToken(16)).not.toEqual(randomToken(16))
  })
})

describe("randomHex", () => {
  it.each([1, 8, 16, 32])("randomHex(%d) → %d chars", (n) => {
    const s = randomHex(n)
    expect(s.length).toBe(2 * n)
    expect(/^[0-9a-f]+$/.test(s)).toBe(true)
  })

  it("returns distinct outputs", () => {
    expect(randomHex(16)).not.toEqual(randomHex(16))
  })
})
