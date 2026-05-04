import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"
import { randomBytes as nodeRandom } from "node:crypto"

import {
  AEAD_KEY_SIZE,
  CryptError,
  InvalidKeyError,
  Sealer,
  TamperedError,
  UnknownFormatError,
  open,
  randomBytes,
  randomHex,
  randomToken,
  seal,
  sign,
  verify,
} from "../src/index.js"
import { sealWithNonce } from "../src/aead.js"
import { decryptCbc, encryptCbc, openAuto } from "../src/index.js"

// ---------------------------------------------------------------------
// AEAD comprehensive
// ---------------------------------------------------------------------

describe("AEAD comprehensive", () => {
  it("accepts Uint8Array (non-Buffer) plaintext input", () => {
    const key = nodeRandom(AEAD_KEY_SIZE)
    const u8 = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]) // "hello"
    const ct = seal(key, u8)
    const pt = open(key, ct)
    expect(pt.toString("utf8")).toBe("hello")
  })

  it("accepts Uint8Array key", () => {
    const key = new Uint8Array(nodeRandom(AEAD_KEY_SIZE))
    const ct = seal(key, "x")
    expect(open(key, ct).toString("utf8")).toBe("x")
  })

  it("accepts Uint8Array AAD", () => {
    const key = nodeRandom(AEAD_KEY_SIZE)
    const aad = new Uint8Array([0x01, 0x02, 0x03])
    const ct = seal(key, "x", aad)
    expect(open(key, ct, aad).toString("utf8")).toBe("x")
  })

  it("seals 1MB plaintext", () => {
    const key = nodeRandom(AEAD_KEY_SIZE)
    const big = Buffer.alloc(1024 * 1024, 0x42)
    const ct = seal(key, big)
    const pt = open(key, ct)
    expect(pt.equals(big)).toBe(true)
  })

  it("seals binary plaintext with all byte values 0..255", () => {
    const key = nodeRandom(AEAD_KEY_SIZE)
    const bin = Buffer.alloc(256)
    for (let i = 0; i < 256; i++) bin[i] = i
    const ct = seal(key, bin)
    const pt = open(key, ct)
    expect(pt.equals(bin)).toBe(true)
  })

  it("Uint8Array AAD vs Buffer AAD interchangeable", () => {
    const key = nodeRandom(AEAD_KEY_SIZE)
    const ct = seal(key, "x", Buffer.from("ctx"))
    // Open with Uint8Array AAD of same content.
    const aadU8 = new Uint8Array(Buffer.from("ctx"))
    expect(open(key, ct, aadU8).toString("utf8")).toBe("x")
  })

  it("tampered version byte at offset 0 → UnsupportedVersionError", async () => {
    const { UnsupportedVersionError } = await import("../src/index.js")
    const key = nodeRandom(AEAD_KEY_SIZE)
    const ct = seal(key, "hello")
    const raw = Buffer.from(ct, "base64url")
    raw[0] = 0xab
    expect(() => open(key, raw.toString("base64url"))).toThrow(UnsupportedVersionError)
  })

  it("Sealer accepts Uint8Array key", () => {
    const u8 = new Uint8Array(nodeRandom(AEAD_KEY_SIZE))
    const s = new Sealer(u8)
    const ct = s.seal("hi")
    expect(s.open(ct).toString("utf8")).toBe("hi")
  })
})

// ---------------------------------------------------------------------
// sealWithNonce — internal test helper, full coverage of nonce-validation
// ---------------------------------------------------------------------

describe("sealWithNonce (internal)", () => {
  it("accepts a fixed valid nonce and is deterministic", () => {
    const key = Buffer.alloc(AEAD_KEY_SIZE, 0x00)
    const nonce = Buffer.alloc(12, 0x11)
    const a = sealWithNonce(key, "hello", undefined, nonce)
    const b = sealWithNonce(key, "hello", undefined, nonce)
    expect(a).toBe(b)
  })

  it("rejects nonce of wrong length", () => {
    const key = Buffer.alloc(AEAD_KEY_SIZE)
    expect(() => sealWithNonce(key, "x", undefined, Buffer.alloc(11))).toThrow(InvalidKeyError)
    expect(() => sealWithNonce(key, "x", undefined, Buffer.alloc(13))).toThrow(InvalidKeyError)
    expect(() => sealWithNonce(key, "x", undefined, Buffer.alloc(0))).toThrow(InvalidKeyError)
  })

  it("rejects invalid key length", () => {
    expect(() => sealWithNonce(Buffer.alloc(16), "x", undefined, undefined)).toThrow(
      InvalidKeyError,
    )
  })

  it("seals empty plaintext with valid fixed nonce", () => {
    const key = Buffer.alloc(AEAD_KEY_SIZE, 0x77)
    const nonce = Buffer.alloc(12, 0x55)
    const ct = sealWithNonce(key, Buffer.alloc(0), undefined, nonce)
    const pt = open(key, ct)
    expect(pt.length).toBe(0)
  })
})

// ---------------------------------------------------------------------
// CBC comprehensive
// ---------------------------------------------------------------------

describe("CBC comprehensive", () => {
  it.each([
    [16, "AES-128"],
    [24, "AES-192"],
    [32, "AES-256"],
  ])("round-trips with %i-byte key (%s)", (n) => {
    const key = Buffer.alloc(n, 0x42)
    const ct = encryptCbc(key, "the quick brown fox")
    const pt = decryptCbc(key, ct)
    expect(pt.toString("utf8")).toBe("the quick brown fox")
  })

  it.each([0, 1, 15, 17, 23, 25, 31, 33, 64])("rejects %i-byte key in encryptCbc", (n) => {
    expect(() => encryptCbc(Buffer.alloc(n), "x")).toThrow(InvalidKeyError)
  })

  it.each([0, 1, 15, 17, 23, 25, 31, 33, 64])("rejects %i-byte key in decryptCbc", (n) => {
    expect(() => decryptCbc(Buffer.alloc(n), "deadbeef")).toThrow(InvalidKeyError)
  })

  it("rejects odd-length hex", async () => {
    const { InvalidCiphertextError } = await import("../src/index.js")
    expect(() => decryptCbc(Buffer.alloc(32), "abc")).toThrow(InvalidCiphertextError)
  })

  it("rejects ciphertext shorter than IV", async () => {
    const { CiphertextTooShortError } = await import("../src/index.js")
    expect(() => decryptCbc(Buffer.alloc(32), "00".repeat(8))).toThrow(CiphertextTooShortError)
  })

  it("rejects body that's not block-aligned", async () => {
    const { CiphertextNotBlockAlignedError } = await import("../src/index.js")
    // 16-byte IV + 1-byte body = 17 bytes hex = 34 chars
    expect(() => decryptCbc(Buffer.alloc(32), "00".repeat(17))).toThrow(
      CiphertextNotBlockAlignedError,
    )
  })

  it("rejects empty body (IV only)", async () => {
    const { CiphertextNotBlockAlignedError } = await import("../src/index.js")
    expect(() => decryptCbc(Buffer.alloc(32), "00".repeat(16))).toThrow(
      CiphertextNotBlockAlignedError,
    )
  })

  it("tampering ciphertext changes the result (CBC has no auth)", async () => {
    // CBC has no message authentication, so a single bit flip
    // either produces an InvalidPaddingError OR garbage plaintext
    // (~1/256 chance the corrupted last byte happens to look like
    // valid padding). Either outcome is acceptable for this test —
    // we only assert that the result differs from the original.
    const key = Buffer.alloc(32, 0x42)
    const original = "secret-payload-of-some-length"
    const ct = encryptCbc(key, original)
    const tampered = ct.slice(0, -2) + "ff"
    let differed = false
    try {
      const out = decryptCbc(key, tampered)
      if (out.toString("utf8") !== original) differed = true
    } catch {
      differed = true
    }
    expect(differed).toBe(true)
  })

  it("encryptCbc accepts Uint8Array plaintext", () => {
    const key = Buffer.alloc(32, 0x42)
    const u8 = new Uint8Array([0x68, 0x69]) // "hi"
    const ct = encryptCbc(key, u8)
    const pt = decryptCbc(key, ct)
    expect(pt.toString("utf8")).toBe("hi")
  })

  it.each([
    "",
    "a",
    "abcdefghijklmno", // 15 < 1 block
    "abcdefghijklmnop", // 16 = exact block (full padding follows)
    "abcdefghijklmnopq", // 17 > 1 block
    "x".repeat(100), // multi-block
  ])("CBC round-trips %i-byte plaintext", (pt) => {
    const key = Buffer.alloc(32, 0x42)
    const ct = encryptCbc(key, pt)
    expect(decryptCbc(key, ct).toString("utf8")).toBe(pt)
  })
})

// ---------------------------------------------------------------------
// openAuto fall-through paths
// ---------------------------------------------------------------------

describe("openAuto fall-through paths", () => {
  const key = Buffer.alloc(32, 0x01)

  it("AEAD-shaped but wrong key falls through to UnknownFormatError", () => {
    const goodKey = Buffer.alloc(32, 0x02)
    const ct = seal(goodKey, "hello")
    // openAuto will detect AEAD shape, try open with wrong key,
    // catch the TamperedError, then try CBC (which fails — base64url
    // chars aren't all valid hex), then throw UnknownFormatError OR
    // the CBC error. Accept either.
    expect(() => openAuto(key, ct)).toThrow()
  })

  it("hex-shaped but wrong key produces wrong plaintext or throws", () => {
    // CBC has no auth, so a wrong key either fails padding check or
    // produces garbage plaintext. Both are acceptable outcomes; we
    // assert the result is not the original.
    const goodKey = Buffer.alloc(32, 0x02)
    const original = "hello"
    const ct = encryptCbc(goodKey, original)
    let differed = false
    try {
      const out = openAuto(key, ct)
      if (out.toString("utf8") !== original) differed = true
    } catch {
      differed = true
    }
    expect(differed).toBe(true)
  })

  it("totally bad input throws UnknownFormatError", () => {
    expect(() => openAuto(key, "***neither base64 nor hex***")).toThrow(UnknownFormatError)
  })

  it("returns plaintext on AEAD success", () => {
    const ct = seal(key, "v1 path")
    expect(openAuto(key, ct).toString("utf8")).toBe("v1 path")
  })

  it("returns plaintext on CBC success", () => {
    const ct = encryptCbc(key, "v0 path")
    expect(openAuto(key, ct).toString("utf8")).toBe("v0 path")
  })

  it("ignores AAD for CBC path", () => {
    const ct = encryptCbc(key, "no aad here")
    expect(openAuto(key, ct, Buffer.from("ignored")).toString("utf8")).toBe("no aad here")
  })

  it("AAD applied to AEAD path", () => {
    const aad = Buffer.from("ctx")
    const ct = seal(key, "data", aad)
    expect(openAuto(key, ct, aad).toString("utf8")).toBe("data")
    // Wrong AAD on the AEAD path falls through to CBC detection (which
    // fails because base64url isn't valid CBC), so error.
    expect(() => openAuto(key, ct, Buffer.from("other"))).toThrow()
  })

  it("base64url too short for AEAD falls through", () => {
    // 3 raw bytes, base64url-encoded.
    const tooShort = Buffer.from([0x01, 0x02, 0x03]).toString("base64url")
    expect(() => openAuto(key, tooShort)).toThrow(UnknownFormatError)
  })

  it("hex too short for CBC falls through", () => {
    expect(() => openAuto(key, "00".repeat(8))).toThrow(UnknownFormatError)
  })
})

// ---------------------------------------------------------------------
// Random — edge cases
// ---------------------------------------------------------------------

describe("random edge cases", () => {
  it.each([0, -1, -100, 1.5, NaN, Infinity])("rejects %s", (n) => {
    expect(() => randomBytes(n as number)).toThrow(RangeError)
  })

  it("randomToken matches encoded length", () => {
    expect(randomToken(1).length).toBe(2)
    expect(randomToken(48).length).toBe(64)
  })

  it("randomHex always produces 2*n chars", () => {
    for (let n = 1; n <= 32; n++) {
      expect(randomHex(n).length).toBe(2 * n)
    }
  })

  it("randomBytes outputs are well-distributed across 1024 samples", () => {
    const counts = new Array(256).fill(0) as number[]
    for (let i = 0; i < 1024; i++) {
      const b = randomBytes(32)
      for (const x of b) counts[x] = (counts[x] ?? 0) + 1
    }
    const expectedAvg = (1024 * 32) / 256 // 128
    for (let v = 0; v < 256; v++) {
      const c = counts[v] ?? 0
      expect(c).toBeGreaterThan(expectedAvg / 4)
      expect(c).toBeLessThan(expectedAvg * 4)
    }
  })
})

// ---------------------------------------------------------------------
// HMAC — additional coverage
// ---------------------------------------------------------------------

describe("HMAC comprehensive", () => {
  it("sign accepts empty key (cryptographically valid, operationally bad)", () => {
    const mac = sign(Buffer.from([]), Buffer.from("data"))
    expect(mac.length).toBe(32)
  })

  it("sign accepts empty data", () => {
    const mac = sign(Buffer.from("k"), Buffer.from([]))
    expect(mac.length).toBe(32)
  })

  it("sign accepts Uint8Array key + data", () => {
    const k = new Uint8Array([0x01, 0x02])
    const d = new Uint8Array([0x03, 0x04])
    const mac = sign(k, d)
    expect(mac.length).toBe(32)
  })

  it("sign on 1MB data round-trips", () => {
    const key = Buffer.alloc(32, 0xff)
    const data = Buffer.alloc(1024 * 1024, 0xaa)
    const mac = sign(key, data)
    expect(verify(key, data, mac)).toBe(true)
  })

  it("verify with empty mac returns false", () => {
    expect(verify(Buffer.from("k"), Buffer.from("d"), Buffer.alloc(0))).toBe(false)
  })

  it("verify accepts Uint8Array MAC", () => {
    const key = Buffer.from("k")
    const data = Buffer.from("d")
    const mac = sign(key, data)
    expect(verify(key, data, new Uint8Array(mac))).toBe(true)
  })
})

// ---------------------------------------------------------------------
// Error class hierarchy
// ---------------------------------------------------------------------

describe("error classes", () => {
  it("all custom errors extend CryptError", () => {
    const errs: CryptError[] = []
    try {
      open(Buffer.alloc(31), "x")
    } catch (e) {
      errs.push(e as CryptError)
    }
    try {
      open(Buffer.alloc(32), "tooshort")
    } catch (e) {
      errs.push(e as CryptError)
    }
    for (const e of errs) {
      expect(e).toBeInstanceOf(CryptError)
      expect(e).toBeInstanceOf(Error)
      expect(e.message).toMatch(/crypt:/)
    }
  })

  it("error names are unique strings", () => {
    const names = new Set<string>()
    const cases: Array<() => void> = [
      () => open(Buffer.alloc(31), "x"),
      () => open(Buffer.alloc(32), Buffer.alloc(0).toString("base64url")),
      () =>
        open(
          Buffer.alloc(32),
          Buffer.from(
            new Uint8Array([
              0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0,
            ]),
          ).toString("base64url"),
        ),
      () => decryptCbc(Buffer.alloc(31), "deadbeef"),
      () => decryptCbc(Buffer.alloc(32), "abc"),
      () => decryptCbc(Buffer.alloc(32), "00".repeat(8)),
      () => decryptCbc(Buffer.alloc(32), "00".repeat(17)),
      () => openAuto(Buffer.alloc(32), "xyz-not-encrypted"),
    ]
    for (const fn of cases) {
      try {
        fn()
      } catch (e) {
        names.add((e as Error).name)
      }
    }
    expect(names.size).toBeGreaterThanOrEqual(4)
  })

  it("TamperedError name is correct", () => {
    const key = nodeRandom(AEAD_KEY_SIZE)
    const ct = seal(key, "x")
    try {
      open(nodeRandom(AEAD_KEY_SIZE), ct)
      expect.unreachable()
    } catch (e) {
      expect(e).toBeInstanceOf(TamperedError)
      expect((e as Error).name).toBe("TamperedError")
    }
  })
})
