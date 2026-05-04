/**
 * Vitest benchmarks. Run with:
 *   pnpm exec vitest bench --run
 *
 * Numbers are captured in BENCHMARKS.md.
 */

import { bench, describe } from "vitest"
import { Buffer } from "node:buffer"
import { randomBytes as nodeRandom } from "node:crypto"

import {
  AEAD_KEY_SIZE,
  Sealer,
  constantTimeEqual,
  open,
  randomBytes,
  randomToken,
  seal,
  sign,
  verify,
} from "../src/index.js"
import { encryptCbc } from "../src/legacy/index.js"

const key = nodeRandom(AEAD_KEY_SIZE)
const sealer = new Sealer(key)

const pt64 = Buffer.alloc(64, 0x42)
const pt1k = Buffer.alloc(1024, 0x42)
const pt16k = Buffer.alloc(16 * 1024, 0x42)
const pt1m = Buffer.alloc(1024 * 1024, 0x42)

describe("AEAD seal", () => {
  bench("seal 64B", () => {
    seal(key, pt64)
  })
  bench("seal 1KB", () => {
    seal(key, pt1k)
  })
  bench("seal 16KB", () => {
    seal(key, pt16k)
  })
  bench("seal 1MB", () => {
    seal(key, pt1m)
  })
  bench("Sealer.seal 1KB", () => {
    sealer.seal(pt1k)
  })
})

describe("AEAD open", () => {
  const ct64 = seal(key, pt64)
  const ct1k = seal(key, pt1k)
  bench("open 64B", () => {
    open(key, ct64)
  })
  bench("open 1KB", () => {
    open(key, ct1k)
  })
  bench("Sealer.open 1KB", () => {
    sealer.open(ct1k)
  })
})

describe("HMAC", () => {
  bench("sign 64B", () => {
    sign(key, pt64)
  })
  bench("sign 1KB", () => {
    sign(key, pt1k)
  })
  const mac = sign(key, pt1k)
  bench("verify 1KB", () => {
    verify(key, pt1k, mac)
  })
})

describe("random", () => {
  bench("randomBytes(32)", () => {
    randomBytes(32)
  })
  bench("randomToken(24)", () => {
    randomToken(24)
  })
})

describe("misc", () => {
  const a = Buffer.alloc(32, 0x42)
  const b = Buffer.alloc(32, 0x42)
  bench("constantTimeEqual 32B", () => {
    constantTimeEqual(a, b)
  })
  bench("encryptCbc 1KB", () => {
    encryptCbc(key, pt1k)
  })
})
