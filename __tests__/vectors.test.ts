/**
 * Cross-language test vectors. Both Go and TS implementations consume
 * testdata/vectors.json. Any divergence between the two implementations
 * fails CI on both sides.
 */

import { describe, expect, it } from "vitest"
import { Buffer } from "node:buffer"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { dirname } from "node:path"

import { open, sign, verify } from "../src/index.js"
import { sealWithNonce } from "../src/aead.js"
import { decryptCbc } from "../src/legacy/index.js"

const __dirname = dirname(fileURLToPath(import.meta.url))

interface VectorsDoc {
  version: number
  notes: string
  aead: AEADVector[]
  hmac: HMACVector[]
  cbc_legacy: CBCVector[]
}

interface AEADVector {
  name: string
  key_hex: string
  nonce_hex: string
  aad_hex: string
  plaintext_hex: string
  expected_b64url: string
}

interface HMACVector {
  name: string
  key_hex: string
  data_hex: string
  expected_hex: string
}

interface CBCVector {
  name: string
  key_hex: string
  iv_hex: string
  plaintext_hex: string
  expected_hex: string
}

function loadVectors(): VectorsDoc {
  const path = resolve(__dirname, "..", "testdata", "vectors.json")
  return JSON.parse(readFileSync(path, "utf8")) as VectorsDoc
}

const vectors = loadVectors()

describe("AEAD seal — vector parity with Go", () => {
  for (const v of vectors.aead) {
    it(v.name, () => {
      const key = Buffer.from(v.key_hex, "hex")
      const nonce = Buffer.from(v.nonce_hex, "hex")
      const aad = v.aad_hex ? Buffer.from(v.aad_hex, "hex") : undefined
      const plaintext = Buffer.from(v.plaintext_hex, "hex")
      const got = sealWithNonce(key, plaintext, aad, nonce)
      expect(got).toBe(v.expected_b64url)
    })
  }
})

describe("AEAD open — vector parity with Go", () => {
  for (const v of vectors.aead) {
    it(v.name, () => {
      const key = Buffer.from(v.key_hex, "hex")
      const aad = v.aad_hex ? Buffer.from(v.aad_hex, "hex") : undefined
      const expectedPlaintext = Buffer.from(v.plaintext_hex, "hex")
      const pt = open(key, v.expected_b64url, aad)
      expect(pt.equals(expectedPlaintext)).toBe(true)
    })
  }
})

describe("HMAC sign — vector parity with Go", () => {
  for (const v of vectors.hmac) {
    it(v.name, () => {
      const key = Buffer.from(v.key_hex, "hex")
      const data = Buffer.from(v.data_hex, "hex")
      const want = Buffer.from(v.expected_hex, "hex")
      const got = sign(key, data)
      expect(got.equals(want)).toBe(true)
      expect(verify(key, data, want)).toBe(true)
    })
  }
})

describe("CBC decrypt — vector parity with Go", () => {
  for (const v of vectors.cbc_legacy) {
    it(v.name, () => {
      const key = Buffer.from(v.key_hex, "hex")
      const expectedPlaintext = Buffer.from(v.plaintext_hex, "hex")
      const pt = decryptCbc(key, v.expected_hex)
      expect(pt.equals(expectedPlaintext)).toBe(true)
    })
  }
})
