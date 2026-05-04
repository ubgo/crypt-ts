/**
 * Cross-language interop demo, TS side.
 *
 * Run:           node --import tsx examples/cross-lang-ts/encrypt.ts
 * It prints a ciphertext to stdout encrypted under a fixed shared
 * key. Then in the Go repo, run:
 *
 *     go run ./examples/cross_lang_go/decrypt -ct '<paste>'
 *
 * (Or paste into your own Go program.) The Go side will produce the
 * same plaintext, byte-for-byte.
 */

import { open, seal } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const SHARED_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const key = Buffer.from(SHARED_KEY_HEX, "hex")
const plaintext = Buffer.from("Hello from TS! This message will decrypt in Go.")
const aad = Buffer.from("crypt-demo-v1")

const ct = seal(key, plaintext, aad)

console.log("=== TS encrypt ===")
console.log(`key (hex): ${SHARED_KEY_HEX}`)
console.log(`aad      : ${aad.toString("utf8")}`)
console.log(`plaintext: ${plaintext.toString("utf8")}`)
console.log(`ciphertext (paste into Go decrypt):\n${ct}`)

// Sanity round-trip.
const pt = open(key, ct, aad)
console.log(`\nTS round-trip plaintext: ${pt.toString("utf8")}`)
