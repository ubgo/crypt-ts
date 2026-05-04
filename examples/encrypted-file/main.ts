/**
 * Encrypt a file before writing to disk / object storage.
 *
 * Local FS is used here; the same shape applies to S3, GCS, R2.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"

async function writeEncrypted(
  sealer: Sealer,
  filePath: string,
  plaintext: Buffer | string,
  aad: Buffer,
): Promise<void> {
  const ct = sealer.seal(plaintext, aad)
  await fs.writeFile(filePath, ct, "utf8")
}

async function readEncrypted(sealer: Sealer, filePath: string, aad: Buffer): Promise<Buffer> {
  const raw = await fs.readFile(filePath, "utf8")
  return sealer.open(raw, aad)
}

async function main() {
  const sealer = new Sealer(Buffer.from("01234567890123456789012345678901"))
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "crypt-file-"))

  try {
    const plain = Buffer.from(
      "This is the contents of a sensitive document.\nAnyone with the encryption key can decrypt; everyone else sees ciphertext.",
    )
    const encPath = path.join(tmp, "report.enc")
    const aad = Buffer.from("file:report-2026-05")

    await writeEncrypted(sealer, encPath, plain, aad)
    const stat = await fs.stat(encPath)
    console.log(`wrote ${encPath} (${stat.size} bytes ciphertext, ${plain.length} bytes plaintext)`)

    const got = await readEncrypted(sealer, encPath, aad)
    console.log(`\ndecrypted contents:\n${got.toString("utf8")}`)

    try {
      await readEncrypted(sealer, encPath, Buffer.from("file:wrong-name"))
    } catch (e) {
      console.log(`\nAAD mismatch: ${(e as Error).message}`)
    }
  } finally {
    await fs.rm(tmp, { recursive: true, force: true })
  }
}

void main()
