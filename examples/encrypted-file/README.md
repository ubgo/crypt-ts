# Example: encrypted-file

Encrypt a file before writing to disk / object storage.

## When to use this pattern

- Storing user-uploaded documents at rest where the storage layer isn't trusted to hold plaintext.
- Backup files moved across systems.
- Application data exports.

For multi-GB files, the Go counterpart's `SealStream` / `OpenStream` handles streaming encryption — that path is Go-only in v1.2.

## Run

```sh
cd examples/encrypted-file
node --import tsx main.ts
```

## What it does

1. Writes a 120-byte plaintext file to a temp directory.
2. Reads it, seals with `Sealer.seal`, writes ciphertext.
3. Reads ciphertext, opens, recovers original.
4. Demonstrates AAD binding — opening with a different filename binding fails.

## Adapting to your code (S3)

```ts
import { Sealer } from "@ubgo/crypt"
import { PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3"

async function uploadEncrypted(
  sealer: Sealer,
  s3: S3Client,
  bucket: string,
  key: string,
  body: Buffer,
): Promise<void> {
  const aad = Buffer.from(`s3:${bucket}:${key}`)
  const ct = sealer.seal(body, aad)
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: ct }))
}

async function downloadEncrypted(
  sealer: Sealer,
  s3: S3Client,
  bucket: string,
  key: string,
): Promise<Buffer> {
  const out = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }))
  const raw = await out.Body!.transformToString()
  return sealer.open(raw, Buffer.from(`s3:${bucket}:${key}`))
}
```

The AAD = `s3:bucket:key` binding ensures an attacker who copies a ciphertext to a different S3 path can't have it decrypted there.
