# Example: encrypt-field

Encrypt-at-rest of a database column using `Sealer`.

## When to use this pattern

- Storing sensitive strings (API client secrets, tokens, encryption keys) in a database column where plaintext storage is unacceptable.
- The application needs to read the value back out for use (so it must be reversible — not hashed).

## Run

```sh
cd examples/encrypt-field
node --import tsx main.ts
```

## What it does

1. Loads a 32-byte application key.
2. Constructs a long-lived `Sealer`.
3. Encrypts a plaintext "client secret", stores ciphertext in a fake row.
4. Reads it back, decrypts.
5. Demonstrates that any tampering with the stored ciphertext throws `TamperedError`.

## Adapting to your code

```ts
import { Sealer } from "@ubgo/crypt"

class PartnerService {
  constructor(
    private readonly sealer: Sealer,
    private readonly db: Pool,
  ) {}

  async create(secret: string): Promise<void> {
    const enc = this.sealer.seal(secret)
    await this.db.query(`INSERT INTO partners(client_secret) VALUES($1)`, [enc])
  }

  async getSecret(id: string): Promise<string> {
    const { rows } = await this.db.query(`SELECT client_secret FROM partners WHERE id = $1`, [id])
    return this.sealer.open(rows[0].client_secret).toString("utf8")
  }
}
```
