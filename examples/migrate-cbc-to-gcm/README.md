# Example: migrate-cbc-to-gcm

One-shot migration script that re-encrypts AES-CBC ciphertext as AES-GCM AEAD.

## When to use this pattern

- You have data encrypted with `encryptCbc` (or the older `aitoolscrypt.ts`-style hex CBC) and want authenticated encryption.
- You're consolidating two systems where one used CBC and the other uses GCM.
- A compliance audit flags the lack of authentication on stored ciphertext.

## When migration is optional

CBC is a first-class peer in this package — `decryptCbc` and `open` both work indefinitely. If your CBC data is stable and you don't have a specific reason to switch, leaving it alone is correct.

## Run

```sh
cd examples/migrate-cbc-to-gcm
node --import tsx main.ts
```

## What it does

1. Sets up an in-memory "database" with three CBC-encrypted rows and one already-AEAD row (mixed format).
2. Iterates every row.
3. Calls `openAuto(key, ciphertext)` — works on both CBC and AEAD formats.
4. Re-encrypts the plaintext with `seal`.
5. Sanity-check: every row now opens with plain `open`.

## Why `openAuto`

- **Idempotent.** Safe to re-run. AEAD rows pass through untouched.
- **Mixed format.** If app code is concurrently writing AEAD during the migration, the script handles whatever it finds.

## Production playbook

1. Backup the database.
2. Run in batches with cursor-based iteration (`WHERE id > $last`).
3. Log per-row: success / failure / format.
4. Run during low traffic.
5. After completion, switch the application read path from `openAuto` back to plain `open`.

## See also

- [Go counterpart's MIGRATION.md](https://github.com/ubgo/crypt/blob/main/MIGRATION.md) — full playbook with rollback strategy.
