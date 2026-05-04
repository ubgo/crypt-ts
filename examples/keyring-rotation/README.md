# Example: keyring-rotation

Built-in `KeyRing` for graceful key rotation. Wire format embeds a key id (kid) in each ciphertext, so reads dispatch O(1) by kid.

## When to use this pattern

- Annual or scheduled key rotation (compliance: SOC2, PCI).
- Compromise response: add new active key, leave old key in for read-only fallback, migrate as natural turnover happens, drop old key.
- Multi-tenant SaaS where each tenant has a kid identifying their key version.

## Run

```sh
cd examples/keyring-rotation
node --import tsx main.ts
```

## What it does

1. Boots a ring with one active key tagged "2025".
2. Seals data — ciphertext is tagged with "2025" (version byte 0x03 + kid).
3. Adds a "2026" key, sets it active.
4. New seals are tagged "2026"; old seals still read because the ring still holds the "2025" key.
5. Removes "2025" — orphaned 2025-tagged ciphertexts now fail.

## Adapting to your code

```ts
import { KeyRing } from "@ubgo/crypt"

// Boot once. Load keys from secrets manager.
const ring = new KeyRing(activeKid, activeKey)
for (const [kid, key] of Object.entries(historicalKeys)) {
  ring.add(kid, key)
}

// Inject as a service dependency.
class Service {
  constructor(private readonly ring: KeyRing) {}
  encrypt(plaintext: Buffer | string): string {
    return this.ring.seal(plaintext)
  }
  decrypt(ct: string): Buffer {
    return this.ring.open(ct)
  }
}
```

## Rotation playbook

1. Generate new key, add to KMS / secrets manager.
2. Deploy: include the new key as `ring.add(newKid, newKey)`. Active kid stays the old one.
3. Once all replicas have the new key loaded: deploy with `ring.setActive(newKid)`.
4. Watch metrics for old-kid reads. They'll drop off as data naturally rotates.
5. After the rotation window: deploy with `ring.remove(oldKid)`. Or run a batch migration first.

## Cross-language

KeyRing wire format (version 0x03) is byte-identical with the Go counterpart. A KeyRing-sealed ciphertext from Go opens here with the same kid/key, and vice versa.
