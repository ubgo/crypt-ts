# Changelog

All notable changes are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v2 features

- **Ed25519 signatures**: `generateEd25519`, `signEd25519`, `verifyEd25519` for asymmetric (public-key) signing.
- **Asymmetric encryption** (sealed-box): `generateKeyPair`, `sealAsymmetric`, `openAsymmetric` using X25519 ECDH + ChaCha20-Poly1305. Anonymous-sender semantics; sign with Ed25519 first if you need sender authentication. Wire format version 0x05.

### Added — v1.2 features

- **Time-locked tokens**: `issueToken` / `verifyToken` with embedded expiry. Returns `ExpiredError` on expiry. Stateless one-time tokens for password reset, magic login.

### Added — v1.1 features

- **HKDF key derivation**: `deriveKey` (SHA-256) for per-tenant or per-purpose sub-keys from a master.
- **KeyRing for rotation**: `KeyRing` class with `add`, `remove`, `setActive`, `activeKid`, `seal`, `open`. Wire format version 0x03 with embedded kid; old v1 ciphertexts still readable via try-each fallback.
- **ChaCha20-Poly1305 AEAD**: `sealChaCha20` / `openChaCha20`. Wire format version 0x02.

### Added — v0.1.0 baseline

- **AEAD authenticated encryption**: `seal` / `open` and the `Sealer` class. AES-256-GCM. Byte-for-byte parity with `github.com/ubgo/crypt`.
- **Random helpers**: `randomBytes`, `randomToken`, `randomHex`.
- **HMAC-SHA256 signing**: `sign` / `verify` and `constantTimeEqual` wrapper.
- **AES-CBC** at `@ubgo/crypt`: `encryptCbc` / `decryptCbc` for backward compatibility.
- **Migration helper** at `@ubgo/crypt`: `openAuto` detects format and dispatches.
- **Cross-language test vectors** consumed from `testdata/vectors.json` (shared with the Go counterpart).
- Strict TypeScript types; dual ESM + CJS build via tsup; vitest test runner.

### Notes

- Password hashing remains out of scope — server-side concern. Use the Go counterpart's `HashPassword` or pull `argon2` directly.
- KMS adapters and envelope encryption are Go-only — Node services typically delegate KMS to a Go service.
- Browser/WebCrypto target is not supported; this package targets Node.js only.
