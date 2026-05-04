# Changelog

All notable changes are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v0.1.0 initial release

### Added

- **AEAD authenticated encryption**: `seal` / `open` and the `Sealer` class. AES-256-GCM with version-tagged base64url-no-pad output. Byte-for-byte parity with `github.com/ubgo/crypt`.
- **Random helpers**: `randomBytes`, `randomToken` (URL-safe base64), `randomHex`.
- **HMAC-SHA256 signing**: `sign` / `verify` (constant-time) and `constantTimeEqual` wrapper.
- **Legacy AES-CBC** at `@ubgo/crypt/legacy`: `encryptCbc` / `decryptCbc` for backward compatibility with data encrypted by older Go API.
- **Migration helper** at `@ubgo/crypt/legacy`: `openAuto` detects format (AEAD vs CBC) and dispatches.
- **Cross-language test vectors** consumed from `testdata/vectors.json` (shared with the Go counterpart).
- Strict TypeScript types throughout; dual ESM + CJS build via tsup; vitest test runner.
- 93 tests covering round-trip, tamper, key validation, and 17 cross-language vector tests for byte-for-byte parity with Go.

### Notes

- Password hashing is intentionally not included — it's a server-side concern. Use the Go counterpart's `crypt.HashPassword` or pull in a separate `argon2` npm package.
- Browser/WebCrypto target is not supported; this package targets Node.js only.
