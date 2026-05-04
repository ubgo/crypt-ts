# Benchmarks

Real numbers from `pnpm exec vitest bench --run` on commodity hardware. Re-run on your target before making capacity decisions.

## How to run

```sh
pnpm exec vitest bench --run
```

## Reference numbers

Hardware: Apple M1, macOS 14, Node.js 22.

```
AEAD seal
  seal 64B          187,086 ops/sec   ~5.3 µs/op
  seal 1KB          153,544 ops/sec   ~6.5 µs/op
  seal 16KB          72,195 ops/sec   ~13.9 µs/op
  seal 1MB            1,617 ops/sec   ~618 µs/op
  Sealer.seal 1KB   158,754 ops/sec   ~6.3 µs/op

AEAD open
  open 64B          284,754 ops/sec   ~3.5 µs/op
  open 1KB          211,855 ops/sec   ~4.7 µs/op
  Sealer.open 1KB   224,970 ops/sec   ~4.4 µs/op

HMAC
  sign 64B          403,089 ops/sec   ~2.5 µs/op
  sign 1KB          381,810 ops/sec   ~2.6 µs/op
  verify 1KB        331,805 ops/sec   ~3.0 µs/op

random
  randomBytes(32)   746,005 ops/sec   ~1.3 µs/op
  randomToken(24)   505,947 ops/sec   ~2.0 µs/op

misc
  constantTimeEqual 32B  1,587,583 ops/sec  ~0.6 µs/op
  encryptCbc 1KB           131,308 ops/sec  ~7.6 µs/op
```

The Go counterpart at `github.com/ubgo/crypt` is ~3-5x faster per op due to JS overhead in V8 (still calling the same AES-NI hardware path under the hood). See `BENCHMARKS.md` in the Go repo for matching numbers.

## What this means in practice

- **Encrypt-at-rest per-row:** ~150k ops/sec for 1KB rows. Network and DB will be the bottleneck long before crypto.
- **Webhook signing:** ~400k ops/sec. Effectively free.
- **Session decrypt per request:** ~210k ops/sec for 1KB sessions.

## Sealer vs package-level seal/open

The `Sealer` class is marginally faster (~10%) than the package-level functions for repeated operations because the AES key is bound at construction. Use `Sealer` in long-lived services; use the package-level form in one-shots.

## Memory

Each AEAD op allocates ~4-5 short-lived Buffers. V8's GC handles these without measurable impact at typical SaaS request rates.

## Browser

This package targets Node.js. A future browser/WebCrypto build would have different performance characteristics (WebCrypto's async API has measurable overhead per call).
