# Contributing to @ubgo/crypt (crypt-ts)

Thanks for your interest in `@ubgo/crypt`. This repository is licensed under the **Apache License 2.0**. Pull requests are welcome.

## Workflow

1. Open an issue first for anything beyond a tiny fix.
2. Fork + branch named after the issue: `fix/123-...`, `feat/456-...`.
3. Run local checks: `pnpm verify`.
4. Use Conventional Commits for the PR title.

## Code conventions

- **Strict TypeScript.** No `any`; the public API is fully typed. `pnpm typecheck` must pass.
- **Coverage target.** ≥ 90% line coverage (`pnpm test:coverage`).
- **Cross-language parity is a hard invariant.** Any change to the wire format must keep `testdata/vectors.json` in lockstep with the Go counterpart [`github.com/ubgo/crypt`](https://github.com/ubgo/crypt). A ciphertext produced by one side must decrypt byte-for-byte on the other.
- **Public API stability.** Once the package reaches v1.0.0, breaking changes require a major version bump.

## Testing locally

```sh
pnpm test            # vitest run
pnpm test:coverage   # with coverage report
pnpm typecheck       # tsc --noEmit
pnpm lint            # eslint
pnpm build           # tsup (ESM + CJS)
pnpm verify          # typecheck + test + build (what CI runs)
```

## License of contributions

By submitting a pull request, you agree that your contribution is provided under the same Apache License 2.0 as the rest of the repository.
