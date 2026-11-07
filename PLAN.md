# PLAN: the Windows CI job passes again

Status: **done** on `fix/windows-ci` (not pushed); the Windows job itself is
proven by the next CI run.

## Goal

`ci` / `test (windows-latest)` fails at `go test ./...` on every push since
6537aad (feat/packages, 2026-10-29; run 40920338326) - dev's runs 40920412874,
40927113395, 41360967634, 41727551241. The last green Windows run tested
c506e84 (38489808613). Find the cause and fix it without weakening a check.

Cause: 68fe206 moved the vendor data from `vendors/` to `ekroots/vendors/`;
`.gitattributes` kept `vendors/** -text`, which, having a slash, is anchored at
the root and no longer matches. The Windows runner checks out with
`core.autocrlf=true`, so the text files of the embedded data (MANIFEST,
README.md, vendor.yaml) and the signed test vectors (`manifest/testdata`)
arrive with CRLF: their SHA-256 no longer matches MANIFEST, the ssh signature
no longer verifies. Reproduced on Linux with `git -c core.autocrlf=true clone`:
ekroots, store, manifest and cmd/tpm2-verifier fail exactly so.

## Steps

- [x] 1. `.gitattributes`: `-text` for `ekroots/vendors/**`,
      `manifest/allowed_signers`, `manifest/testdata/**`.
- [x] 2. `internal/gitattr.RequireBinary`, a test helper asking
      `git check-attr text`; tests in ekroots and manifest, so a move of the
      data without its line fails on Linux too (skips without git or a work
      tree).
- [x] 3. Verify: `go vet`, `go test -count=1 ./...`; the same in a checkout
      with `core.autocrlf=true`; `GOOS=windows` vet, build and `test -c` of
      every package.

## Open questions

- None blocking. The Node.js 20 deprecation warning (actions/checkout@v4,
  actions/setup-go@v5) is a warning only; moving to their next majors is a
  separate change.
