# Packaging

| Path | Purpose |
|------|---------|
| `aur/PKGBUILD` | Arch Linux package of a release tag; published to the AUR by the release workflow |
| `../debian/` | Debian package (native, `3.0 (native)`), built against Debian 13 |
| `deb-version.sh` | Debian version from `git describe` (`v0.3.0-rc1` -> `0.3.0~rc1`) |
| `deb/Dockerfile` | Debian 13 build container for local builds |
| `build-packages.sh` | Builds the Arch and Debian packages of HEAD locally into `build/packages/` |

Both packages contain one statically linked, cgo-free binary,
`/usr/bin/tpm2-verifier`, the vendor data in
`/usr/share/tpm2-verifier/vendors` (use it with `-store`), README and licence.
A release needs vendor data signed by a key in `manifest/allowed_signers`
(`tpm2-verifier store verify`); sign `vendors/MANIFEST` before tagging.

## Releases

Pushing a tag (`v0.1.0`, or `v0.2.0-rc1` for a prerelease) runs
`.github/workflows/release.yml`:

1. unit tests (once; the package builds skip theirs)
2. release binaries: Linux amd64/arm64, Windows amd64, macOS amd64/arm64;
   `store verify` of `vendors/` (must be signed) and the vendor data archive
3. Arch package in an `archlinux` container, checked with `namcap`
4. Debian package in a `debian:trixie` container (vendored source, builds
   offline), checked with `lintian`
5. GitHub release with all artifacts and checksums
6. AUR: the built PKGBUILD and `.SRCINFO` are pushed to
   `aur.archlinux.org/tpm2-verifier.git` (not for prereleases). Needs the
   repository secret `AUR_SSH_PRIVATE_KEY`; without it the step is skipped.

All builds use the current Go release from go.dev
(`.github/actions/go-latest`), not the distribution's.

## Local builds

```bash
packaging/build-packages.sh          # both
packaging/build-packages.sh arch     # makepkg, on Arch Linux
packaging/build-packages.sh deb      # in a Debian 13 container (docker)
```
