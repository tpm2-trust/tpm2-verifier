# tpm2-verifier

A pure Go library and CLI (`tpm2-verifier`) to inspect and verify TPM 2.0
endorsement key (EK) certificates and their vendor certificate chains, with a
curated, fingerprint-pinned store of TPM vendor root CAs, shipped as a signed
data directory next to the binary.

It is the Go successor of [intel-ek-dechainer](https://github.com/mrwiora/intel-ek-dechainer)
and does everything it did (split the per-device chain from NV, verify against
the Intel OnDie CA) for any vendor. It also reads the TPM directly, completes
chains via AIA, and checks every certificate of the chain against the CRLs
named in its distribution points, including indirect CRLs. CRLs are cached
locally, and their signatures are verified. For TPMs of unknown vendors it
writes a debug bundle that can be replayed and analyzed anywhere.

## Install

Every [release](https://github.com/tpm2-trust/tpm2-verifier/releases) has
static binaries (Linux amd64/arm64, Windows, macOS), an Arch Linux package and
a Debian 13 package; the Arch package is also in the AUR (`tpm2-verifier`).

```bash
sudo pacman -U tpm2-verifier-*.pkg.tar.zst      # Arch Linux (or: yay -S tpm2-verifier)
sudo apt install ./tpm2-verifier_*.deb          # Debian / Ubuntu
go install github.com/tpm2-trust/tpm2-verifier/cmd/tpm2-verifier@latest
```

The vendor data (`vendors/`) is not compiled in: tpm2-verifier uses
`./vendors` in the working directory, or the directory given with `-store`,
and stops with an error if there is none. The packages install it to
`/usr/share/tpm2-verifier/vendors`; with the binaries, download
`tpm2-verifier-vendors-<version>.tar.gz` from the release. Updated vendor data
can be dropped in without a new binary; see [Vendor data](#vendor-data) for
how it is checked.

```bash
tpm2-verifier version -store /usr/share/tpm2-verifier/vendors
# tpm2-verifier v0.1.0
# vendor data /usr/share/tpm2-verifier/vendors: version 2026.10.14, 5 files, manifest sha256 8a2e72bca53fca22, signed by ...
```

No cgo, no openssl needed. Linux first; it builds and runs on Windows too.
Packaging and the release workflow: [packaging/README.md](packaging/README.md).

## CLI

```bash
# Everything in one go: vendor, firmware, all NV indices, every EK certificate
# verified up to the vendor root, every CA checked against its CRL
tpm2-verifier info            # -v for attributes, fingerprints, CRL details; -json

tpm2-verifier info -prove     # also prove that this TPM holds the EK's private key (see below)
tpm2-verifier verify          # only the verification of the EK certificates in the TPM
tpm2-verifier export -o out   # EK certs, chain, raw NV, vendor CAs + matching openssl command
tpm2-verifier debug           # debug bundle for unknown vendors / bug reports (see below)
tpm2-verifier debug-anon      # what is needed to add the vendor, without identifying data

# The same for files, e.g. read with tpm2-tools (see the manual section)
tpm2-verifier verify ek.der chain.der
tpm2-verifier inspect ek.der chain.der some.crl   # details, AIA/CDP URLs, TCG quirks, store matches
tpm2-verifier split -o out chain.der              # one file per certificate
tpm2-verifier split -p intel-int -s 3 chain.der   # intel-ek-dechainer naming: intel-int3..5.der

tpm2-verifier store list | show intel | export -o certs
tpm2-verifier store verify                        # check vendors/ against its signed MANIFEST
tpm2-verifier version                             # program and vendor data version
tpm2-verifier cache list | clear | path

# Maintainers: turn submissions into vendor store changes (see below)
tpm2-verifier vendor review submissions/x.tar.gz
tpm2-verifier vendor import -accept <sha256> submissions/x.tar.gz
```

Reading the TPM needs access to `/dev/tpmrm0` (root or the `tss` group).
`-tpm` selects another TPM, using the TCTI syntax of tpm2-tools
(`TPM2TOOLS_TCTI` is honored too):

| `-tpm` | TPM |
|--------|-----|
| (empty) | `/dev/tpmrm0`, falling back to `/dev/tpm0`; TBS on Windows |
| `device:/dev/tpm0` | a TPM character device |
| `swtpm:host=localhost,port=2321` | [swtpm](https://github.com/stefanberger/swtpm) with `--server type=tcp` |
| `swtpm:path=/run/swtpm.sock` | swtpm with `--server type=unixio` |
| `bundle:file.tar.gz` | replay a [debug bundle](#debug-bundles-for-unknown-vendors) |

Only public data is read and no secrets are used: indices are read with
owner authorization and an empty password (if `ownerread` is set), or with
index authorization only if `no_da` is set, so a TPM can never be pushed
towards dictionary attack lockout. Only the TCG range `0x01C00000-0x01C0FFFF`
is read; other indices are only listed.

Expected output of `tpm2-verifier verify` on an Intel PTT machine (format illustration):

```
TPM 0x01C00002 (ek-certificate RSA 2048 (low)): TRUSTED (vendor intel)
TPM: manufacturer INTC, model "...", version ...
Chain:
  depth=0: <empty> [leaf] revocation=good
  depth=1: CN=CSME MCC PTT  01SVN [provided] revocation=good
  depth=2: CN=CSME MCC SVN01 Kernel CA [provided] revocation=good
  depth=3: CN=CSME MCC ROM CA [provided] revocation=good
  depth=4: CN=www.intel.com,OU=On Die CSME P_MCC 00001881 Issuing CA [store:intel/intermediates/mcc-00001881-issuing-ca.der] revocation=good
  depth=5: CN=www.intel.com,OU=OnDie CA CSME Intermediate CA [store:intel/intermediates/ondie-ca-csme-intermediate.der] revocation=good
  depth=6: CN=www.intel.com,OU=OnDie CA Root Cert Signing,... [store:intel/roots/ondie-ca-root.der, trust anchor]
```

`verify` and `info` exit with 0 if trusted, 1 if not (`untrusted-root`,
`incomplete`, `revoked`, `invalid`, or no EK certificate) and 2 on errors.

### Chain building and AIA

The chain is built from the EK certificate upwards using, in this order of
preference, the store's trust anchors, the certificates read from the TPM's
chain NV indices and the store's intermediates. If no issuer is known, the
issuer certificate is downloaded from the certificate's AIA "CA Issuers" URL
(DER, PEM or PKCS#7 `.p7c`) and cached in `~/.cache/tpm2-verifier/certs/`.
Downloaded certificates are only used as intermediates: a root obtained via
AIA is reported (`untrusted-root`, with its SHA-256) but never trusted unless
the identical certificate is in the vendor store.

### Revocation and the CRL cache

Each certificate of the chain (except the trust anchor) is checked against the
CRL named in its CRL distribution point. The CRL's signature is verified with
the CA that issued it, which must be in the verified chain or in the vendor
store. For an indirect CRL, that CA is the one named as `cRLIssuer`. A CRL that
cannot be verified is not used, and a CRL past its `nextUpdate` counts as stale.

| `-revocation` | Effect |
|---------------|--------|
| `best-effort` (default) | revoked certificates fail; unknown status is reported only |
| `require` | unknown status (no CRL, stale, bad signature) also fails |
| `off` | no checks |

Downloaded CRLs are cached in `~/.cache/tpm2-verifier/crls/` (Windows:
`%LocalAppData%\tpm2-verifier\crls`). The folder layout mirrors the URL, and a
`.json` file next to each CRL records the URL, fetch time and SHA-256:

```
~/.cache/tpm2-verifier/crls/tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
~/.cache/tpm2-verifier/crls/tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl.json
```

A cached CRL is reused for 24 hours and refetched sooner if its `nextUpdate` has passed (with
`If-None-Match`/`If-Modified-Since`). If the download fails, the cached copy
is used with a warning. A CRL with a lower CRL number never replaces a newer
cached one. `-offline` uses the cache only, `-no-fetch` disables all
downloads (CRLs and AIA), `-crl file` adds local CRLs.

## Proving the TPM is genuine (`-prove`)

A trusted chain shows that the EK certificate stored in the TPM was issued
by the vendor. It does not show that the TPM you are talking to is the one
it was issued for: a certificate can be copied into the NV of another TPM,
or of a software TPM. `-prove` (for `info`, `verify`, `debug` and
`debug-anon`) closes that gap for every EK certificate:

1. The EK is created again from its TCG template (`TPM2_CreatePrimary` in the
   endorsement hierarchy; the TPM always derives the same key from its
   endorsement seed) and compared with the public key in the certificate.
   A vendor template in the EK template index and a nonce in the EK nonce
   index (low range) are used as the TCG EK Credential Profile specifies.
2. A random secret is encrypted to the **certificate's** public key
   (MakeCredential, in software) and the TPM is asked to decrypt it with
   `TPM2_ActivateCredential` using the EK. Only a TPM holding the private
   key returns the secret.

```
Possession: PROVEN (TCG template L-1 (RSA 2048), 1.4s)
  the TPM decrypted a credential encrypted to the certificate's public key (TPM2_ActivateCredential)
Verdict: GENUINE: the certificate chains to vendor intel and this TPM holds its private key
```

| Possession | Meaning |
|------------|---------|
| `proven` | the TPM holds the certificate's private key |
| `key-mismatch` | the EK created from the template is another key: the certificate belongs to another TPM, or the vendor uses a non-default EK template |
| `failed` | the TPM reports the certificate's key but cannot use it: an impostor |
| `unsupported` | no proof possible: replayed bundle, SM2 (H-5), unknown index |
| `error` | a TPM command failed, e.g. the endorsement hierarchy has a password (`-endorsement-auth`) |

With `-prove`, the exit status is 0 only if every EK certificate is trusted
**and** proven. Step 1 alone proves nothing (a fake TPM can return any public
key); it tells a wrong template apart from a wrong TPM. The proof needs the
live TPM: replaying a bundle reports `unsupported`, `debug` records the
result in `analysis/possession.json`, `debug-anon` records status and
template, and `vendor import` shows them per observation.

Templates: L-1/L-2 (low range) are the go-tpm reference templates. H-1 to
H-7 (high range) use the PolicyB digests of the TCG EK Credential Profile
2.5; all are tested with swtpm, and L-1, L-2 and H-3 are confirmed on Intel
PTT (firmware 600.15). A wrong template can only cause `key-mismatch`, never
a false `proven`.

Like any local check, this trusts the software on the machine it runs on. To
attest a remote machine, the verifier must run elsewhere and send the
credential to it (remote attestation), which is outside the scope of this
tool.

## Debug bundles for unknown vendors

```bash
sudo tpm2-verifier debug                   # writes tpm2-verifier-debug-<manufacturer>-<time>.tar.gz
tpm2-verifier info -tpm bundle:tpm2-verifier-debug-IFX-20261011-120000.tar.gz   # anywhere, no TPM needed
```

A bundle records everything `tpm2-verifier` reads, so a TPM can be analyzed on
another machine exactly as if it were attached:

| File | Content |
|------|---------|
| `manifest.json` | tool version, OS, kernel, TPM sysfs attributes, DMI vendor/model/BIOS (no serial numbers or UUIDs; `-no-platform` omits all of it) |
| `tpm/properties.json`, `tpm/info.json` | all fixed TPM properties, raw and decoded |
| `tpm/nv.json`, `tpm/nv/*.bin` | every NV index: public area, read errors, content of the readable TCG indices |
| `analysis/summary.txt`, `analysis/report.json` | the `info -v` output and JSON report at creation time |
| `analysis/chains/<index>/<depth>-<source>.der` | every certificate of each EK chain, including those downloaded via AIA |

**Privacy:** the EK certificate uniquely identifies the TPM and thus the
machine. Share bundles only with people you trust with that, or use
`debug-anon`. No secrets, keys or measurements are included.

### Adding a vendor without revealing the TPM (`debug-anon`)

```bash
sudo tpm2-verifier debug-anon -o ifx            # directory; .tar.gz/.tgz writes an archive
tpm2-verifier info -allow-unsigned -store ifx/vendor   # try the draft vendor directory
tpm2-verifier debug-anon -tpm bundle:debug.tar.gz -o ifx.tar.gz   # from an existing bundle
```

`debug-anon` collects only what is needed to build the vendor directory. It
is not replayable, and nothing in it is unique to the TPM:

| File | Content |
|------|---------|
| `info.json` | TPM manufacturer, vendor string, firmware, spec; NV layout (index, attributes, size, readability, key type and CA flag of the certificates in it) without content; per EK the verification status, the chain structure and the chain |
| `certs/<sha256>.der` | the public CA certificates of the chains: from the vendor store or downloaded via AIA |
| `vendor/<id>/` | draft `vendor.yaml`, `README.md` (TPM, NV layout, hierarchy, quirks), `roots/`, `intermediates/` |

Certificates that are not public (the EK and per-device CAs) are only
described by their structure: key and signature algorithm, serial number
length, validity in days, CA flag, key usages, extensions (OID and critical
flag, no values), CRL/AIA/OCSP URLs, policies, TCG TPM attributes and quirks.
Their serial number, key, signature, key identifiers, fingerprint and dates
are not written. In their names, all values except C, O and TCG attributes
are replaced by `REDACTED` for the EK; for CAs only serialNumber, UID and
e-mail values and runs of 8+ hex digits (`-strict`: all values except C and O).
Each EK chain also gets a structure summary: the number of levels and the
type of every level, root first, e.g.
`root(ECDSA P-384) > vendor-ca(ECDSA P-384) x2 > device-ca(ECDSA P-256) x3 > ek(RSA 2048)`
(`vendor-ca`: published, `device-ca`: not published, usually per device).
The issuer name of the last device specific CA is kept, as it names the
vendor CA to look for. The NV content (EK, chain, nonce, templates, platform
certificates) is not included.

A certificate counts as public if it is in the vendor store or published at
the AIA URL of a certificate in the chain. A vendor CA stored in NV and
published nowhere looks device specific; if you know it is shared by all
devices, include it with `-include <sha256>` (the fingerprints are printed,
not written). `-platform` adds the DMI vendor/model strings (no BIOS, no
serials).

Bundles are also test fixtures: every bundle in `testdata/bundles/` is
replayed by the tests and must still produce the status recorded in it.
`testdata/bundles/swtpm-localca.tar.gz` is a swtpm provisioned by
`swtpm_setup`, an example of a vendor that is not in the store.

## Library

```go
import (
	"github.com/tpm2-trust/tpm2-verifier/fetch"
	"github.com/tpm2-trust/tpm2-verifier/possession"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

t, _ := tpm.Open("")                      // /dev/tpmrm0, TBS, or a TCTI spec
defer t.Close()
scan, _ := t.Scan(ctx)                    // identity + all TCG NV indices, parsed
fmt.Println(scan.Info.Manufacturer)       // "INTC"

// vendors/, checked against its MANIFEST, signed by a built-in key
st, _, _ := store.Open("vendors", store.OpenOptions{})
cacheDir, _ := fetch.DefaultCacheDir()
v := verify.New(st, verify.WithCRLFetcher(fetch.New(fetch.WithCacheDir(cacheDir))))

for _, ek := range scan.EKCertificates() {
	rep, _ := v.Verify(ctx, ek.Certificates[0], scan.ChainCertificates())
	fmt.Println(tpm.HexIndex(ek.Index), rep.Status, rep.Vendor) // 0x01C00002 trusted intel
	for _, l := range rep.Chain {
		fmt.Println(l.Subject, l.Source, l.Revocation.Status, l.Revocation.Source)
	}
	// Prove that this TPM holds the EK (pass the EK template and nonce
	// index contents for the low range if the TPM has them).
	if d, ok := t.Backend().(*tpm.Device); ok {
		res := possession.Prove(d.Transport(), ek.Index, ek.Certificates[0].PublicKey, nil, nil, possession.Options{})
		fmt.Println(res.Status) // proven
	}
}
```

Files instead of a TPM: `certparse.Parse(ekDER)`, `certparse.ParseAll(chainBlob)`
(concatenated DER, padding ignored), `certparse.ParseCRL(crlDER)` and
`verify.WithCRLs(...)`. `tpm.Fake` is an in-memory TPM for tests.

| Package     | Purpose |
|-------------|---------|
| `bundle`    | Records a TPM into a debug bundle and replays it as a `tpm.Fake` |
| `vendorinfo` | Collects the non-identifying information to add a vendor (`debug-anon`), with a draft vendor directory |
| `vendorimport` | Reviews submissions (bundles, debug-anon output) and merges them into a vendor directory tree |
| `tpm`       | Reads TPM properties and NV indices (go-tpm, pure Go): Linux device, Windows TBS, swtpm; NV index labels; `Fake` backend |
| `fetch`     | Downloads CRLs (CDP) and issuer certificates (AIA) into the local cache |
| `certparse` | DER chain splitting, certificate parsing with TCG extensions (critical subjectAltName with TPM identity, EK EKU), CRL distribution points with `cRLIssuer`, indirect CRLs, SHA-1 signatures of legacy vendor PKIs |
| `store`     | Loads and validates the vendor trust store (fingerprints, root self-signature, CA flag) |
| `verify`    | Chain building and validation with a per-link report: signature, validity, path length, critical extensions, revocation |
| `possession` | Proof that the TPM holds the EK certificate's private key: EK templates (TCG L-1/L-2, H-1..H-7, NV template and nonce), key comparison, MakeCredential/ActivateCredential |
| `manifest`  | The vendor data MANIFEST (SHA-256 of every file, version) and its SSH signature |

Why not `x509.Certificate.Verify`? EK certificates have an empty subject with a
*critical* subjectAltName that only holds a TCG `directoryName`. The standard
library rejects that as an unhandled critical extension, does not check CRLs,
and returns one error instead of a report per link.

If a vendor uses negative serial numbers, programs using the library need
`//go:debug x509negativeserial=1` in their main package (`tpm2-verifier` has it).

## Vendor data

```
vendors/
├── MANIFEST                        # SHA-256 of every file + version
├── MANIFEST.sig                    # ssh-keygen -Y sign signature of MANIFEST
└── intel/
    ├── vendor.yaml                 # metadata + certificate manifest
    ├── README.md                   # the vendor's PKI hierarchy and quirks
    ├── roots/ondie-ca-root.der
    └── intermediates/
        ├── ondie-ca-csme-intermediate.der
        └── mcc-00001881-issuing-ca.der
```

```yaml
id: intel
name: Intel Corporation
manufacturer_ids: [INTC]           # TPM2_PT_MANUFACTURER
chain_nv_indices: [0x01C00100]     # NV indices with per-device intermediates
accepted_critical_extensions: []   # vendor specific critical extensions to tolerate
certificates:
  - file: roots/ondie-ca-root.der
    role: root                     # root | intermediate
    source: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
    sha256: beb40bb7507b33967226aa80e084749fbb6593893c642e818d682e9a8d07fc24
    retrieved: 2026-10-10
```

Rules: every certificate file must be listed with its SHA-256 and source URL
(enforced by tests); roots must be self-signed CAs. Only roots are trust
anchors; intermediates only help to build chains.

### Where it is found, and how it is checked

Every command that needs the vendor data uses `./vendors`, or the directory
given with `-store`; nothing else is loaded. A missing directory is an error.

The vendor data holds the trust anchors, and it is a directory outside the
binary that someone else may have written (think of `sudo tpm2-verifier` in a
directory you do not own). So before it is used:

1. `MANIFEST` must list exactly the files present, with matching SHA-256.
   It has the `sha256sum` format: `cd vendors && sha256sum -c MANIFEST`.
2. `MANIFEST.sig` must be a valid SSH signature of `MANIFEST` (namespace
   `tpm2-verifier-vendors`) by an ed25519 key listed in
   [`manifest/allowed_signers`](manifest/allowed_signers), which is compiled
   into the binary. The data is read once and used from memory, so files
   changed after the check are not used.

A mismatch or a broken signature is always an error. Data without a
signature by a trusted key (a working copy, a draft vendor directory,
your own CAs) is refused unless you pass `-allow-unsigned`; the hashes are
still checked if there is a `MANIFEST`, and a warning shows the data used.
Without signature the check only guards against accidents: anyone who can
write the directory can also rewrite the `MANIFEST`.

The version in `MANIFEST` is the date of the change (`2026.10.14`, then
`2026.10.14.2`, ...). `tpm2-verifier version` and `store verify` print it
together with the digest of the `MANIFEST` and the signer; debug bundles
record it in `analysis/vendor-data.txt`.

Maintainers, after changing `vendors/` by hand (`vendor import` does this
itself):

```bash
tpm2-verifier store manifest                    # new MANIFEST and version; removes the stale signature
ssh-keygen -Y sign -f ~/.ssh/<key> -n tpm2-verifier-vendors vendors/MANIFEST   # writes MANIFEST.sig
tpm2-verifier store verify                      # OK only if signed by a key in manifest/allowed_signers
# independent of tpm2-verifier:
ssh-keygen -Y verify -f manifest/allowed_signers -I <principal> -n tpm2-verifier-vendors -s vendors/MANIFEST.sig < vendors/MANIFEST
```

The release workflow refuses to release vendor data that `store verify`
does not accept, and publishes it as `tpm2-verifier-vendors-<version>.tar.gz`
and in the packages. Signing happens on the maintainer's machine; the key is
not in CI.

Optional `domains: [tsci.intel.com]` lists the hosts the vendor publishes
certificates on; `vendor import` holds back certificates from other hosts.
`observations.yaml` (generated, not loaded by the store) records the TPMs
seen in submissions; the README of the vendor shows them between generated
markers.

### Extending the vendor data from submissions

Users send `tpm2-verifier debug-anon` output (or, privately, full `debug`
bundles), see [submissions/](submissions/README.md). A pull request that adds a
file to `submissions/` gets an automatic `vendor review` in its CI job
summary; full bundles are refused there (`-anon-only`).

```bash
tpm2-verifier vendor review submissions/x.tar.gz        # read-only: plan and findings
tpm2-verifier vendor import submissions/x.tar.gz        # write vendors/<id>/
tpm2-verifier vendor import -accept <sha256> ...        # approve a root or flagged CA
tpm2-verifier vendor import -fixture testdata/bundles debug.tar.gz   # keep a full bundle as test fixture (with consent)
git diff vendors/
ssh-keygen -Y sign -f ~/.ssh/<key> -n tpm2-verifier-vendors vendors/MANIFEST
```

The import changes `vendors/<id>/`: certificate files in `roots/` and
`intermediates/`; `vendor.yaml`, merged line by line so that comments and
layout stay (new vendors get a generated file with `description: TODO`);
`observations.yaml` (firmware, vendor string, NV layout, chain structure,
quirks; no device data; importing the same TPM twice adds nothing); and the
generated block of `README.md`. It also writes a new `MANIFEST` and removes
the old signature, so the result has to be signed again. If the result does
not load as a store, every change is undone.

Nothing in a submission is trusted:

- every certificate is **downloaded again** from its source URL; it is only
  taken if the vendor serves identical bytes, a different certificate is an
  error that blocks the import;
- **roots are never added automatically**: compare the SHA-256 with one the
  vendor publishes through another channel, then approve it with `-accept`;
- intermediates are added automatically only if they were downloaded again,
  come from one of the vendor's `domains` (new vendors: the domains are taken
  from the accepted certificates), and are signed by a root of the store or
  an approved one;
- certificates read from the TPM need approval even if published, as they
  are usually device specific; so do certificates without a URL;
- the public part of each chain must verify, and the EK's TCG manufacturer
  must match the TPM's (warning otherwise); incomplete chains and unhandled
  critical extensions are reported.

## The manual way: tpm2-tools and openssl

Everything `tpm2-verifier` does can be done by hand. This is also the reference for
what the tool reads.

### 1. Talk to the resource manager

```bash
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
```

The kernel resource manager avoids "out of memory" / busy errors when other
processes use the TPM. Reading NV usually requires root or membership in the
`tss` group.

### 2. Identify the vendor

```bash
tpm2_getcap properties-fixed | grep -A2 -E 'TPM2_PT_(MANUFACTURER|VENDOR_STRING|FIRMWARE_VERSION)'
```

`TPM2_PT_MANUFACTURER` is four ASCII characters, e.g. `INTC` (Intel PTT),
`IFX` (Infineon), `STM` (STMicroelectronics), `NTC` (Nuvoton), `AMD` (AMD fTPM),
`MSFT` (Microsoft/Hyper-V/Pluton), `GOOG` (Google), `IBM` (swtpm/IBM simulator).
`tpm2-verifier store list` shows which ones have a curated root.

### 3. List the NV indices

```bash
tpm2_getcap handles-nv-index   # which indices exist
tpm2_nvreadpublic              # with size and attributes
```

TCG EK Credential Profile indices:

| Index | Content |
|-------|---------|
| `0x01C00002` | RSA 2048 EK certificate (low range) |
| `0x01C00003` / `0x01C00004` | RSA 2048 EK nonce / template |
| `0x01C0000A` | ECC NIST P-256 EK certificate (low range) |
| `0x01C0000B` / `0x01C0000C` | ECC NIST P-256 EK nonce / template |
| `0x01C00012` | RSA 2048 EK certificate (H-1, high range) |
| `0x01C00014` | ECC NIST P-256 EK certificate (H-2) |
| `0x01C00016` / `0x01C00018` | ECC NIST P-384 / P-521 EK certificate (H-3 / H-4) |
| `0x01C0001A` | ECC SM2 P-256 EK certificate (H-5) |
| `0x01C0001C` / `0x01C0001E` | RSA 3072 / RSA 4096 EK certificate (H-6 / H-7) |
| `0x01C00100` - `0x01C001FF` | EK certificate chain: concatenated DER intermediates (Intel uses `0x01C00100`) |
| `0x01C08000` - `0x01C0FFFF` | Platform certificates |

### 4. Read the EK certificate(s)

```bash
tpm2_nvread -C o -o ek-rsa.der 0x01C00002
tpm2_nvread -C o -o ek-ecc.der 0x01C0000A
```

If owner read is not permitted, try index authorization: `tpm2_nvread -C 0x01C00002 ...`.
`tpm2_getekcertificate -o ek-rsa.der -o ek-ecc.der` reads the same indices. On
older Intel PTT the certificate is not in NV at all; `tpm2_getekcertificate`
can download it from Intel's online EK service instead (see its man page).

Some vendors pad the index; openssl reads only the first certificate and
ignores the rest, so this is harmless.

### 5. Read and split the per-device chain (Intel)

```bash
tpm2_nvread -C o -o chain.der 0x01C00100
```

The index holds concatenated DER certificates followed by padding. Each
certificate starts with `30 82 <2 byte length>`. Without any tool:

```bash
# list the top-level elements: offset, header length and content length
openssl asn1parse -inform der -in chain.der 2>/dev/null | grep 'd=0'
#     0:d=0  hl=4 l= 524 cons: SEQUENCE
#   528:d=0  hl=4 l= 612 cons: SEQUENCE
#  ...   (an error at the end is the padding)

# cut them out
n=3
openssl asn1parse -inform der -in chain.der 2>/dev/null | grep 'd=0' |
  sed -E 's/^ *([0-9]+):d=0 +hl= *([0-9]+) +l= *([0-9]+).*/\1 \2 \3/' |
  while read off hl len; do
    dd if=chain.der of=intel-int$n.der bs=1 skip=$off count=$((hl+len)) status=none
    n=$((n+1))
  done
```

### 6. Inspect and walk up via AIA

```bash
openssl x509 -inform der -in intel-int3.der -noout -subject -issuer -ext authorityInfoAccess,crlDistributionPoints
```

`CA Issuers - URI:` (AIA) points to the issuer certificate. Download it and
repeat until you reach a self-signed certificate (subject == issuer):

```bash
curl -sSO https://tsci.intel.com/content/OnDieCA/certs/MCC_00001881_OnDie_CA.cer
openssl x509 -inform der -in MCC_00001881_OnDie_CA.cer -noout -subject -issuer -ext authorityInfoAccess
```

**A root downloaded over AIA proves nothing on its own.** Compare its
fingerprint with the vendor store before trusting it:

```bash
openssl x509 -inform der -in OnDie_CA_RootCA_Certificate.cer -noout -fingerprint -sha256
grep -r sha256 vendors/*/vendor.yaml
```

### 7. CRLs

`X509v3 CRL Distribution Points` names the CRL that lists the certificate.

```bash
curl -sSO https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
openssl crl -inform der -in OnDie_CA_CSME_Indirect.crl -noout -text
# check the CRL signature with its issuer
openssl crl -inform der -in OnDie_CA_CSME_Indirect.crl -CAfile ondie-ca-csme-intermediate.der -noout
```

If the distribution point has a `CRL Issuer`, the CRL is signed by that CA
rather than by the certificate's issuer: an *indirect CRL* (Intel's per-device
CAs use one). openssl needs `-extended_crl` for those.

### 8. Verify the chain

```bash
tpm2-verifier store export -o certs intel     # or use the files in vendors/intel/
openssl verify -show_chain \
  -trusted certs/intel/roots/ondie-ca-root.der \
  -untrusted certs/intel/intermediates/ondie-ca-csme-intermediate.der \
  -untrusted certs/intel/intermediates/mcc-00001881-issuing-ca.der \
  -untrusted intel-int3.der -untrusted intel-int4.der -untrusted intel-int5.der \
  ek-rsa.der

# with revocation checks (all CRLs of the chain, indirect CRLs enabled)
openssl verify -show_chain -crl_check_all -extended_crl \
  -CRLfile OnDie_CA.crl -CRLfile OnDie_CA_CSME_Product.crl \
  -CRLfile MCC_00001881_OnDie_CA.crl -CRLfile OnDie_CA_CSME_Indirect.crl \
  -trusted ... -untrusted ... ek-rsa.der
```

### 9. Prove that the TPM holds the EK

```bash
# Create the EK from the default template; compare its key with the certificate's
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_readpublic -c ek.ctx -f pem -o ek.pem
openssl x509 -in ek-rsa.der -inform DER -pubkey -noout > ekcert-key.pem
cmp ek.pem ekcert-key.pem && echo "EK matches the certificate"

# A key to bind the credential to (null hierarchy)
tpm2_createprimary -C n -G ecc -c obj.ctx
tpm2_readpublic -c obj.ctx -n obj.name

# Encrypt a random secret to the CERTIFICATE's key, in software
head -c 32 /dev/urandom > secret.bin
tpm2_makecredential -T none -u ekcert-key.pem -G rsa -s secret.bin \
  -n "$(xxd -p -c 256 obj.name)" -o cred.bin

# Let the TPM decrypt it with the EK (low range EKs need PolicySecret(endorsement))
tpm2_startauthsession --policy-session -S session.ctx
tpm2_policysecret -S session.ctx -c e
tpm2_activatecredential -c obj.ctx -C ek.ctx -i cred.bin -o actual.bin -P "session:session.ctx"
tpm2_flushcontext session.ctx
cmp secret.bin actual.bin && echo "PROVEN: this TPM holds the EK of the certificate"
```

Tested with tpm2-tools 5 against swtpm (without a resource manager, run
`tpm2_flushcontext -t` between the commands). For the ECC EK use `-G ecc`.

## Roadmap

| Phase | Content | State |
|-------|---------|-------|
| 0 | Repository, vendor store format, Intel migrated | done |
| 1 | `certparse` + `verify`, offline verification of files, CLI `inspect`/`split`/`verify`/`store` | done |
| 1b | CRLs fetched from the distribution points, signature checked, cached locally | done |
| 2 | Read the TPM directly (pure Go, `/dev/tpmrm0`, Windows TBS, swtpm): `tpm2-verifier info` / `verify` / `export` | done |
| 3 | Debug bundle for unknown vendors (`tpm2-verifier debug`), replayable with `-tpm bundle:` and as test fixture; `debug-anon` with a draft vendor directory | done |
| 4 | Walk AIA up to the root for vendors without a stored chain | done |
| 4b | Submissions: `vendor review`/`import`, observations, CI review of `submissions/` | done |
| 4c | Vendor data as a directory next to the binary, with a versioned, SSH-signed `MANIFEST` | done |
| 5 | More vendors: Infineon, STMicro, Nuvoton, AMD fTPM, Microsoft, Google | next |
| 6 | Proof of EK possession (`-prove`): recreate the EK from its template, MakeCredential/ActivateCredential | done |
| 7 | EK certificates not stored in NV (AMD fTPM, older Intel PTT: download from the vendor's EK service by EK public key) | open |

## Development

```bash
go test ./...
```

Tests need no hardware TPM:

- the Intel root and static intermediates and Intel's published CRLs
  (`testdata/intel/crls`) are real-world fixtures,
- `internal/testpki` generates a synthetic hierarchy with the same shape as
  Intel's (seven levels, empty EK subject, critical TCG subjectAltName,
  indirect CRL),
- if [swtpm](https://github.com/stefanberger/swtpm) is installed, the TPM
  code is tested against it end to end (provisioned NV indices, chunked
  reads, authorization rules, `info`/`verify`/`export`/`debug`); otherwise
  those tests are skipped,
- debug bundles in `testdata/bundles/` are replayed as regression fixtures.

Real EK certificates identify a device, so they are not committed.

## License

MIT, see [LICENSE](LICENSE).
