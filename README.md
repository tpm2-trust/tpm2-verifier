# tpm2-verifier

A pure Go library and CLI (`tpm2-ek`) to inspect and verify TPM 2.0
endorsement key (EK) certificates and their vendor certificate chains, with a
curated, fingerprint-pinned store of TPM vendor root CAs.

It is the Go successor of [intel-ek-dechainer](https://github.com/mrwiora/intel-ek-dechainer)
and does everything it did (split the per-device chain from NV, verify against
the Intel OnDie CA) for any vendor. It also reads the TPM directly, completes
chains via AIA, and checks every certificate of the chain against the CRLs
named in its distribution points, including indirect CRLs. CRLs are cached
locally, and their signatures are verified. For TPMs of unknown vendors it
writes a debug bundle that can be replayed and analyzed anywhere.

## Install

```bash
go install github.com/mrwiora/tpm2-verifier/cmd/tpm2-ek@latest
```

No cgo, no openssl needed. Linux first; it builds and runs on Windows too.

## CLI

```bash
# Everything in one go: vendor, firmware, all NV indices, every EK certificate
# verified up to the vendor root, every CA checked against its CRL
tpm2-ek info            # -v for attributes, fingerprints, CRL details; -json

tpm2-ek verify          # only the verification of the EK certificates in the TPM
tpm2-ek export -o out   # EK certs, chain, raw NV, vendor CAs + matching openssl command
tpm2-ek debug           # debug bundle for unknown vendors / bug reports (see below)
tpm2-ek debug-anon      # what is needed to add the vendor, without identifying data

# The same for files, e.g. read with tpm2-tools (see the manual section)
tpm2-ek verify ek.der chain.der
tpm2-ek inspect ek.der chain.der some.crl   # details, AIA/CDP URLs, TCG quirks, store matches
tpm2-ek split -o out chain.der              # one file per certificate
tpm2-ek split -p intel-int -s 3 chain.der   # intel-ek-dechainer naming: intel-int3..5.der

tpm2-ek store list | show intel | export -o certs
tpm2-ek cache list | clear | path

# Maintainers: turn submissions into vendor store changes (see below)
tpm2-ek vendor review submissions/x.tar.gz
tpm2-ek vendor import -accept <sha256> submissions/x.tar.gz
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

Expected output of `tpm2-ek verify` on an Intel PTT machine (format illustration):

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

## Debug bundles for unknown vendors

```bash
sudo tpm2-ek debug                   # writes tpm2-ek-debug-<manufacturer>-<time>.tar.gz
tpm2-ek info -tpm bundle:tpm2-ek-debug-IFX-20261011-120000.tar.gz   # anywhere, no TPM needed
```

A bundle records everything `tpm2-ek` reads, so a TPM can be analyzed on
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
sudo tpm2-ek debug-anon -o ifx            # directory; .tar.gz/.tgz writes an archive
tpm2-ek info -store ifx/vendor            # try the draft vendor directory
tpm2-ek debug-anon -tpm bundle:debug.tar.gz -o ifx.tar.gz   # from an existing bundle
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
	"github.com/mrwiora/tpm2-verifier/fetch"
	"github.com/mrwiora/tpm2-verifier/store"
	"github.com/mrwiora/tpm2-verifier/tpm"
	"github.com/mrwiora/tpm2-verifier/verify"
)

t, _ := tpm.Open("")                      // /dev/tpmrm0, TBS, or a TCTI spec
defer t.Close()
scan, _ := t.Scan(ctx)                    // identity + all TCG NV indices, parsed
fmt.Println(scan.Info.Manufacturer)       // "INTC"

st, _ := store.Default()                  // embedded vendors + local overlay
cacheDir, _ := fetch.DefaultCacheDir()
v := verify.New(st, verify.WithCRLFetcher(fetch.New(fetch.WithCacheDir(cacheDir))))

for _, ek := range scan.EKCertificates() {
	rep, _ := v.Verify(ctx, ek.Certificates[0], scan.ChainCertificates())
	fmt.Println(tpm.HexIndex(ek.Index), rep.Status, rep.Vendor) // 0x01C00002 trusted intel
	for _, l := range rep.Chain {
		fmt.Println(l.Subject, l.Source, l.Revocation.Status, l.Revocation.Source)
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
| `vendors`   | The embedded store data |

Why not `x509.Certificate.Verify`? EK certificates have an empty subject with a
*critical* subjectAltName that only holds a TCG `directoryName`. The standard
library rejects that as an unhandled critical extension, does not check CRLs,
and returns one error instead of a report per link.

If a vendor uses negative serial numbers, programs using the library need
`//go:debug x509negativeserial=1` in their main package (`tpm2-ek` has it).

## Vendor store

```
vendors/
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

**Local overlay:** the same layout in `~/.config/tpm2-verifier/vendors/`
(`%AppData%\tpm2-verifier\vendors` on Windows) or a directory passed with
`-store` is loaded on top of the embedded store. A vendor with an existing ID is
merged (certificates added). Use it for vendors that are not curated yet.

Optional `domains: [tsci.intel.com]` lists the hosts the vendor publishes
certificates on; `vendor import` holds back certificates from other hosts.
`observations.yaml` (generated, not loaded by the store) records the TPMs
seen in submissions; the README of the vendor shows them between generated
markers.

### Extending the vendor store from submissions

Users send `tpm2-ek debug-anon` output (or, privately, full `debug`
bundles), see [submissions/](submissions/README.md). A pull request that adds a
file to `submissions/` gets an automatic `vendor review` in its CI job
summary; full bundles are refused there (`-anon-only`).

```bash
tpm2-ek vendor review submissions/x.tar.gz        # read-only: plan and findings
tpm2-ek vendor import submissions/x.tar.gz        # write vendors/<id>/
tpm2-ek vendor import -accept <sha256> ...        # approve a root or flagged CA
tpm2-ek vendor import -fixture testdata/bundles debug.tar.gz   # keep a full bundle as test fixture (with consent)
git diff vendors/
```

The import changes `vendors/<id>/`: certificate files in `roots/` and
`intermediates/`; `vendor.yaml`, merged line by line so that comments and
layout stay (new vendors get a generated file with `description: TODO`);
`observations.yaml` (firmware, vendor string, NV layout, chain structure,
quirks; no device data; importing the same TPM twice adds nothing); and the
generated block of `README.md`. If the result does not load as a store,
every change is undone.

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

Everything `tpm2-ek` does can be done by hand. This is also the reference for
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
`tpm2-ek store list` shows which ones have a curated root.

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
tpm2-ek store export -o certs intel     # or use the files in vendors/intel/
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

## Roadmap

| Phase | Content | State |
|-------|---------|-------|
| 0 | Repository, vendor store format, Intel migrated | done |
| 1 | `certparse` + `verify`, offline verification of files, CLI `inspect`/`split`/`verify`/`store` | done |
| 1b | CRLs fetched from the distribution points, signature checked, cached locally | done |
| 2 | Read the TPM directly (pure Go, `/dev/tpmrm0`, Windows TBS, swtpm): `tpm2-ek info` / `verify` / `export` | done |
| 3 | Debug bundle for unknown vendors (`tpm2-ek debug`), replayable with `-tpm bundle:` and as test fixture; `debug-anon` with a draft vendor directory | done |
| 4 | Walk AIA up to the root for vendors without a stored chain | done |
| 4b | Submissions: `vendor review`/`import`, observations, CI review of `submissions/` | done |
| 5 | More vendors: Infineon, STMicro, Nuvoton, AMD fTPM, Microsoft, Google | next |

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
