# tpm2-verifier

A pure Go library and CLI (`tpm2-ek`) to inspect and verify TPM 2.0
endorsement key (EK) certificates and their vendor certificate chains, with a
curated, fingerprint-pinned store of TPM vendor root CAs.

It is the Go successor of [intel-ek-dechainer](https://github.com/mrwiora/intel-ek-dechainer)
and does everything it did (split the per-device chain from NV, verify against
the Intel OnDie CA) for any vendor, plus CRL checks including indirect CRLs.

> **Status:** phases 0 and 1 of the roadmap are done: vendor store, parsing and
> offline verification of files. Reading the TPM directly is next; until then,
> read the NV indices with tpm2-tools as described [below](#the-manual-way-tpm2-tools-and-openssl).

## Install

```bash
go install github.com/mrwiora/tpm2-verifier/cmd/tpm2-ek@latest
```

No cgo, no openssl needed. Linux first; it builds and runs on Windows too.

## CLI

```bash
# Read the EK certificate and the Intel per-device chain (see the manual section)
tpm2_nvread -C o -o ek.der 0x01C00002
tpm2_nvread -C o -o chain.der 0x01C00100

# Verify in one step: EK -> NV chain -> store intermediates -> store root
tpm2-ek verify ek.der chain.der

# ... with revocation checks against downloaded CRLs (fetching is on the roadmap)
tpm2-ek verify -v -revocation require -crl OnDie_CA.crl -crl OnDie_CA_CSME_Product.crl \
  -crl MCC_00001881_OnDie_CA.crl -crl OnDie_CA_CSME_Indirect.crl ek.der chain.der

tpm2-ek inspect ek.der chain.der some.crl   # details, AIA/CDP URLs, TCG quirks, store matches
tpm2-ek split -o out chain.der              # one file per certificate
tpm2-ek split -p intel-int -s 3 chain.der   # intel-ek-dechainer naming: intel-int3..5.der
tpm2-ek store list | show intel | export -o certs
```

Example output:

```
ek.der: TRUSTED (vendor intel)
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

`verify` exits with 0 if trusted, 1 if not (`untrusted-root`, `incomplete`,
`revoked`, `invalid`) and 2 on errors. `-json` prints a machine readable report.

## Library

```go
import (
	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/store"
	"github.com/mrwiora/tpm2-verifier/verify"
)

st, _ := store.Default()                 // embedded vendors + local overlay
ek, _ := certparse.Parse(ekDER)          // TCG aware: ek.TPM.Manufacturer == "INTC"
chain, _ := certparse.ParseAll(nvChain)  // concatenated DER from NV 0x01C00100, padding ignored
crl, _ := certparse.ParseCRL(crlDER)     // handles indirect CRLs

rep, _ := verify.New(st, verify.WithCRLs(crl)).Verify(ctx, ek, chain)
if rep.Status == verify.StatusTrusted { /* rep.Vendor == "intel" */ }
for _, l := range rep.Chain { fmt.Println(l.Subject, l.Source, l.Revocation.Status) }
```

| Package     | Purpose |
|-------------|---------|
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
| 2 | Read the TPM directly (pure Go, `/dev/tpmrm0`, Windows TBS): `tpm2-ek info` / `export` in one shot | next |
| 3 | Debug bundle for unknown vendors (`tpm2-ek debug`), replayable as a fake TPM for tests | |
| 4 | Online: walk AIA up to the root, fetch CRLs from CDPs, cache | |
| 5 | More vendors: Infineon, STMicro, Nuvoton, AMD fTPM, Microsoft, Google | |

## Development

```bash
go test ./...
```

Tests run without a TPM: the Intel root and static intermediates and Intel's
published CRLs (`testdata/intel/crls`) are used as real-world fixtures, and
`internal/testpki` generates a synthetic hierarchy with the same shape as
Intel's (seven levels, empty EK subject, critical TCG subjectAltName, indirect
CRL). Real EK certificates identify a device, so they are not committed.

## License

MIT, see [LICENSE](LICENSE).
