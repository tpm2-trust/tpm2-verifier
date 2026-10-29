// Package ekroots is the curated store of TPM vendors' endorsement key
// (EK) roots, for every program that checks a TPM's EK certificate: the
// phone app (through tpm2-kira's core), tpm2-kira, its vault and
// tpm2-verifier's own command. The vendor data of vendors/ - per vendor its
// roots, the intermediates its TPMs do not carry, vendor.yaml - is embedded
// at build time, and checked at load against its MANIFEST (the SHA-256 of
// every file) and, once manifest/allowed_signers names a key, against the
// signature MANIFEST.sig: data that does not match is never used. Nothing
// is added at runtime; a newer vendor directory next to tpm2-verifier's
// binary is the command's own matter (store.Open).
//
// A check has three outcomes. Verified: the chain ends at a root of the
// TPM's vendor. VendorUnknown: the store has no root of the TPM's vendor
// yet - not untrusted, a risk to weigh, until the vendor is added. Failed:
// the vendor is known and the chain does not verify.
package ekroots

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/manifest"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

//go:embed vendors
var embedded embed.FS

// Origin names the embedded data in results and errors.
const Origin = "tpm2-verifier/ekroots (embedded)"

var load = sync.OnceValues(func() (*loaded, error) {
	sub, err := fs.Sub(embedded, "vendors")
	if err != nil {
		return nil, err
	}
	signers, err := manifest.TrustedSigners()
	if err != nil {
		return nil, err
	}
	res, err := manifest.VerifyFS(sub, Origin, signers)
	if err != nil {
		return nil, fmt.Errorf("the embedded EK roots: %w", err)
	}
	// With signing keys built in, only signed data is used; before any
	// key is named, the manifest's hashes alone bind the data to this build.
	if len(signers) > 0 && !res.Trusted() {
		return nil, fmt.Errorf("the embedded EK roots are not signed by a trusted key (%s)", res.Describe())
	}
	st := store.New()
	if err := st.AddFS(res.FS, Origin); err != nil {
		return nil, err
	}
	return &loaded{store: st, data: res}, nil
})

type loaded struct {
	store *store.Store
	data  *manifest.Result
}

// Data describes the embedded data: its version, its files, who signed it.
func Data() (*manifest.Result, error) {
	l, err := load()
	if err != nil {
		return nil, err
	}
	return l.data, nil
}

// Store is the embedded vendor store.
func Store() (*store.Store, error) {
	l, err := load()
	if err != nil {
		return nil, err
	}
	return l.store, nil
}

// Vendors are the names of the vendors whose roots are in the store.
func Vendors() []string {
	st, err := Store()
	if err != nil {
		return nil
	}
	return vendorNames(st)
}

func vendorNames(st *store.Store) []string {
	var out []string
	for _, v := range st.Vendors() {
		out = append(out, v.Name)
	}
	return out
}

// Certificates are the DER encodings of every root and intermediate in
// the store: what completes a chain a TPM sends only in part.
func Certificates() [][]byte {
	st, err := Store()
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, e := range st.Entries() {
		out = append(out, e.Cert.Raw)
	}
	return out
}

// Status is a check's outcome.
type Status string

const (
	// Verified: the chain ends at a root of the TPM's vendor.
	Verified Status = "verified"
	// VendorUnknown: the store has no root of the TPM's vendor - not
	// untrusted, a risk to weigh, until the vendor is added.
	VendorUnknown Status = "vendor not known"
	// Failed: the vendor is known and its chain does not verify.
	Failed Status = "failed"
)

// Result is a check's outcome.
type Result struct {
	Status Status
	// Vendor is the vendor's name (Verified, Failed), or with
	// VendorUnknown the TPM's manufacturer ID as its certificate names it.
	Vendor string
	// Detail says why, for a person.
	Detail string
	// Report is tpm2-verifier's full report, when the chain was built.
	Report *verify.Report
}

// Check verifies the EK certificate leaf (DER) with the intermediates the
// TPM gave (DER), offline: against the embedded roots and intermediates, no
// download, no revocation list.
func Check(leaf []byte, intermediates [][]byte, now time.Time) Result {
	st, err := Store()
	if err != nil {
		return Result{Status: Failed, Detail: err.Error()}
	}
	return CheckWith(st, leaf, intermediates, now)
}

// CheckWith is Check against st: a vendor directory tpm2-verifier's
// command was given (store.Open), or a test's.
func CheckWith(st *store.Store, leaf []byte, intermediates [][]byte, now time.Time) Result {
	lc, err := certparse.Parse(leaf)
	if err != nil {
		return Result{Status: Failed, Detail: fmt.Sprintf("the EK certificate does not parse: %v", err)}
	}
	var inter []*certparse.Certificate
	for _, b := range intermediates {
		c, err := certparse.Parse(b)
		if err != nil {
			return Result{Status: Failed, Detail: fmt.Sprintf("an intermediate certificate does not parse: %v", err)}
		}
		inter = append(inter, c)
	}
	rep, err := verify.New(st, verify.WithTime(now)).Verify(context.Background(), lc, inter)
	if err != nil {
		return Result{Status: Failed, Detail: err.Error()}
	}
	if rep.Status == verify.StatusTrusted {
		name := rep.Vendor
		if v := st.Vendor(rep.Vendor); v != nil {
			name = v.Name
		}
		return Result{Status: Verified, Vendor: name, Report: rep}
	}
	manufacturer := ""
	if lc.TPM != nil {
		manufacturer = lc.TPM.Manufacturer
	}
	// The vendor is the one the certificate names, or the one whose store
	// certificate the chain reached: either way a known vendor's chain that
	// does not verify fails.
	vendor := st.VendorForManufacturer(manufacturer)
	for _, l := range rep.Chain {
		if vendor == nil && l.StoreEntry != nil {
			vendor = l.StoreEntry.Vendor
		}
	}
	if vendor == nil {
		who := manufacturer
		if who == "" {
			who = "unnamed in its certificate"
		}
		return Result{Status: VendorUnknown, Vendor: manufacturer, Report: rep,
			Detail: fmt.Sprintf("the TPM's vendor (%s) is not in the EK root store yet (known: %s): not untrusted - not verified, a risk to weigh",
				who, strings.Join(vendorNames(st), ", "))}
	}
	why := append(append([]string{}, rep.Problems...), rep.Hints...)
	if len(why) == 0 {
		why = []string{string(rep.Status)}
	}
	return Result{Status: Failed, Vendor: vendor.Name, Report: rep,
		Detail: fmt.Sprintf("a %s TPM whose EK certificate does not verify: %s", vendor.Name, strings.Join(why, "; "))}
}
