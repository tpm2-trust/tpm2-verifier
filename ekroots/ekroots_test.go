package ekroots

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/internal/testpki"
	"github.com/tpm2-trust/tpm2-verifier/manifest"
	"github.com/tpm2-trust/tpm2-verifier/store"
)

// The embedded data loads: every file is in the manifest with its hash,
// signed once allowed_signers names a key, and the store has Intel's root.
func TestEmbeddedData(t *testing.T) {
	d, err := Data()
	if err != nil {
		t.Fatal(err)
	}
	signers, _ := manifest.TrustedSigners()
	if len(signers) > 0 && !d.Trusted() {
		t.Fatalf("signing keys are built in, the data is %s", d.Describe())
	}
	if d.Files == 0 || d.Version == "" {
		t.Fatalf("data %s", d.Describe())
	}
	st, err := Store()
	if err != nil {
		t.Fatal(err)
	}
	if v := st.VendorForManufacturer("INTC"); v == nil || len(v.Roots()) == 0 {
		t.Fatal("no Intel root in the store")
	}
	if len(Certificates()) < 3 || len(Vendors()) == 0 {
		t.Fatalf("%d certificates, vendors %v", len(Certificates()), Vendors())
	}
}

// A chain of a vendor the store has, ending at its root: verified. The
// same vendor's TPM whose chain ends elsewhere: failed. A TPM of a vendor
// the store does not have: vendor not known - not a failure.
func TestCheck(t *testing.T) {
	pki := testpki.IntelLike(t)
	ek := pki.IssueEK(t, nil)
	now := ek.NotBefore.Add(time.Hour)
	device := chainCerts(t, pki.DeviceChain())

	if r := CheckWith(storeOf(t, pki), ek.Raw, device, now); r.Status != Verified || r.Vendor != "Test Vendor" {
		t.Fatalf("its own vendor's chain: %+v", r)
	}
	// The embedded store has Intel, not this synthetic root.
	if r := Check(ek.Raw, device, now); r.Status != Failed || r.Vendor != "Intel Corporation" || r.Detail == "" {
		t.Fatalf("an INTC TPM whose chain is not Intel's: %+v", r)
	}

	other := testpki.NewRoot(t, pkix.Name{CommonName: "Unknown Vendor EK Root"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	unknown := other.Issue(t, &x509.Certificate{
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		ExtraExtensions: []pkix.Extension{testpki.TPMSubjectAltName("id:58595A00", "X", "id:00010000")},
	})
	r := Check(unknown.Raw, nil, now)
	if r.Status != VendorUnknown || !strings.Contains(r.Detail, "not untrusted") {
		t.Fatalf("a vendor not in the store: %+v", r)
	}
	if r := Check([]byte("not a certificate"), nil, now); r.Status != Failed {
		t.Fatalf("garbage: %+v", r)
	}
}

func chainCerts(t *testing.T, chain []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(chain) > 0 && chain[0] == 0x30 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(chain, &raw)
		if err != nil {
			break
		}
		out = append(out, raw.FullBytes)
		chain = rest
	}
	return out
}

// storeOf is a store of the synthetic hierarchy's static part, the way
// vendors/intel holds the real one.
func storeOf(t *testing.T, pki *testpki.IntelChain) *store.Store {
	t.Helper()
	fsys := fstest.MapFS{}
	var y strings.Builder
	y.WriteString("id: testvendor\nname: Test Vendor\nmanufacturer_ids: [INTC]\ncertificates:\n")
	for name, c := range map[string]struct {
		cert *x509.Certificate
		role string
	}{"root.der": {pki.Root.Cert, "root"}, "int1.der": {pki.Int1.Cert, "intermediate"}, "int2.der": {pki.Int2.Cert, "intermediate"}} {
		sum := sha256.Sum256(c.cert.Raw)
		fsys["testvendor/"+name] = &fstest.MapFile{Data: c.cert.Raw}
		fmt.Fprintf(&y, "  - file: %s\n    role: %s\n    source: test\n    sha256: %s\n", name, c.role, hex.EncodeToString(sum[:]))
	}
	fsys["testvendor/vendor.yaml"] = &fstest.MapFile{Data: []byte(y.String())}
	st := store.New()
	if err := st.AddFS(fsys, "test"); err != nil {
		t.Fatal(err)
	}
	return st
}
