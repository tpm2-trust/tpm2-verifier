package certparse_test

import (
	"bytes"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/internal/testpki"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func intelStatic(t *testing.T) [][]byte {
	return [][]byte{
		readFile(t, "../vendors/intel/intermediates/mcc-00001881-issuing-ca.der"),
		readFile(t, "../vendors/intel/intermediates/ondie-ca-csme-intermediate.der"),
		readFile(t, "../vendors/intel/roots/ondie-ca-root.der"),
	}
}

func TestSplitDERRealIntelWithPadding(t *testing.T) {
	parts := intelStatic(t)
	blob := bytes.Join(parts, nil)
	blob = append(blob, bytes.Repeat([]byte{0xff}, 100)...)

	got, err := certparse.SplitDER(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(parts) {
		t.Fatalf("got %d elements, want %d", len(got), len(parts))
	}
	for i := range parts {
		if !bytes.Equal(got[i], parts[i]) {
			t.Errorf("element %d differs", i)
		}
	}
}

func TestSplitDERSyntheticDeviceChain(t *testing.T) {
	pki := testpki.IntelLike(t)
	certs, err := certparse.ParseAll(pki.DeviceChain())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CN=CSME MCC ROM CA", "CN=CSME MCC SVN01 Kernel CA", "CN=CSME MCC PTT 01SVN"}
	if len(certs) != len(want) {
		t.Fatalf("got %d certificates, want %d", len(certs), len(want))
	}
	for i, c := range certs {
		if c.SubjectString() != want[i] {
			t.Errorf("cert %d subject %q, want %q", i, c.SubjectString(), want[i])
		}
	}
}

func TestSplitDERErrors(t *testing.T) {
	root := intelStatic(t)[2]
	cases := map[string][]byte{
		"truncated":  root[:len(root)-10],
		"garbage":    append(append([]byte{}, root...), 0x02, 0x01, 0x00),
		"indefinite": {0x30, 0x80, 0x00, 0x00},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := certparse.SplitDER(in)
			var se *certparse.SplitError
			if !errors.As(err, &se) {
				t.Fatalf("want SplitError, got %v", err)
			}
		})
	}
}

func TestSplitAnyPEM(t *testing.T) {
	var buf bytes.Buffer
	for _, der := range intelStatic(t) {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	got, err := certparse.SplitAny(buf.Bytes())
	if err != nil || len(got) != 3 {
		t.Fatalf("got %d, %v", len(got), err)
	}
}

func TestParseSyntheticEK(t *testing.T) {
	pki := testpki.IntelLike(t)
	ek, err := certparse.Parse(pki.EK.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ek.IsEK {
		t.Error("IsEK not set")
	}
	if ek.TPM == nil || ek.TPM.Manufacturer != "INTC" || ek.TPM.Model != "PTT" {
		t.Errorf("TPM info = %+v", ek.TPM)
	}
	if len(ek.UnhandledCriticalExtensions) != 0 {
		t.Errorf("unhandled critical extensions left: %v", ek.UnhandledCriticalExtensions)
	}
	for _, q := range []string{certparse.QuirkEmptySubject, certparse.QuirkTCGSubjectAltName} {
		if !ek.HasQuirk(q) {
			t.Errorf("missing quirk %s", q)
		}
	}
	if ek.SubjectString() != "<empty>" {
		t.Errorf("subject %q", ek.SubjectString())
	}
}

func TestParseDistributionPointWithCRLIssuer(t *testing.T) {
	pki := testpki.IntelLike(t)
	k, err := certparse.Parse(pki.Kernel.Cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.DistributionPoints) != 1 {
		t.Fatalf("got %d distribution points", len(k.DistributionPoints))
	}
	dp := k.DistributionPoints[0]
	if len(dp.URIs) != 1 || dp.URIs[0] != testpki.URLIndirectCRL {
		t.Errorf("URIs = %v", dp.URIs)
	}
	if len(dp.CRLIssuer) != 1 || !certparse.SameName(dp.CRLIssuer[0], pki.Int1.Cert.RawSubject) {
		t.Errorf("CRLIssuer does not name Int1")
	}
}

func TestParseRealIntel(t *testing.T) {
	for _, der := range intelStatic(t) {
		c, err := certparse.Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Quirks) != 0 {
			t.Errorf("%s: unexpected quirks %v", c.SubjectString(), c.Quirks)
		}
	}
	root, _ := certparse.Parse(intelStatic(t)[2])
	if !root.IsSelfSigned() {
		t.Error("root not self-signed")
	}
}

func TestParseRealIntelCRLs(t *testing.T) {
	want := map[string]bool{
		"OnDie_CA.crl":               false,
		"OnDie_CA_CSME_Product.crl":  false,
		"MCC_00001881_OnDie_CA.crl":  false,
		"OnDie_CA_CSME_Indirect.crl": true,
	}
	for name, indirect := range want {
		crl, err := certparse.ParseCRL(readFile(t, filepath.Join("../testdata/intel/crls", name)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if crl.Indirect != indirect {
			t.Errorf("%s: Indirect = %v, want %v", name, crl.Indirect, indirect)
		}
	}
}

func TestIndirectCRLLookup(t *testing.T) {
	pki := testpki.IntelLike(t)
	crls := pki.CRLs(t, pki.Kernel.Cert, pki.EK)
	crl, err := certparse.ParseCRL(crls[testpki.URLIndirectCRL])
	if err != nil {
		t.Fatal(err)
	}
	if !crl.Indirect {
		t.Fatal("not indirect")
	}
	if _, ok := crl.Lookup(pki.Kernel.Cert.SerialNumber, pki.ROM.Cert.RawSubject); !ok {
		t.Error("kernel CA not found as revoked by ROM CA")
	}
	if _, ok := crl.Lookup(pki.EK.SerialNumber, pki.PTT.Cert.RawSubject); !ok {
		t.Error("EK not found as revoked by PTT CA")
	}
	// Same serial, wrong issuer: must not match.
	if _, ok := crl.Lookup(pki.Kernel.Cert.SerialNumber, pki.PTT.Cert.RawSubject); ok {
		t.Error("matched entry with wrong issuer")
	}
	if _, ok := crl.Lookup(pki.PTT.Cert.SerialNumber, pki.Kernel.Cert.RawSubject); ok {
		t.Error("non revoked PTT CA reported as revoked")
	}
}

func TestDecodeManufacturer(t *testing.T) {
	for in, want := range map[string]string{
		"id:494E5443": "INTC",
		"id:49465800": "IFX",
		"id:53544D20": "STM",
		"Nuvoton":     "Nuvoton",
		"id:00001014": "id:00001014", // swtpm: numeric vendor ID
		"id:zz":       "id:zz",
	} {
		if got := certparse.DecodeManufacturer(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}
