package verify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/fetch"
	"github.com/mrwiora/tpm2-verifier/internal/testpki"
	"github.com/mrwiora/tpm2-verifier/store"
	"github.com/mrwiora/tpm2-verifier/verify"
)

var ctx = context.Background()

func mustParse(t *testing.T, der []byte) *certparse.Certificate {
	t.Helper()
	c, err := certparse.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustParseAll(t *testing.T, der []byte) []*certparse.Certificate {
	t.Helper()
	c, err := certparse.ParseAll(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustCRL(t *testing.T, der []byte) *certparse.CRL {
	t.Helper()
	c, err := certparse.ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testStore builds a store containing the static part of a synthetic
// hierarchy, the way vendors/intel does for the real one.
func testStore(t *testing.T, pki *testpki.IntelChain, extraYAML string) *store.Store {
	t.Helper()
	fsys := fstest.MapFS{}
	var y strings.Builder
	y.WriteString("id: testvendor\nname: Test Vendor\nmanufacturer_ids: [INTC]\nchain_nv_indices: [0x01C00100]\n" + extraYAML + "certificates:\n")
	for name, c := range map[string]struct {
		cert *x509.Certificate
		role string
	}{
		"root.der": {pki.Root.Cert, "root"},
		"int1.der": {pki.Int1.Cert, "intermediate"},
		"int2.der": {pki.Int2.Cert, "intermediate"},
	} {
		sum := sha256.Sum256(c.cert.Raw)
		fsys["testvendor/"+name] = &fstest.MapFile{Data: c.cert.Raw}
		fmt.Fprintf(&y, "  - file: %s\n    role: %s\n    source: test\n    sha256: %s\n", name, c.role, hex.EncodeToString(sum[:]))
	}
	fsys["testvendor/vendor.yaml"] = &fstest.MapFile{Data: []byte(y.String())}
	var s store.Store
	if err := s.AddFS(fsys, "test"); err != nil {
		t.Fatal(err)
	}
	return &s
}

func crlList(t *testing.T, m map[string][]byte) []*certparse.CRL {
	var out []*certparse.CRL
	for _, der := range m {
		out = append(out, mustCRL(t, der))
	}
	return out
}

func wantStatus(t *testing.T, r *verify.Report, want verify.Status) {
	t.Helper()
	if r.Status != want {
		var b strings.Builder
		for i, l := range r.Chain {
			fmt.Fprintf(&b, "  depth=%d %s %v %+v\n", i, l.Subject, l.Problems, l.Revocation)
		}
		t.Fatalf("status %s, want %s; problems %v hints %v\n%s", r.Status, want, r.Problems, r.Hints, b.String())
	}
}

func TestRealIntelStaticChainWithCRLs(t *testing.T) {
	s, err := store.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	int2 := mustParse(t, s.Vendor("intel").Intermediates()[1].Cert.Raw)
	var crls []*certparse.CRL
	for _, n := range []string{"OnDie_CA.crl", "OnDie_CA_CSME_Product.crl", "MCC_00001881_OnDie_CA.crl", "OnDie_CA_CSME_Indirect.crl"} {
		b, err := os.ReadFile(filepath.Join("../testdata/intel/crls", n))
		if err != nil {
			t.Fatal(err)
		}
		crls = append(crls, mustCRL(t, b))
	}
	v := verify.New(s, verify.WithCRLs(crls...), verify.WithRevocation(verify.RevocationRequire),
		verify.WithTime(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)))
	r, err := v.Verify(ctx, int2, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, r, verify.StatusTrusted)
	if r.Vendor != "intel" || len(r.Chain) != 3 {
		t.Fatalf("vendor %q, chain length %d", r.Vendor, len(r.Chain))
	}
	for _, l := range r.Chain[:2] {
		if l.Revocation.Status != verify.RevocationGood {
			t.Errorf("%s: revocation %+v", l.Subject, l.Revocation)
		}
	}
}

func TestSyntheticIntelFullChain(t *testing.T) {
	pki := testpki.IntelLike(t)
	s := testStore(t, pki, "")
	v := verify.New(s, verify.WithTime(pki.Now), verify.WithCRLs(crlList(t, pki.CRLs(t))...),
		verify.WithRevocation(verify.RevocationRequire))
	r, err := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, r, verify.StatusTrusted)
	if len(r.Chain) != 7 {
		t.Fatalf("chain length %d, want 7", len(r.Chain))
	}
	wantSources := []verify.Source{"leaf", "provided", "provided", "provided", "store", "store", "store"}
	for i, l := range r.Chain {
		if l.Source != wantSources[i] {
			t.Errorf("depth %d source %s, want %s", i, l.Source, wantSources[i])
		}
	}
	if !r.Chain[6].Anchor || r.Vendor != "testvendor" || r.TPM.Manufacturer != "INTC" {
		t.Errorf("anchor %v vendor %q tpm %+v", r.Chain[6].Anchor, r.Vendor, r.TPM)
	}
	if len(r.Hints) != 0 {
		t.Errorf("unexpected hints %v", r.Hints)
	}
	// The kernel CA and the EK are checked against the indirect CRL.
	for _, d := range []int{0, 2} {
		if rv := r.Chain[d].Revocation; rv.Status != verify.RevocationGood || !strings.Contains(rv.CRLIssuer, "OnDie CA CSME Intermediate CA") {
			t.Errorf("depth %d revocation %+v", d, rv)
		}
	}
}

func TestMissingDeviceChain(t *testing.T) {
	pki := testpki.IntelLike(t)
	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now)).Verify(ctx, mustParse(t, pki.EK.Raw), nil)
	wantStatus(t, r, verify.StatusIncomplete)
	if !strings.Contains(strings.Join(r.Hints, "\n"), "0x01C00100") {
		t.Errorf("hints do not mention the chain NV index: %v", r.Hints)
	}
}

func TestRevokedViaIndirectCRL(t *testing.T) {
	pki := testpki.IntelLike(t)
	v := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithCRLs(crlList(t, pki.CRLs(t, pki.Kernel.Cert))...))
	r, _ := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusRevoked)
	if r.Chain[2].Revocation.Status != verify.RevocationRevoked {
		t.Errorf("kernel CA: %+v", r.Chain[2].Revocation)
	}
	if r.Chain[0].Revocation.Status != verify.RevocationGood {
		t.Errorf("EK: %+v", r.Chain[0].Revocation)
	}
}

func TestRevokedEK(t *testing.T) {
	pki := testpki.IntelLike(t)
	v := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithCRLs(crlList(t, pki.CRLs(t, pki.EK))...))
	r, _ := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusRevoked)
	if r.Chain[0].Revocation.Status != verify.RevocationRevoked {
		t.Errorf("EK: %+v", r.Chain[0].Revocation)
	}
}

func TestStaleCRL(t *testing.T) {
	pki := testpki.IntelLike(t)
	crls := crlList(t, pki.CRLs(t))
	later := pki.Now.AddDate(1, 0, 0)

	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(later), verify.WithCRLs(crls...)).
		Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusTrusted) // best effort
	if r.Chain[0].Revocation.Status != verify.RevocationUnknown || !strings.Contains(r.Chain[0].Revocation.Detail, "stale") {
		t.Errorf("EK: %+v", r.Chain[0].Revocation)
	}

	r, _ = verify.New(testStore(t, pki, ""), verify.WithTime(later), verify.WithCRLs(crls...), verify.WithRevocation(verify.RevocationRequire)).
		Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusInvalid)
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "revocation status") {
		t.Errorf("problems %v", r.Problems)
	}
}

// A CRL signed by a look-alike CA (same name, different key) must not be
// accepted, even when the look-alike certificate is passed in.
func TestForgedCRLIgnored(t *testing.T) {
	pki := testpki.IntelLike(t)
	evilRoot := testpki.NewRoot(t, pkix.Name{CommonName: "evil"}, pki.Root.Cert.NotBefore, pki.Root.Cert.NotAfter)
	fakeInt1 := evilRoot.IssueCA(t, pki.Int1.Cert.Subject)
	crls := pki.CRLs(t, pki.EK)
	crls[testpki.URLIndirectCRL] = fakeInt1.CRL(t, 99, pki.Now.AddDate(0, -1, 0), pki.Now.AddDate(0, 1, 0), nil, testpki.IndirectIDP(testpki.URLIndirectCRL))

	chain := append(mustParseAll(t, pki.DeviceChain()), mustParse(t, fakeInt1.Cert.Raw))
	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithCRLs(crlList(t, crls)...)).
		Verify(ctx, mustParse(t, pki.EK.Raw), chain)
	if got := r.Chain[0].Revocation.Status; got != verify.RevocationUnknown {
		t.Fatalf("EK revocation %s (%s), want unknown", got, r.Chain[0].Revocation.Detail)
	}
}

func TestUntrustedRoot(t *testing.T) {
	pki := testpki.IntelLike(t)
	other := testpki.IntelLike(t)
	all := append(mustParseAll(t, pki.DeviceChain()), mustParse(t, pki.Int2.Cert.Raw), mustParse(t, pki.Int1.Cert.Raw), mustParse(t, pki.Root.Cert.Raw))
	r, _ := verify.New(testStore(t, other, ""), verify.WithTime(pki.Now)).Verify(ctx, mustParse(t, pki.EK.Raw), all)
	wantStatus(t, r, verify.StatusUntrustedRoot)
	if len(r.Chain) != 7 || !strings.Contains(strings.Join(r.Hints, "\n"), r.Chain[6].Fingerprint) {
		t.Errorf("chain %d, hints %v", len(r.Chain), r.Hints)
	}
}

func TestExpired(t *testing.T) {
	pki := testpki.IntelLike(t)
	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now.AddDate(50, 0, 0))).
		Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusInvalid)
	for _, l := range r.Chain {
		if len(l.Problems) != 1 || !strings.HasPrefix(l.Problems[0], "expired at") {
			t.Errorf("%s: problems %v", l.Subject, l.Problems)
		}
	}
}

func TestVendorCriticalExtension(t *testing.T) {
	pki := testpki.IntelLike(t)
	oid := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 5, 5, 1, 1}
	svn := pkix.Extension{Id: oid, Critical: true, Value: []byte{0x02, 0x01, 0x01}}
	pki.Kernel = pki.ROM.IssueCA(t, pki.Kernel.Cert.Subject, svn)
	pki.PTT = pki.Kernel.IssueCA(t, pki.PTT.Cert.Subject)
	pki.EK = pki.PTT.Issue(t, &x509.Certificate{NotBefore: pki.Now.AddDate(-1, 0, 0), NotAfter: pki.Now.AddDate(1, 0, 0)})

	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now)).
		Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusInvalid)
	if p := r.Chain[2].Problems; len(p) != 1 || !strings.Contains(p[0], "unhandled critical extension 1.2.840.113741.1.5.5.1.1") {
		t.Errorf("kernel CA problems %v", p)
	}

	r, _ = verify.New(testStore(t, pki, "accepted_critical_extensions: [1.2.840.113741.1.5.5.1.1]\n"), verify.WithTime(pki.Now)).
		Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusTrusted)
}

// crlTransport serves CRLs by URL without network access.
type crlTransport map[string][]byte

func (m crlTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := m[r.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

func fetcherFor(t *testing.T, pki *testpki.IntelChain, crls map[string][]byte) *fetch.Fetcher {
	return fetch.New(fetch.WithClient(&http.Client{Transport: crlTransport(crls)}),
		fetch.WithCacheDir(t.TempDir()), fetch.WithTime(pki.Now))
}

func TestFetchedCRLs(t *testing.T) {
	pki := testpki.IntelLike(t)
	v := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithRevocation(verify.RevocationRequire),
		verify.WithCRLFetcher(fetcherFor(t, pki, pki.CRLs(t))))
	r, _ := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusTrusted)
	ek := r.Chain[0].Revocation
	if ek.Source != testpki.URLIndirectCRL || ek.Origin != "network" || ek.SignedBy != mustParse(t, pki.Int1.Cert.Raw).Fingerprint {
		t.Errorf("EK revocation %+v", ek)
	}
	// Every non-anchor certificate was checked against a fetched CRL.
	for _, l := range r.Chain[:6] {
		if l.Revocation.Status != verify.RevocationGood || !strings.HasPrefix(l.Revocation.Source, "https://") {
			t.Errorf("%s: %+v", l.Subject, l.Revocation)
		}
	}
}

func TestFetchedCRLRevoked(t *testing.T) {
	pki := testpki.IntelLike(t)
	v := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now),
		verify.WithCRLFetcher(fetcherFor(t, pki, pki.CRLs(t, pki.ROM.Cert))))
	r, _ := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusRevoked)
	if r.Chain[3].Revocation.Status != verify.RevocationRevoked {
		t.Errorf("ROM CA: %+v", r.Chain[3].Revocation)
	}
}

func TestTamperedCRLSignatureRejected(t *testing.T) {
	pki := testpki.IntelLike(t)
	crls := pki.CRLs(t)
	bad := bytes.Clone(crls[testpki.URLIndirectCRL])
	bad[len(bad)-3] ^= 0x01 // inside the signature value
	crls[testpki.URLIndirectCRL] = bad

	v := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithRevocation(verify.RevocationRequire),
		verify.WithCRLFetcher(fetcherFor(t, pki, crls)))
	r, _ := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusInvalid)
	ek := r.Chain[0].Revocation
	if ek.Status != verify.RevocationUnknown || !strings.Contains(ek.Detail, "signature verification failed") {
		t.Errorf("EK revocation %+v", ek)
	}
	if r.Chain[3].Revocation.Status != verify.RevocationGood {
		t.Errorf("ROM CA (direct CRL) should still be good: %+v", r.Chain[3].Revocation)
	}
}

func TestCRLDownloadFailure(t *testing.T) {
	pki := testpki.IntelLike(t)
	v := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now),
		verify.WithCRLFetcher(fetcherFor(t, pki, map[string][]byte{})))
	r, _ := v.Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusTrusted) // best effort
	if d := r.Chain[0].Revocation.Detail; !strings.Contains(d, "404") {
		t.Errorf("detail %q", d)
	}
}

// Without the NV chain, the per-device CAs are downloaded via AIA.
func TestAIACompletesChain(t *testing.T) {
	pki := testpki.IntelLike(t)
	f := fetcherFor(t, pki, pki.AIAFiles())
	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithAIAFetcher(f)).
		Verify(ctx, mustParse(t, pki.EK.Raw), nil)
	wantStatus(t, r, verify.StatusTrusted)
	want := []verify.Source{"leaf", "aia", "aia", "aia", "store", "store", "store"}
	for i, l := range r.Chain {
		if l.Source != want[i] {
			t.Errorf("depth %d: source %s, want %s", i, l.Source, want[i])
		}
	}
	if len(r.AIA) != 3 {
		t.Errorf("AIA log %+v", r.AIA)
	}
}

// An unknown vendor: the chain is completed up to a root via AIA, but the
// downloaded root is not trusted.
func TestAIAUnknownRootNotTrusted(t *testing.T) {
	pki := testpki.IntelLike(t)
	other := testpki.IntelLike(t)
	f := fetcherFor(t, pki, pki.AIAFiles())
	r, _ := verify.New(testStore(t, other, ""), verify.WithTime(pki.Now), verify.WithAIAFetcher(f)).
		Verify(ctx, mustParse(t, pki.EK.Raw), nil)
	wantStatus(t, r, verify.StatusUntrustedRoot)
	root := r.Chain[len(r.Chain)-1]
	if len(r.Chain) != 7 || root.Source != verify.SourceAIA || root.Anchor {
		t.Fatalf("chain %d, root %+v", len(r.Chain), root)
	}
	if !strings.Contains(strings.Join(r.Hints, "\n"), root.Fingerprint) {
		t.Errorf("hints %v", r.Hints)
	}
}

// A downloaded root identical to a store root is the store's trust anchor:
// here the store has only the root, and the AIA URL for Int1 serves Int1
// together with the root (like a .p7c bundle would).
func TestAIARootFromStoreTrusted(t *testing.T) {
	pki := testpki.IntelLike(t)
	sum := sha256.Sum256(pki.Root.Cert.Raw)
	var s store.Store
	if err := s.AddFS(fstest.MapFS{
		"v/root.der":    {Data: pki.Root.Cert.Raw},
		"v/vendor.yaml": {Data: []byte("id: v\nmanufacturer_ids: [V]\ncertificates:\n  - {file: root.der, role: root, source: t, sha256: " + hex.EncodeToString(sum[:]) + "}\n")},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	files := pki.AIAFiles()
	files[testpki.AIAURL(pki.Int1.Cert)] = append(bytes.Clone(pki.Int1.Cert.Raw), pki.Root.Cert.Raw...)

	r, _ := verify.New(&s, verify.WithTime(pki.Now), verify.WithAIAFetcher(fetcherFor(t, pki, files))).
		Verify(ctx, mustParse(t, pki.EK.Raw), mustParseAll(t, pki.DeviceChain()))
	wantStatus(t, r, verify.StatusTrusted)
	root := r.Chain[len(r.Chain)-1]
	if !root.Anchor || root.Source != verify.SourceStore {
		t.Errorf("root %+v", root)
	}
	if r.Chain[4].Source != verify.SourceAIA || r.Chain[5].Source != verify.SourceAIA {
		t.Errorf("Int2/Int1 not from AIA: %s %s", r.Chain[4].Source, r.Chain[5].Source)
	}
}

func TestAIAFetchErrorLogged(t *testing.T) {
	pki := testpki.IntelLike(t)
	f := fetcherFor(t, pki, map[string][]byte{})
	r, _ := verify.New(testStore(t, pki, ""), verify.WithTime(pki.Now), verify.WithAIAFetcher(f)).
		Verify(ctx, mustParse(t, pki.EK.Raw), nil)
	wantStatus(t, r, verify.StatusIncomplete)
	if len(r.AIA) != 1 || !strings.Contains(r.AIA[0].Error, "404") {
		t.Errorf("AIA log %+v", r.AIA)
	}
}
