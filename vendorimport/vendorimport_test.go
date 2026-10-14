package vendorimport_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/bundle"
	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/fetch"
	"github.com/tpm2-trust/tpm2-verifier/internal/testpki"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/vendorimport"
	"github.com/tpm2-trust/tpm2-verifier/vendorinfo"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

var ctx = context.Background()

// web serves certificates like a vendor's web server.
type web map[string][]byte

func (w web) FetchCertificates(_ context.Context, url string) (*fetch.CertResult, error) {
	der, ok := w[url]
	if !ok {
		return nil, errors.New("404")
	}
	c, err := certparse.Parse(der)
	if err != nil {
		return nil, err
	}
	return &fetch.CertResult{URL: url, Certificates: []*certparse.Certificate{c}}, nil
}

type fixture struct {
	pki  *testpki.IntelChain
	fake *tpm.Fake
	web  web
	dir  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pki := testpki.IntelLike(t)
	f := &tpm.Fake{Properties: map[uint32]uint32{tpm.PTManufacturer: 0x53594E00, tpm.PTFirmwareVersion1: 0x00010002}} // "SYN"
	f.SetCertificate(0x01C00002, pki.EK.Raw)
	f.SetCertificate(0x01C00100, pki.DeviceChain())
	// The vendor publishes its static CAs, not the per-device ones.
	w := web{}
	for _, ca := range []*testpki.CA{pki.Root, pki.Int1, pki.Int2} {
		w[testpki.AIAURL(ca.Cert)] = ca.Cert.Raw
	}
	return &fixture{pki: pki, fake: f, web: w, dir: t.TempDir()}
}

func fp(c *x509.Certificate) string {
	p, _ := certparse.Parse(c.Raw)
	return p.Fingerprint
}

// anon writes debug-anon output for the fixture's TPM, as a contributor
// would, and returns its path.
func (f *fixture) anon(t *testing.T) string {
	t.Helper()
	s, err := tpm.New(f.fake).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New()
	v := verify.New(st, verify.WithTime(f.pki.Now), verify.WithAIAFetcher(f.web))
	var eks []vendorinfo.EKReport
	for _, e := range s.EKCertificates() {
		rep, err := v.Verify(ctx, e.Certificates[0], s.ChainCertificates())
		if err != nil {
			t.Fatal(err)
		}
		eks = append(eks, vendorinfo.EKReport{Index: e.Index, Report: rep})
	}
	info, err := vendorinfo.Build(s, eks, st, vendorinfo.Options{Tool: "test", Published: vendorinfo.Published(ctx, s, eks, f.web)})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "anon.tar.gz")
	var buf bytes.Buffer
	if err := info.WriteArchive(&buf); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, buf.Bytes(), 0o644)
	return p
}

func (f *fixture) review(t *testing.T, path string, accept ...string) *vendorimport.Plan {
	t.Helper()
	sub, err := vendorimport.Load(ctx, path, store.New(), f.web, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := vendorimport.Review(ctx, sub, f.opts(accept...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) opts(accept ...string) vendorimport.Options {
	return vendorimport.Options{Vendors: f.dir, Fetcher: f.web, Accept: accept, Now: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)}
}

func pending(p *vendorimport.Plan) map[string]string {
	out := map[string]string{}
	for _, c := range p.Certificates {
		if !c.Accepted {
			out[c.Subject] = c.Pending
		}
	}
	return out
}

func TestNewVendor(t *testing.T) {
	f := newFixture(t)
	sub := f.anon(t)

	// Without approval of the root nothing is added.
	p := f.review(t, sub)
	if !p.NewVendor || p.VendorID != "syn" || len(p.Certificates) != 3 || len(p.Accepted()) != 0 || p.HasErrors() {
		t.Fatalf("plan %+v findings %+v", p, p.Findings)
	}
	for subj, why := range pending(p) {
		if strings.Contains(subj, "Root") && !strings.Contains(why, "roots need approval") ||
			!strings.Contains(subj, "Root") && !strings.Contains(why, "issuer") {
			t.Errorf("%s pending: %s", subj, why)
		}
	}

	// With the root approved, the intermediates follow.
	p = f.review(t, sub, fp(f.pki.Root.Cert))
	if len(p.Accepted()) != 3 {
		t.Fatalf("accepted %d, pending %v", len(p.Accepted()), pending(p))
	}
	changed, err := p.Apply(f.opts())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"syn/README.md", "syn/intermediates/on-die-csme-p-mcc-00001881-issuing-ca.der", "syn/intermediates/ondie-ca-csme-intermediate-ca.der",
		"syn/observations.yaml", "syn/roots/ondie-ca-root-cert-signing.der", "syn/vendor.yaml"}
	if strings.Join(changed, " ") != strings.Join(want, " ") {
		t.Errorf("changed %v", changed)
	}
	y, _ := os.ReadFile(filepath.Join(f.dir, "syn", "vendor.yaml"))
	for _, w := range []string{"manufacturer_ids: [SYN]", "chain_nv_indices: [0x01C00100]", "domains: [aia.example]", "role: root"} {
		if !strings.Contains(string(y), w) {
			t.Errorf("vendor.yaml lacks %q:\n%s", w, y)
		}
	}
	readme, _ := os.ReadFile(filepath.Join(f.dir, "syn", "README.md"))
	if !strings.Contains(string(readme), "| 1.2.0.0 |") || !strings.Contains(string(readme), "device-ca(ECDSA P-256) x3 > ek(ECDSA P-256)") {
		t.Errorf("README:\n%s", readme)
	}

	// The EK now verifies with the vendor directory alone.
	st, err := store.LoadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := verify.New(st, verify.WithTime(f.pki.Now)).Verify(ctx, mustParse(t, f.pki.EK.Raw), mustParseAll(t, f.pki.DeviceChain()))
	if rep.Status != verify.StatusTrusted || rep.Vendor != "syn" {
		t.Errorf("status %s %v", rep.Status, rep.Problems)
	}

	// Importing the same submission again changes nothing.
	p = f.review(t, sub)
	if p.Changes() || len(p.Certificates) != 0 {
		t.Errorf("second import: %+v", p)
	}
}

func TestMergeExistingVendor(t *testing.T) {
	f := newFixture(t)
	// The vendor exists with its root, domains and hand-written comments.
	os.MkdirAll(filepath.Join(f.dir, "syn", "roots"), 0o755)
	os.WriteFile(filepath.Join(f.dir, "syn", "roots", "root.der"), f.pki.Root.Cert.Raw, 0o644)
	orig := `id: syn
name: Synthetic
# keep this comment
manufacturer_ids: [SYN]  # and this one
description: >-
  A long description that is folded over
  two lines and must stay like this.
domains:
  - aia.example
certificates:
  - file: roots/root.der
    role: root
    sha256: ` + fp(f.pki.Root.Cert) + `

# trailing comment
`
	os.WriteFile(filepath.Join(f.dir, "syn", "vendor.yaml"), []byte(orig), 0o644)

	p := f.review(t, f.anon(t))
	if p.NewVendor || len(p.Accepted()) != 2 || len(p.Domains) != 0 {
		t.Fatalf("accepted %d, pending %v, domains %v, findings %v", len(p.Accepted()), pending(p), p.Domains, p.Findings)
	}
	if _, err := p.Apply(f.opts()); err != nil {
		t.Fatal(err)
	}
	y, _ := os.ReadFile(filepath.Join(f.dir, "syn", "vendor.yaml"))
	got := string(y)
	// Every original line is still there, in order; only lines were added.
	rest := got
	for _, l := range strings.Split(orig, "\n") {
		i := strings.Index(rest, l)
		if i < 0 {
			t.Fatalf("line %q lost or reordered:\n%s", l, got)
		}
		rest = rest[i+len(l):]
	}
	if !strings.Contains(got, "chain_nv_indices: [0x01C00100]\ncertificates:") ||
		!strings.Contains(got, "    sha256: "+fp(f.pki.Root.Cert)+"\n  - file: intermediates/") {
		t.Errorf("unexpected merge:\n%s", got)
	}
}

// TestPublishedDeviceCAs: CAs read from the TPM need approval even if the
// vendor publishes them.
func TestPublishedDeviceCAs(t *testing.T) {
	f := newFixture(t)
	f.web = web(f.pki.AIAFiles())
	p := f.review(t, f.anon(t), fp(f.pki.Root.Cert))
	if len(p.Certificates) != 6 || len(p.Accepted()) != 3 || !strings.Contains(pending(p)["CN=CSME MCC ROM CA"], "read from the TPM") {
		t.Errorf("%d candidates, %d accepted, pending %v", len(p.Certificates), len(p.Accepted()), pending(p))
	}
}

func TestDownloadMismatch(t *testing.T) {
	f := newFixture(t)
	sub := f.anon(t)
	f.web[testpki.AIAURL(f.pki.Int1.Cert)] = f.pki.Int2.Cert.Raw // the vendor serves something else
	p := f.review(t, sub, fp(f.pki.Root.Cert), fp(f.pki.Int1.Cert))
	if !p.HasErrors() || !strings.Contains(pending(p)[f.pki.Int1.Cert.Subject.String()], "different certificate") {
		t.Errorf("findings %v pending %v", p.Findings, pending(p))
	}
	if _, err := p.Apply(f.opts()); err == nil {
		t.Error("applied despite errors")
	}
}

func TestForeignDomain(t *testing.T) {
	f := newFixture(t)
	os.MkdirAll(filepath.Join(f.dir, "syn", "roots"), 0o755)
	os.WriteFile(filepath.Join(f.dir, "syn", "roots", "root.der"), f.pki.Root.Cert.Raw, 0o644)
	os.WriteFile(filepath.Join(f.dir, "syn", "vendor.yaml"), []byte("id: syn\nname: S\nmanufacturer_ids: [SYN]\ndomains: [vendor.example]\ncertificates:\n  - file: roots/root.der\n    role: root\n    sha256: "+fp(f.pki.Root.Cert)+"\n"), 0o644)
	p := f.review(t, f.anon(t))
	if len(p.Accepted()) != 0 || !strings.Contains(pending(p)[f.pki.Int1.Cert.Subject.String()], "not in the domains") {
		t.Errorf("pending %v", pending(p))
	}
	// Approval overrides it.
	p = f.review(t, f.anon(t), fp(f.pki.Int1.Cert), fp(f.pki.Int2.Cert))
	if len(p.Accepted()) != 2 || len(p.Domains) != 1 {
		t.Errorf("accepted %d domains %v", len(p.Accepted()), p.Domains)
	}
}

func TestBundleSubmission(t *testing.T) {
	f := newFixture(t)
	b, err := bundle.Collect(ctx, f.fake, bundle.CollectOptions{Tool: "test", NoPlatform: true})
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest.Created = f.pki.Now
	path := filepath.Join(t.TempDir(), "debug.tar.gz")
	if err := b.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	sub, err := vendorimport.Load(ctx, path, store.New(), f.web, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Kind != vendorimport.KindBundle || sub.Bundle == nil || len(sub.Info.Certificates) != 3 {
		t.Fatalf("kind %s, %d certificates", sub.Kind, len(sub.Info.Certificates))
	}
	p, err := vendorimport.Review(ctx, sub, f.opts(fp(f.pki.Root.Cert)))
	if err != nil || len(p.Accepted()) != 3 {
		t.Fatalf("%v, accepted %d", err, len(p.Accepted()))
	}

	if _, err := vendorimport.Load(ctx, "vendorimport_test.go", store.New(), nil, nil); err == nil {
		t.Error("garbage accepted")
	}
}

func mustParse(t *testing.T, der []byte) *certparse.Certificate {
	t.Helper()
	c, err := certparse.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustParseAll(t *testing.T, data []byte) []*certparse.Certificate {
	t.Helper()
	c, err := certparse.ParseAll(data)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
