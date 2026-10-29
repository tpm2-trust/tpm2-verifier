package vendorinfo_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/fetch"
	"github.com/tpm2-trust/tpm2-verifier/internal/testpki"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/vendorinfo"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

var ctx = context.Background()

// aia serves certificates like a vendor's web server.
type aia map[string][]byte

func (a aia) FetchCertificates(_ context.Context, url string) (*fetch.CertResult, error) {
	c, err := certparse.Parse(a[url])
	if err != nil {
		return nil, err
	}
	return &fetch.CertResult{URL: url, Certificates: []*certparse.Certificate{c}, Origin: fetch.OriginNetwork}, nil
}

type fixture struct {
	pki   *testpki.IntelChain
	cloud *x509.Certificate
	scan  *tpm.Scan
	eks   []vendorinfo.EKReport
	st    *store.Store
	pub   map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pki := testpki.IntelLike(t)
	// A second EK with identifying names, like cloud vTPMs have.
	cloud := pki.PTT.Issue(t, &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes([]byte{0x7f, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
		Subject:      pkix.Name{Organization: []string{"Cloud Inc"}, CommonName: "instance-4711-secret", SerialNumber: "SN0042"},
		NotBefore:    pki.PTT.Cert.NotBefore,
		NotAfter:     pki.PTT.Cert.NotAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}, Value: []byte{0x0C, 6, 's', 'e', 'c', 'r', 'e', 't'}},
		},
	})
	f := &tpm.Fake{Properties: map[uint32]uint32{tpm.PTManufacturer: 0x53594E00}} // "SYN"
	f.SetCertificate(0x01C00002, pki.EK.Raw)
	f.SetCertificate(0x01C0000A, cloud.Raw)
	f.SetCertificate(0x01C0000B, []byte("nonce-0123456789"))
	f.SetCertificate(0x01C00100, pki.DeviceChain())
	s, err := tpm.New(f).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadDir("../ekroots/vendors")
	if err != nil {
		t.Fatal(err)
	}
	files := aia(pki.AIAFiles())
	v := verify.New(st, verify.WithTime(pki.Now), verify.WithAIAFetcher(files))
	fx := &fixture{pki: pki, cloud: cloud, scan: s, st: st, pub: map[string]string{}}
	for _, e := range s.EKCertificates() {
		rep, err := v.Verify(ctx, e.Certificates[0], s.ChainCertificates())
		if err != nil {
			t.Fatal(err)
		}
		fx.eks = append(fx.eks, vendorinfo.EKReport{Index: e.Index, Report: rep})
	}
	for _, ca := range []*testpki.CA{pki.Root, pki.Int1, pki.Int2} {
		fx.pub[fingerprint(t, ca.Cert)] = testpki.AIAURL(ca.Cert)
	}
	return fx
}

func fingerprint(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	p, err := certparse.Parse(c.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return p.Fingerprint
}

func TestBuild(t *testing.T) {
	fx := newFixture(t)
	info, err := vendorinfo.Build(fx.scan, fx.eks, fx.st, vendorinfo.Options{Tool: "test", Published: fx.pub})
	if err != nil {
		t.Fatal(err)
	}
	files, err := info.Files()
	if err != nil {
		t.Fatal(err)
	}

	// Nothing that identifies the TPM.
	var all bytes.Buffer
	for _, d := range files {
		all.Write(d)
	}
	pki := fx.pki
	for _, c := range []*x509.Certificate{pki.EK, fx.cloud, pki.ROM.Cert, pki.Kernel.Cert, pki.PTT.Cert} {
		fp := fingerprint(t, c)
		for name, s := range map[string][]byte{
			"key": c.RawSubjectPublicKeyInfo, "signature": c.Signature, "fingerprint": []byte(fp),
			"skid": []byte(hex.EncodeToString(c.SubjectKeyId)), "serial": []byte(c.SerialNumber.Text(16)),
		} {
			if len(s) >= 4 && bytes.Contains(all.Bytes(), s) {
				t.Errorf("output contains %s of %q", name, c.Subject)
			}
		}
	}
	for _, s := range []string{"instance-4711", "SN0042", "secret", "nonce-0123"} {
		if bytes.Contains(all.Bytes(), []byte(s)) {
			t.Errorf("output contains %q", s)
		}
	}

	// The public part is complete.
	if info.Draft != "vendor/syn" || len(info.Certificates) != 3 {
		t.Fatalf("draft %s, %d certificates", info.Draft, len(info.Certificates))
	}
	ek := info.EK[0]
	if ek.Status != verify.StatusUntrustedRoot || len(ek.Chain) != 7 {
		t.Fatalf("EK %s, %d links", ek.Status, len(ek.Chain))
	}
	leaf, ptt, root := ek.Chain[0], ek.Chain[3], ek.Chain[6]
	if leaf.Public || leaf.SHA256 != "" || leaf.NotBefore != nil || leaf.TPM == nil || leaf.TPM.Manufacturer != "INTC" ||
		leaf.CRLs[0] != testpki.URLIndirectCRL || leaf.CRLIssuers[0] != pki.Int1.Cert.Subject.String() {
		t.Errorf("EK description %+v", leaf)
	}
	if ptt.Subject != "CN=CSME MCC ROM CA" || ptt.Issuer != pki.Int2.Cert.Subject.String() || !ptt.CA {
		t.Errorf("ROM CA: %s issued by %s", ptt.Subject, ptt.Issuer)
	}
	if !root.Public || root.URL != testpki.AIAURL(pki.Root.Cert) || root.File == "" {
		t.Errorf("root %+v", root)
	}
	cloud := info.EK[1].Chain[0]
	if cloud.Subject != "SERIALNUMBER=REDACTED,CN=REDACTED,O=Cloud Inc" || !cloud.Redacted || cloud.SerialLength != 10 {
		t.Errorf("cloud EK: %s, serial length %d", cloud.Subject, cloud.SerialLength)
	}
	var sawExt bool
	for _, e := range cloud.Extensions {
		sawExt = sawExt || e.OID == "1.3.6.1.4.1.11129.2.1.21"
	}
	if !sawExt {
		t.Error("private extension not listed")
	}
	for _, n := range info.NV {
		if n.Index == "0x01C00100" && (len(n.Certificates) != 3 || n.Certificates[0].Public || n.Certificates[0].SHA256 != "") {
			t.Errorf("chain index %+v", n)
		}
	}

	// The draft directory works as store overlay: the original EK chain is
	// trusted with it.
	dir := t.TempDir()
	if err := info.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	y, _ := os.ReadFile(filepath.Join(dir, "vendor/syn/vendor.yaml"))
	for _, want := range []string{"manufacturer_ids: [SYN]", "chain_nv_indices: [0x01C00100]", "role: root", "source: \"https://aia.example/"} {
		if !strings.Contains(string(y), want) {
			t.Errorf("vendor.yaml lacks %q:\n%s", want, y)
		}
	}
	st, err := store.LoadDir("../ekroots/vendors")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddFS(os.DirFS(filepath.Join(dir, "vendor")), "draft"); err != nil {
		t.Fatalf("draft does not load: %v\n%s", err, y)
	}
	rep, err := verify.New(st, verify.WithTime(pki.Now)).Verify(ctx, fx.scan.EKCertificates()[0].Certificates[0], fx.scan.ChainCertificates())
	if err != nil || rep.Status != verify.StatusTrusted || rep.Vendor != "syn" {
		t.Errorf("with draft: %v %s %v", err, rep.Status, rep.Problems)
	}
	readme, _ := os.ReadFile(filepath.Join(dir, "vendor/syn/README.md"))
	if !strings.Contains(string(readme), "device specific (from the TPM)") || !strings.Contains(string(readme), "0x01C00100") {
		t.Errorf("README:\n%s", readme)
	}

	var buf bytes.Buffer
	if err := info.WriteArchive(&buf); err != nil || buf.Len() == 0 {
		t.Fatal(err)
	}
}

func TestBuildInclude(t *testing.T) {
	fx := newFixture(t)
	rom := fingerprint(t, fx.pki.ROM.Cert)
	info, err := vendorinfo.Build(fx.scan, fx.eks, fx.st, vendorinfo.Options{Published: fx.pub, Include: []string{strings.ToUpper(rom)}})
	if err != nil {
		t.Fatal(err)
	}
	files, _ := info.Files()
	if !bytes.Equal(files["certs/"+rom+".der"], fx.pki.ROM.Cert.Raw) || !info.EK[0].Chain[3].Public {
		t.Error("included certificate missing")
	}
	if _, ok := files["vendor/syn/intermediates/csme-mcc-rom-ca.der"]; !ok {
		t.Errorf("draft lacks the included CA: %v", keys(files))
	}
}

func TestStrict(t *testing.T) {
	fx := newFixture(t)
	info, err := vendorinfo.Build(fx.scan, fx.eks, fx.st, vendorinfo.Options{Published: fx.pub, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if s := info.EK[0].Chain[3].Subject; s != "CN=REDACTED" {
		t.Errorf("strict ROM CA subject %q", s)
	}
	if s := info.EK[0].Chain[2].Issuer; s != "CN=REDACTED" {
		t.Errorf("strict issuer of the Kernel CA %q", s)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
