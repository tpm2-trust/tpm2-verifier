package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-verifier/bundle"
	"github.com/mrwiora/tpm2-verifier/internal/swtpmtest"
	"github.com/mrwiora/tpm2-verifier/possession"
	"github.com/mrwiora/tpm2-verifier/tpm"
)

// provisioned starts swtpm with the fixture's EK and device chain in NV.
func provisioned(t *testing.T, f *fixture) string {
	t.Helper()
	spec := swtpmtest.Start(t)
	tp, err := tpm.Open(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()
	tr := tp.Backend().(*tpm.Device).Transport()
	swtpmtest.Define(t, tr, 0x01C00002, swtpmtest.EKCertAttrs, 0, f.pki.EK.Raw)
	swtpmtest.Define(t, tr, 0x01C00100, swtpmtest.EKCertAttrs, 0, f.pki.DeviceChain())
	swtpmtest.Define(t, tr, 0x01C0000A, swtpmtest.EKCertAttrs, 32, nil)
	return spec
}

func TestInfoFromSwtpm(t *testing.T) {
	f := newFixture(t, false)
	spec := provisioned(t, f)
	code, stdout, stderr := runCLI("info", "-tpm", spec, "-store", f.store, "-no-fetch")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"Manufacturer:   IBM (not in vendor store)",
		"0x01C00002", "ek-certificate RSA 2048 (low)",
		"0x01C00100", "cert: CN=CSME MCC ROM CA",
		"0x01C0000A", "not read: index has not been written",
		"EK certificate 0x01C00002 (ek-certificate RSA 2048 (low)): TRUSTED (vendor synthetic)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in\n%s", want, stdout)
		}
	}
}

func TestVerifyFromSwtpm(t *testing.T) {
	f := newFixture(t, true) // PTT CA revoked on the indirect CRL
	spec := provisioned(t, f)
	args := []string{"verify", "-tpm", spec, "-store", f.store, "-no-fetch"}
	for _, c := range f.crls {
		args = append(args, "-crl", c)
	}
	code, stdout, _ := runCLI(args...)
	if code != 1 || !strings.Contains(stdout, "REVOKED") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestExportFromSwtpm(t *testing.T) {
	f := newFixture(t, false)
	spec := provisioned(t, f)
	out := filepath.Join(f.dir, "export")
	// Make the synthetic vendor match the swtpm manufacturer.
	y, _ := os.ReadFile(filepath.Join(f.store, "synthetic", "vendor.yaml"))
	os.WriteFile(filepath.Join(f.store, "synthetic", "vendor.yaml"), []byte(strings.Replace(string(y), "[SYN]", "[IBM]", 1)), 0o644)

	code, stdout, stderr := runCLI("export", "-tpm", spec, "-store", f.store, "-o", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	for _, p := range []string{"ek-0x01C00002.der", "chain-1.der", "chain-3.der", "nv/0x01C00100.bin", "store/synthetic/root.der"} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Error(err)
		}
	}
	i := strings.Index(stdout, "openssl verify")
	if i < 0 {
		t.Fatalf("no openssl command in\n%s", stdout)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	cmdline := strings.ReplaceAll(stdout[i:], "\\\n", "")
	res, err := exec.Command("sh", "-c", cmdline).CombinedOutput()
	if err != nil || !strings.Contains(string(res), ": OK") {
		t.Fatalf("openssl: %v\n%s\n%s", err, cmdline, res)
	}
}

func TestDebugBundleReplay(t *testing.T) {
	f := newFixture(t, false)
	spec := provisioned(t, f)
	out := filepath.Join(f.dir, "debug.tar.gz")
	code, stdout, stderr := runCLI("debug", "-tpm", spec, "-store", f.store, "-no-fetch", "-o", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "EK:   0x01C00002 TRUSTED") || !strings.Contains(stdout, "Privacy") {
		t.Errorf("unexpected output:\n%s", stdout)
	}

	b, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"analysis/summary.txt", "analysis/report.json", "analysis/chains/0x01C00002/6-store.der"} {
		if _, ok := b.Extra[name]; !ok {
			t.Errorf("bundle lacks %s", name)
		}
	}

	// The replay shows the same as the live TPM.
	_, live, _ := runCLI("info", "-v", "-tpm", spec, "-store", f.store, "-no-fetch")
	code, replay, stderr := runCLI("info", "-v", "-tpm", "bundle:"+out, "-store", f.store, "-no-fetch")
	if code != 0 || live != replay {
		t.Errorf("replay differs (exit %d, %s)\nlive:\n%s\nreplay:\n%s", code, stderr, live, replay)
	}
	if code, _, stderr := runCLI("export", "-tpm", "bundle:"+out, "-o", filepath.Join(f.dir, "exp")); code != 0 {
		t.Errorf("export from bundle: exit %d %s", code, stderr)
	}
	if code, _, _ := runCLI("debug", "-tpm", "bundle:"+out); code != 2 {
		t.Errorf("debug of a bundle: exit %d", code)
	}
}

func TestDebugAnon(t *testing.T) {
	f := newFixture(t, false)
	spec := provisioned(t, f)
	out := filepath.Join(f.dir, "anon")
	code, stdout, stderr := runCLI("debug-anon", "-tpm", spec, "-store", f.store, "-no-fetch", "-o", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{"EK:   0x01C00002 TRUSTED", "Included in full (public):", "store synthetic/", "CN=CSME MCC ROM CA  sha256 ", "-include <sha256>", "tpm2-ek info -store "} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in\n%s", want, stdout)
		}
	}
	var all []byte
	filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			all = append(all, b...)
		}
		return nil
	})
	for _, c := range []*x509.Certificate{f.pki.EK, f.pki.ROM.Cert, f.pki.Kernel.Cert, f.pki.PTT.Cert} {
		fp := sha256.Sum256(c.Raw)
		if bytes.Contains(all, c.RawSubjectPublicKeyInfo) || bytes.Contains(all, []byte(hex.EncodeToString(fp[:]))) {
			t.Errorf("output contains %q", c.Subject)
		}
	}
	y, err := os.ReadFile(filepath.Join(out, "vendor", "ibm", "vendor.yaml"))
	if err != nil || !strings.Contains(string(y), "chain_nv_indices: [0x01C00100]") {
		t.Errorf("vendor.yaml: %v\n%s", err, y)
	}

	// A full debug bundle can be converted, and an archive written.
	bundlePath := filepath.Join(f.dir, "debug.tar.gz")
	if code, _, stderr := runCLI("debug", "-tpm", spec, "-store", f.store, "-no-fetch", "-o", bundlePath); code != 0 {
		t.Fatal(stderr)
	}
	archive := filepath.Join(f.dir, "anon.tar.gz")
	if code, _, stderr := runCLI("debug-anon", "-tpm", "bundle:"+bundlePath, "-store", f.store, "-no-fetch", "-o", archive); code != 0 {
		t.Fatal(stderr)
	}
	if fi, err := os.Stat(archive); err != nil || fi.Size() == 0 {
		t.Errorf("archive: %v", err)
	}
}

// TestVendorImport: a contributor runs debug-anon, the maintainer reviews
// and imports it into an empty vendor directory.
func TestVendorImport(t *testing.T) {
	f := newFixture(t, false)
	spec := provisioned(t, f)
	sub := filepath.Join(f.dir, "anon.tar.gz")
	if code, _, stderr := runCLI("debug-anon", "-tpm", spec, "-store", f.store, "-no-fetch", "-o", sub); code != 0 {
		t.Fatal(stderr)
	}
	vendors := filepath.Join(f.dir, "vendors")
	os.MkdirAll(vendors, 0o755)

	code, stdout, stderr := runCLI("vendor", "review", "-vendors", vendors, "-no-fetch", sub)
	if code != 0 || !strings.Contains(stdout, "Vendor:     ibm, IBM (NEW)") || !strings.Contains(stdout, "pending: not published") ||
		!strings.Contains(stdout, "ready to import (0 certificates, 3 pending approval)") {
		t.Fatalf("review exit %d\n%s%s", code, stdout, stderr)
	}
	args := []string{"vendor", "import", "-vendors", vendors, "-no-fetch"}
	for _, c := range []*x509.Certificate{f.pki.Root.Cert, f.pki.Int1.Cert, f.pki.Int2.Cert} {
		sum := sha256.Sum256(c.Raw)
		args = append(args, "-accept", hex.EncodeToString(sum[:]))
	}
	code, stdout, stderr = runCLI(append(args, sub)...)
	if code != 0 || !strings.Contains(stdout, "ibm/vendor.yaml") {
		t.Fatalf("import exit %d\n%s%s", code, stdout, stderr)
	}
	// The imported vendor directory alone makes the TPM trusted.
	code, stdout, _ = runCLI("info", "-tpm", spec, "-store", vendors, "-no-fetch")
	if code != 0 || !strings.Contains(stdout, "TRUSTED (vendor ibm)") {
		t.Errorf("info with imported vendor: exit %d\n%s", code, stdout)
	}
	// Again: nothing to do.
	if _, stdout, _ := runCLI("vendor", "review", "-vendors", vendors, "-no-fetch", sub); !strings.Contains(stdout, "nothing to import") {
		t.Errorf("second review:\n%s", stdout)
	}
	// Public intake refuses full bundles.
	full := filepath.Join(f.dir, "debug.tar.gz")
	if code, _, stderr := runCLI("debug", "-tpm", spec, "-no-fetch", "-o", full); code != 0 {
		t.Fatal(stderr)
	}
	if code, _, stderr := runCLI("vendor", "review", "-anon-only", "-vendors", vendors, "-no-fetch", full); code != 2 || !strings.Contains(stderr, "full debug bundle") {
		t.Errorf("-anon-only: exit %d %s", code, stderr)
	}
}

// TestProve: an EK certificate for the swtpm's own EK is proven; the
// fixture's certificate (copied, for another key) is not.
func TestProve(t *testing.T) {
	f := newFixture(t, false)
	spec := swtpmtest.Start(t)
	tp, err := tpm.Open(spec)
	if err != nil {
		t.Fatal(err)
	}
	tr := tp.Backend().(*tpm.Device).Transport()
	ekPub, _, err := possession.EKPublicKey(tr, 0x01C00002, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	genuine := f.pki.IssueEK(t, ekPub)
	swtpmtest.Define(t, tr, 0x01C00002, swtpmtest.EKCertAttrs, 0, genuine.Raw)
	swtpmtest.Define(t, tr, 0x01C0000A, swtpmtest.EKCertAttrs, 0, f.pki.EK.Raw) // copied from another TPM
	swtpmtest.Define(t, tr, 0x01C00100, swtpmtest.EKCertAttrs, 0, f.pki.DeviceChain())
	tp.Close()

	code, stdout, stderr := runCLI("info", "-prove", "-tpm", spec, "-store", f.store, "-no-fetch")
	if code != 1 {
		t.Errorf("exit %d (one EK is not proven)\n%s", code, stderr)
	}
	for _, want := range []string{
		"Possession: PROVEN (TCG template L-1 (RSA 2048)",
		"Verdict: GENUINE: the certificate chains to vendor synthetic and this TPM holds its private key",
		"Possession: KEY-MISMATCH (TCG template L-2 (ECC NIST P-256)",
		"Verdict: NOT PROVEN: the certificate is not for this TPM's EK",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in\n%s", want, stdout)
		}
	}
	code, stdout, _ = runCLI("verify", "-prove", "-json", "-tpm", spec, "-store", f.store, "-no-fetch")
	if code != 1 || !strings.Contains(stdout, `"status": "proven"`) || !strings.Contains(stdout, `"status": "key-mismatch"`) {
		t.Errorf("verify -prove -json: exit %d\n%s", code, stdout)
	}

	// Recorded bundles cannot prove anything.
	b := filepath.Join(f.dir, "debug.tar.gz")
	if code, _, stderr := runCLI("debug", "-prove", "-tpm", spec, "-store", f.store, "-no-fetch", "-o", b); code != 0 {
		t.Fatal(stderr)
	}
	if _, stdout, _ := runCLI("info", "-prove", "-tpm", "bundle:"+b, "-store", f.store, "-no-fetch"); !strings.Contains(stdout, "Possession: UNSUPPORTED") {
		t.Errorf("bundle replay:\n%s", stdout)
	}
	// debug-anon records the result (status and template only).
	anon := filepath.Join(f.dir, "anon")
	if code, stdout, stderr := runCLI("debug-anon", "-prove", "-tpm", spec, "-store", f.store, "-no-fetch", "-o", anon); code != 0 || !strings.Contains(stdout, "possession PROVEN (TCG template L-1 (RSA 2048))") {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	info, _ := os.ReadFile(filepath.Join(anon, "info.json"))
	if !strings.Contains(string(info), `"status": "proven"`) {
		t.Errorf("info.json lacks the proof")
	}
}
