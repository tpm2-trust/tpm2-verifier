package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-verifier/internal/swtpmtest"
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
