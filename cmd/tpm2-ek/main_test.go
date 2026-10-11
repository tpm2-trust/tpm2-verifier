package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-verifier/internal/testpki"
)

// fixture writes a synthetic Intel-like hierarchy to disk: an overlay store
// with the static CAs, the EK, the NV chain blob and the CRLs.
type fixture struct {
	dir, store, ek, chain string
	crls                  []string
	pki                   *testpki.IntelChain
}

func newFixture(t *testing.T, revoked bool) *fixture {
	t.Helper()
	pki := testpki.IntelLike(t)
	f := &fixture{dir: t.TempDir(), pki: pki}
	f.store = filepath.Join(f.dir, "store")
	vdir := filepath.Join(f.store, "synthetic")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "id: synthetic\nname: Synthetic\nmanufacturer_ids: [SYN]\ncertificates:\n"
	for name, c := range map[string][]byte{"root.der": pki.Root.Cert.Raw, "int1.der": pki.Int1.Cert.Raw, "int2.der": pki.Int2.Cert.Raw} {
		write(t, filepath.Join(vdir, name), c)
		role := "intermediate"
		if name == "root.der" {
			role = "root"
		}
		sum := sha256.Sum256(c)
		yaml += fmt.Sprintf("  - file: %s\n    role: %s\n    source: test\n    sha256: %s\n", name, role, hex.EncodeToString(sum[:]))
	}
	write(t, filepath.Join(vdir, "vendor.yaml"), []byte(yaml))

	f.ek = write(t, filepath.Join(f.dir, "ek.der"), pki.EK.Raw)
	f.chain = write(t, filepath.Join(f.dir, "chain.der"), pki.DeviceChain())
	var crls map[string][]byte
	if revoked {
		crls = pki.CRLs(t, pki.PTT.Cert)
	} else {
		crls = pki.CRLs(t)
	}
	i := 0
	for _, der := range crls {
		i++
		f.crls = append(f.crls, write(t, filepath.Join(f.dir, fmt.Sprintf("%d.crl", i)), der))
	}
	return f
}

func write(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *fixture) verifyArgs(extra ...string) []string {
	args := []string{"verify", "-no-fetch", "-store", f.store, "-time", f.pki.Now.Format("2006-01-02T15:04:05Z")}
	for _, c := range f.crls {
		args = append(args, "-crl", c)
	}
	return append(append(args, extra...), f.ek, f.chain)
}

func runCLI(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestSplitDechainerCompatible(t *testing.T) {
	f := newFixture(t, false)
	out := filepath.Join(f.dir, "out")
	code, stdout, stderr := runCLI("split", "-o", out, "-p", "intel-int", "-s", "3", "-pem", f.chain)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for i, want := range map[int]string{3: "CSME MCC ROM CA", 4: "CSME MCC SVN01 Kernel CA", 5: "CSME MCC PTT 01SVN"} {
		der, err := os.ReadFile(filepath.Join(out, fmt.Sprintf("intel-int%d.der", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(out, fmt.Sprintf("intel-int%d.pem", i))); err != nil {
			t.Error(err)
		}
		if !strings.Contains(stdout, want) || len(der) == 0 {
			t.Errorf("int%d: missing %q in output", i, want)
		}
	}
}

func TestVerifyTrusted(t *testing.T) {
	f := newFixture(t, false)
	code, stdout, stderr := runCLI(f.verifyArgs("-revocation", "require")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "TRUSTED (vendor synthetic)") || strings.Count(stdout, "depth=") != 7 {
		t.Errorf("unexpected output:\n%s", stdout)
	}
	// The EK claims INTC but the synthetic store only knows SYN; with the
	// embedded store loaded too, INTC resolves to intel and the mismatch is hinted.
	if !strings.Contains(stdout, "EK claims manufacturer INTC (intel) but chains to vendor synthetic") {
		t.Errorf("missing manufacturer mismatch hint:\n%s", stdout)
	}
}

func TestVerifyRevokedJSON(t *testing.T) {
	f := newFixture(t, true)
	code, stdout, _ := runCLI(f.verifyArgs("-json")...)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	var rep struct {
		Status string
		Chain  []struct {
			Subject    string
			Revocation struct{ Status string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Status != "revoked" || rep.Chain[1].Revocation.Status != "revoked" {
		t.Errorf("status %s, depth 1 %+v", rep.Status, rep.Chain[1])
	}
}

func TestVerifyIncomplete(t *testing.T) {
	f := newFixture(t, false)
	code, stdout, _ := runCLI("verify", "-no-fetch", "-store", f.store, f.ek)
	if code != 1 || !strings.Contains(stdout, "INCOMPLETE") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestInspect(t *testing.T) {
	f := newFixture(t, false)
	code, stdout, stderr := runCLI("inspect", f.ek, f.chain, f.crls[0])
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"TCG EK certificate", "manufacturer INTC", "chain.der[2]", "(CRL)", "empty-subject"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestStoreExportAndUsage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x")
	code, stdout, _ := runCLI("store", "export", "-o", out, "intel")
	if code != 0 || !strings.Contains(stdout, filepath.Join("intel", "roots", "ondie-ca-root.der")) {
		t.Fatalf("exit %d: %s", code, stdout)
	}
	if code, _, _ := runCLI("nonsense"); code != 2 {
		t.Errorf("unknown command exit %d", code)
	}
}
