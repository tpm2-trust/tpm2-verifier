package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSSHKeygenSignature checks a signature made with
// ssh-keygen -Y sign -n tpm2-verifier-vendors (testdata/message.sig).
func TestSSHKeygenSignature(t *testing.T) {
	msg, _ := os.ReadFile("testdata/message")
	sig, _ := os.ReadFile("testdata/message.sig")
	pub, _ := os.ReadFile("testdata/signer.pub")
	signers, err := ParseAllowedSigners([]byte("test " + string(pub)))
	if err != nil || len(signers) != 1 {
		t.Fatalf("%v %v", signers, err)
	}
	key, err := VerifySSHSig(msg, sig, Namespace)
	if err != nil {
		t.Fatal(err)
	}
	// ssh-keygen -l -f testdata/signer.pub
	if !key.Equal(signers[0].Key) || key.Fingerprint() != "SHA256:hnJkuEwrsGtDsZ4suT1sje/U28MvzEgq2YUeKHE1vBo" {
		t.Errorf("key %s", key.Fingerprint())
	}
	if _, err := VerifySSHSig(append(msg, ' '), sig, Namespace); err == nil {
		t.Error("changed message verified")
	}
	other, _ := os.ReadFile("testdata/message-other-ns.sig")
	if _, err := VerifySSHSig(msg, other, Namespace); err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Errorf("other namespace: %v", err)
	}
	if _, err := VerifySSHSig(msg, other, "other-namespace"); err != nil {
		t.Errorf("sha256 signature: %v", err)
	}
}

func TestAllowedSigners(t *testing.T) {
	pub, _ := os.ReadFile("testdata/signer.pub")
	k := strings.TrimSpace(string(pub))
	s, err := ParseAllowedSigners([]byte("# c\n\na@x " + k + "\nb@x namespaces=\"git\" " + k + "\nc@x namespaces=\"git,tpm2-verifier-vendors\" " + k + "\n"))
	if err != nil || len(s) != 2 || s[0].Principal != "a@x" || s[1].Principal != "c@x" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := ParseAllowedSigners([]byte("a@x ecdsa-sha2-nistp256 AAAA")); err == nil {
		t.Error("ecdsa accepted")
	}
	if _, err := TrustedSigners(); err != nil {
		t.Error(err)
	}
}

// sign writes dir/MANIFEST.sig as ssh-keygen -Y sign would.
func sign(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	msg, err := os.ReadFile(filepath.Join(dir, File))
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.Sum512(msg)
	pub := sshString(sshString(nil, []byte(keyTypeEd25519)), priv.Public().(ed25519.PublicKey))
	sig := sshString(sshString(nil, []byte(keyTypeEd25519)), ed25519.Sign(priv, SignedData(Namespace, nil, "sha512", h[:])))
	b := binary.BigEndian.AppendUint32([]byte("SSHSIG"), 1)
	for _, s := range [][]byte{pub, []byte(Namespace), nil, []byte("sha512"), sig} {
		b = sshString(b, s)
	}
	if err := os.WriteFile(filepath.Join(dir, SigFile), pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: b}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		p = filepath.Join(dir, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeManifest(t *testing.T, dir string, now time.Time) *Manifest {
	t.Helper()
	m, changed, err := Update(dir, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		if err := os.WriteFile(filepath.Join(dir, File), m.Marshal(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestVerify(t *testing.T) {
	dir := writeTree(t, map[string]string{"intel/vendor.yaml": "id: intel\n", "intel/roots/r.der": "root"})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := []Signer{{Principal: "maintainer", Key: PublicKey(pub)}}

	r, err := Verify(dir, trusted)
	if err != nil || r.Status != StatusNoManifest || r.Files != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	m := writeManifest(t, dir, now)
	if m.Version != "2026.10.14" || len(m.Files) != 2 || m.Files[0].Path != "intel/roots/r.der" {
		t.Fatalf("%+v", m)
	}
	if r, err = Verify(dir, trusted); err != nil || r.Status != StatusUnsigned || r.Version != "2026.10.14" {
		t.Fatalf("%+v %v", r, err)
	}
	sign(t, dir, priv)
	if r, err = Verify(dir, trusted); err != nil || !r.Trusted() || r.Signer.Principal != "maintainer" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(r.Describe(), "signed by maintainer (SHA256:") {
		t.Error(r.Describe())
	}
	if r, err = Verify(dir, nil); err != nil || r.Status != StatusUntrustedKey {
		t.Fatalf("%+v %v", r, err)
	}
	// The verified content is held in memory.
	if data, err := fs.ReadFile(r.FS, "intel/roots/r.der"); err != nil || string(data) != "root" {
		t.Fatalf("%q %v", data, err)
	}

	// Unchanged files keep the manifest (and the signature).
	if _, changed, _ := Update(dir, "", now); changed {
		t.Error("unchanged tree updated")
	}

	for name, change := range map[string]func(){
		"sha256":      func() { os.WriteFile(filepath.Join(dir, "intel/roots/r.der"), []byte("evil"), 0o644) },
		"not listed":  func() { os.WriteFile(filepath.Join(dir, "intel/roots/extra.der"), []byte("x"), 0o644) },
		"but missing": func() { os.Remove(filepath.Join(dir, "intel/vendor.yaml")) },
	} {
		t.Run(name, func(t *testing.T) {
			d := writeTree(t, map[string]string{"intel/vendor.yaml": "id: intel\n", "intel/roots/r.der": "root"})
			writeManifest(t, d, now)
			sign(t, d, priv)
			dir = d
			change()
			if _, err := Verify(d, trusted); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("want %q, got %v", name, err)
			}
		})
	}

	// A manifest changed after signing.
	m.Files[1].SHA256 = strings.Repeat("0", 64)
	os.WriteFile(filepath.Join(dir, File), m.Marshal(), 0o644)
	if _, err := Verify(dir, trusted); err == nil {
		t.Error("tampered manifest accepted")
	}
}

func TestTamperedManifestSignature(t *testing.T) {
	dir := writeTree(t, map[string]string{"a/vendor.yaml": "id: a\n"})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	writeManifest(t, dir, time.Now())
	sign(t, dir, priv)
	// Consistent files and manifest, but the manifest no longer matches the signature.
	os.WriteFile(filepath.Join(dir, "a/vendor.yaml"), []byte("id: b\n"), 0o644)
	m, _, _ := Update(dir, "x", time.Now())
	os.WriteFile(filepath.Join(dir, File), m.Marshal(), 0o644)
	if _, err := Verify(dir, nil); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("got %v", err)
	}
}

func TestNextVersion(t *testing.T) {
	now := time.Date(2026, 10, 14, 23, 0, 0, 0, time.UTC)
	for prev, want := range map[string]string{"": "2026.10.14", "2026.10.13": "2026.10.14", "2026.10.14": "2026.10.14.2", "2026.10.14.2": "2026.10.14.3", "1.0": "2026.10.14"} {
		if got := NextVersion(prev, now); got != want {
			t.Errorf("%q: %s, want %s", prev, got, want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	sum := strings.Repeat("a", 64)
	for _, m := range []string{
		"a  b\n",
		sum + "  x\n",                       // no version
		"# version: 1\n" + sum + "  ../x\n", // path escape
		"# version: 1\n" + sum + "  /x\n",   // absolute
		"# version: 1\n" + sum + "  b\n" + sum + "  a\n", // unsorted
		"# version: 1\n" + sum + "  MANIFEST\n",
	} {
		if _, err := Parse([]byte(m)); err == nil {
			t.Errorf("accepted %q", m)
		}
	}
}
