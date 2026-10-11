// Package swtpmtest runs a swtpm software TPM for tests and provisions NV
// indices the way TPM vendors do.
package swtpmtest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Start launches swtpm on a unix socket and returns the TPM spec
// ("swtpm:path=...") for tpm.Open. The test is skipped if swtpm is not
// installed.
func Start(t testing.TB) string {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		t.Skip("swtpm not installed")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "tpm.sock")
	cmd := exec.Command(bin, "socket", "--tpm2",
		"--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+filepath.Join(dir, "ctrl.sock"),
		"--flags", "not-need-init,startup-clear")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	for range 100 {
		if _, err := os.Stat(sock); err == nil {
			return "swtpm:path=" + sock
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("swtpm did not start: %s", stderr.String())
	return ""
}

// Attributes used by Define.
var (
	// EKCertAttrs resembles a vendor provisioned EK certificate index:
	// readable with owner or (no-DA) index authorization.
	EKCertAttrs = tpm2.TPMANV{OwnerWrite: true, AuthWrite: true, OwnerRead: true, AuthRead: true, NoDA: true}
	// DAProtectedAttrs is readable only with the index auth value and
	// subject to dictionary attack protection.
	DAProtectedAttrs = tpm2.TPMANV{OwnerWrite: true, AuthWrite: true, AuthRead: true}
	// PolicyOnlyAttrs is readable only with a policy.
	PolicyOnlyAttrs = tpm2.TPMANV{OwnerWrite: true, AuthWrite: true, PolicyRead: true}
)

// Define creates an NV index with the owner hierarchy and writes data to it
// (nothing is written if data is nil; size is used then).
func Define(t testing.TB, tr transport.TPM, index uint32, attrs tpm2.TPMANV, size int, data []byte) {
	t.Helper()
	if data != nil {
		size = len(data)
	}
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	pub := tpm2.TPMSNVPublic{
		NVIndex:    tpm2.TPMHandle(index),
		NameAlg:    tpm2.TPMAlgSHA256,
		Attributes: attrs,
		DataSize:   uint16(size),
	}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(pub)}).Execute(tr); err != nil {
		t.Fatalf("define 0x%08X: %v", index, err)
	}
	if data == nil {
		return
	}
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tr)
	if err != nil {
		t.Fatal(err)
	}
	nv := tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: rsp.NVName}
	const chunk = 512
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		if _, err := (tpm2.NVWrite{
			AuthHandle: owner,
			NVIndex:    nv,
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data[off:end]},
			Offset:     uint16(off),
		}).Execute(tr); err != nil {
			t.Fatalf("write 0x%08X at %d: %v", index, off, err)
		}
	}
}
