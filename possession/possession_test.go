package possession

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-verifier/internal/swtpmtest"
	"github.com/mrwiora/tpm2-verifier/tpm"
)

// TestPolicyA recomputes TPM2_PolicySecret(TPM_RH_ENDORSEMENT).
func TestPolicyA(t *testing.T) {
	d := make([]byte, 32)
	h := sha256.New()
	h.Write(d)
	binary.Write(h, binary.BigEndian, uint32(tpm2.TPMCCPolicySecret))
	binary.Write(h, binary.BigEndian, uint32(tpm2.TPMRHEndorsement)) // name of a permanent handle
	d = h.Sum(nil)
	h.Reset()
	h.Write(d) // policyRef is empty
	if got := h.Sum(nil); !bytes.Equal(got, policyASHA256) || !bytes.Equal(policyASHA256, tpm2.RSAEKTemplate.AuthPolicy.Buffer) {
		t.Errorf("PolicyA %x", got)
	}
}

func swtpm(t *testing.T) transport.TPM {
	t.Helper()
	tp, err := tpm.Open(swtpmtest.Start(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tp.Close() })
	return tp.Backend().(*tpm.Device).Transport()
}

func TestProveSwtpm(t *testing.T) {
	tr := swtpm(t)
	for _, idx := range []uint32{0x01C00002, 0x01C0000A, 0x01C00012, 0x01C00014, 0x01C00016} {
		key, name, err := EKPublicKey(tr, idx, nil, nil, nil)
		if err != nil {
			t.Fatalf("0x%08X: %v", idx, err)
		}
		r := Prove(tr, idx, key, nil, nil, Options{})
		if r.Status != StatusProven || r.Template != name {
			t.Errorf("0x%08X: %+v", idx, r)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if r := Prove(tr, 0x01C00002, &other.PublicKey, nil, nil, Options{}); r.Status != StatusKeyMismatch {
		t.Errorf("foreign certificate key: %+v", r)
	}
	if r := Prove(tr, 0x01C0001A, &other.PublicKey, nil, nil, Options{}); r.Status != StatusUnsupported {
		t.Errorf("SM2 slot: %+v", r)
	}
}

func TestNonceAndTemplate(t *testing.T) {
	tr := swtpm(t)
	nonce := []byte("vendor nonce")
	plain, _, err := EKPublicKey(tr, 0x01C00002, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	withNonce, name, err := EKPublicKey(tr, 0x01C00002, nil, nonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.(interface{ Equal(crypto.PublicKey) bool }).Equal(withNonce) || !strings.Contains(name, "nonce from NV 0x01C00003") {
		t.Fatalf("nonce not applied (%s)", name)
	}
	if r := Prove(tr, 0x01C00002, withNonce, nil, nonce, Options{}); r.Status != StatusProven {
		t.Errorf("with nonce: %+v", r)
	}
	if r := Prove(tr, 0x01C00002, withNonce, nil, nil, Options{}); r.Status != StatusKeyMismatch {
		t.Errorf("nonce ignored: %+v", r)
	}

	// A vendor template in NV (here: ECC P-256 with SHA-256 but AES-256).
	tmpl := tpm2.ECCEKTemplate
	parms, _ := tmpl.Parameters.ECCDetail()
	p := *parms
	p.Symmetric = aes(256)
	tmpl.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &p)
	raw := tpm2.Marshal(tmpl)
	key, name, err := EKPublicKey(tr, 0x01C0000A, raw, nil, nil)
	if err != nil || name != "template from NV 0x01C0000C" {
		t.Fatalf("%v %s", err, name)
	}
	if r := Prove(tr, 0x01C0000A, key, raw, nil, Options{}); r.Status != StatusProven {
		t.Errorf("NV template: %+v", r)
	}
}

// impostor reports the certificate's key for the EK, as a TPM would that
// carries a copied certificate, but holds a different EK.
type impostor struct {
	*tpmOps
	claim crypto.PublicKey
}

func (i impostor) createEK(tmpl tpm2.TPMTPublic) (tpm2.TPMHandle, tpm2.TPMTPublic, tpm2.TPM2BName, error) {
	h, pub, name, err := i.tpmOps.createEK(tmpl)
	if err == nil {
		err = setUnique(&pub, i.claim)
	}
	return h, pub, name, err
}

func TestImpostor(t *testing.T) {
	genuine := swtpm(t) // the TPM the certificate was issued for
	key, _, err := EKPublicKey(genuine, 0x01C00002, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := swtpm(t)
	r := prove(impostor{&tpmOps{t: other}, key}, 0x01C00002, key, nil, nil, Options{})
	if r.Status != StatusFailed {
		t.Errorf("impostor: %+v", r)
	}
	// The honest other TPM is caught by the key comparison already.
	if r := Prove(other, 0x01C00002, key, nil, nil, Options{}); r.Status != StatusKeyMismatch {
		t.Errorf("copied certificate: %+v", r)
	}
}

func TestEndorsementAuth(t *testing.T) {
	tr := swtpm(t)
	key, _, err := EKPublicKey(tr, 0x01C00002, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("secret")},
	}).Execute(tr); err != nil {
		t.Fatal(err)
	}
	if r := Prove(tr, 0x01C00002, key, nil, nil, Options{}); r.Status != StatusError {
		t.Errorf("without auth: %+v", r)
	}
	if r := Prove(tr, 0x01C00002, key, nil, nil, Options{EndorsementAuth: []byte("secret")}); r.Status != StatusProven {
		t.Errorf("with auth: %+v", r)
	}
}
