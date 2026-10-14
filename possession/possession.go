// Package possession proves that a TPM holds the private key of its EK
// certificate.
//
// Verifying the certificate chain shows that the certificate stored in the
// TPM was issued by the vendor. It does not show that the TPM one talks to is
// the one the certificate was issued for: anyone can copy a certificate into
// the NV of another (or a software) TPM. Prove closes that gap:
//
//  1. The EK is created again from its TCG template (TPM2_CreatePrimary in
//     the endorsement hierarchy; the TPM derives it from its endorsement
//     seed, so it is always the same key) and compared with the public key
//     in the certificate.
//  2. A random secret is encrypted to the certificate's public key with
//     MakeCredential (in software, bound to the name of a fresh key in the
//     TPM), and the TPM is asked to decrypt it with TPM2_ActivateCredential
//     using the EK. Only a TPM holding the EK's private key returns the
//     secret.
//
// Step 1 alone proves nothing, as an impostor can return any public key;
// it tells a wrong template apart from a wrong TPM. Step 2 is the proof.
package possession

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Status of a proof.
type Status string

const (
	// StatusProven: the TPM decrypted a credential encrypted to the key of
	// the certificate.
	StatusProven Status = "proven"
	// StatusFailed: the TPM created the certificate's key but could not
	// decrypt the credential. This should never happen with a genuine TPM.
	StatusFailed Status = "failed"
	// StatusKeyMismatch: the EK the TPM creates from the template is not the
	// key of the certificate. Either the certificate belongs to another TPM,
	// or the vendor used a template other than the TCG default.
	StatusKeyMismatch Status = "key-mismatch"
	// StatusUnsupported: no proof possible (recorded bundle, unknown EK
	// template, unsupported key type).
	StatusUnsupported Status = "unsupported"
	// StatusError: a TPM command failed, e.g. wrong endorsement hierarchy
	// authorization.
	StatusError Status = "error"
)

// Result of a proof.
type Result struct {
	Index    string        `json:"index"`
	Status   Status        `json:"status"`
	Template string        `json:"template,omitempty"`
	Detail   string        `json:"detail,omitempty"`
	Duration time.Duration `json:"duration_ns,omitempty"`
}

// Options configure Prove.
type Options struct {
	// EndorsementAuth is the authorization value of the endorsement
	// hierarchy (usually empty).
	EndorsementAuth []byte
	// Rand defaults to crypto/rand.
	Rand io.Reader
}

// Prove proves that the TPM behind t holds the private key of cert, the EK
// certificate read from NV index. nvTemplate and nvNonce are the contents of
// the EK template and nonce indices (index+2, index+1) if present.
func Prove(t transport.TPM, index uint32, cert crypto.PublicKey, nvTemplate, nvNonce []byte, opts Options) Result {
	return prove(&tpmOps{t: t, auth: opts.EndorsementAuth}, index, cert, nvTemplate, nvNonce, opts)
}

// ops are the TPM operations used by prove (an interface for tests that
// simulate an impostor).
type ops interface {
	createEK(tmpl tpm2.TPMTPublic) (tpm2.TPMHandle, tpm2.TPMTPublic, tpm2.TPM2BName, error)
	createObject() (tpm2.TPMHandle, tpm2.TPM2BName, error)
	activate(obj tpm2.TPMHandle, objName tpm2.TPM2BName, ek tpm2.TPMHandle, ekName tpm2.TPM2BName, ekTmpl tpm2.TPMTPublic, blob, secret []byte) ([]byte, error)
	flush(h tpm2.TPMHandle)
}

func prove(o ops, index uint32, certKey crypto.PublicKey, nvTemplate, nvNonce []byte, opts Options) Result {
	start := time.Now()
	r := Result{Index: fmt.Sprintf("0x%08X", index)}
	defer func() { r.Duration = time.Since(start) }()
	rnd := opts.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	tmpl, name, err := Template(index, nvTemplate, nvNonce)
	if err != nil {
		r.Status, r.Detail = StatusUnsupported, err.Error()
		return r
	}
	r.Template = name

	ek, ekPub, ekName, err := o.createEK(tmpl)
	if err != nil {
		r.Status, r.Detail = StatusError, "creating the EK: "+err.Error()
		return r
	}
	defer o.flush(ek)
	tpmKey, err := publicKey(&ekPub)
	if err != nil {
		r.Status, r.Detail = StatusUnsupported, err.Error()
		return r
	}
	if !sameKey(tpmKey, certKey) {
		r.Status = StatusKeyMismatch
		r.Detail = "the EK the TPM creates from " + name + " is not the key of the certificate: " +
			"the certificate belongs to another TPM, or the vendor uses a different EK template"
		return r
	}

	obj, objName, err := o.createObject()
	if err != nil {
		r.Status, r.Detail = StatusError, "creating the activation key: "+err.Error()
		return r
	}
	defer o.flush(obj)

	// The parameters (name algorithm, symmetric algorithm) come from the
	// TPM's public area, the key from the certificate: the TPM's key was
	// just compared with it, but the credential must be decryptable only
	// with the certificate's key.
	enc := ekPub
	if err := setUnique(&enc, certKey); err != nil {
		r.Status, r.Detail = StatusUnsupported, err.Error()
		return r
	}
	kem, err := tpm2.ImportEncapsulationKey(&enc)
	if err != nil {
		r.Status, r.Detail = StatusUnsupported, err.Error()
		return r
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rnd, secret); err != nil {
		r.Status, r.Detail = StatusError, err.Error()
		return r
	}
	blob, encSecret, err := tpm2.CreateCredential(rnd, kem, objName.Buffer, secret)
	if err != nil {
		r.Status, r.Detail = StatusError, "creating the credential: "+err.Error()
		return r
	}
	got, err := o.activate(obj, objName, ek, ekName, tmpl, blob, encSecret)
	if err != nil {
		r.Status, r.Detail = StatusFailed, "the TPM could not decrypt the credential: "+err.Error()
		return r
	}
	if subtle.ConstantTimeCompare(got, secret) != 1 {
		r.Status, r.Detail = StatusFailed, "the TPM returned a wrong secret"
		return r
	}
	r.Status = StatusProven
	r.Detail = "the TPM decrypted a credential encrypted to the certificate's public key (TPM2_ActivateCredential)"
	return r
}

// publicKey converts a TPM public area to a Go public key.
func publicKey(pub *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		parms, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		n, err := pub.Unique.RSA()
		if err != nil {
			return nil, err
		}
		return tpm2.RSAPub(parms, n)
	case tpm2.TPMAlgECC:
		parms, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, err
		}
		pt, err := pub.Unique.ECC()
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch parms.CurveID {
		case tpm2.TPMECCNistP256:
			curve = elliptic.P256()
		case tpm2.TPMECCNistP384:
			curve = elliptic.P384()
		case tpm2.TPMECCNistP521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("EK curve 0x%04X not supported", parms.CurveID)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(pt.X.Buffer), Y: new(big.Int).SetBytes(pt.Y.Buffer)}, nil
	}
	return nil, fmt.Errorf("EK key type 0x%04X not supported", pub.Type)
}

// sameKey compares the TPM's key with the certificate's key.
func sameKey(tpmKey, certKey crypto.PublicKey) bool {
	k, ok := tpmKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(certKey)
}

// setUnique replaces the key of a public area by the certificate's key.
func setUnique(pub *tpm2.TPMTPublic, certKey crypto.PublicKey) error {
	switch k := certKey.(type) {
	case *rsa.PublicKey:
		size := (k.N.BitLen() + 7) / 8
		pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: k.N.FillBytes(make([]byte, size))})
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: k.X.FillBytes(make([]byte, size))},
			Y: tpm2.TPM2BECCParameter{Buffer: k.Y.FillBytes(make([]byte, size))},
		})
	default:
		return errors.New("certificate key type not supported")
	}
	return nil
}

// EKPublicKey creates the EK for the EK certificate index from its template
// (see Template) and returns its public key and the template name.
func EKPublicKey(t transport.TPM, index uint32, nvTemplate, nvNonce []byte, endorsementAuth []byte) (crypto.PublicKey, string, error) {
	tmpl, name, err := Template(index, nvTemplate, nvNonce)
	if err != nil {
		return nil, "", err
	}
	o := &tpmOps{t: t, auth: endorsementAuth}
	h, pub, _, err := o.createEK(tmpl)
	if err != nil {
		return nil, "", err
	}
	defer o.flush(h)
	k, err := publicKey(&pub)
	return k, name, err
}

// tpmOps runs the operations on a TPM.
type tpmOps struct {
	t    transport.TPM
	auth []byte
}

func (o *tpmOps) createEK(tmpl tpm2.TPMTPublic) (tpm2.TPMHandle, tpm2.TPMTPublic, tpm2.TPM2BName, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(o.auth)},
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(o.t)
	if err != nil {
		return 0, tpm2.TPMTPublic{}, tpm2.TPM2BName{}, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		o.flush(rsp.ObjectHandle)
		return 0, tpm2.TPMTPublic{}, tpm2.TPM2BName{}, err
	}
	return rsp.ObjectHandle, *pub, rsp.Name, nil
}

// createObject creates a small ECC signing key in the null hierarchy, the
// object the credential is bound to.
func (o *tpmOps) createObject() (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHNull,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
				UserWithAuth: true, SignEncrypt: true, NoDA: true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
				CurveID: tpm2.TPMECCNistP256,
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
		}),
	}.Execute(o.t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, err
	}
	return rsp.ObjectHandle, rsp.Name, nil
}

func (o *tpmOps) activate(obj tpm2.TPMHandle, objName tpm2.TPM2BName, ek tpm2.TPMHandle, ekName tpm2.TPM2BName, ekTmpl tpm2.TPMTPublic, blob, secret []byte) ([]byte, error) {
	// High range EKs have userWithAuth and an empty auth value; low range
	// EKs need PolicySecret(TPM_RH_ENDORSEMENT).
	ekAuth := tpm2.PasswordAuth(nil)
	if !ekTmpl.ObjectAttributes.UserWithAuth {
		ekAuth = tpm2.Policy(ekTmpl.NameAlg, 16, func(t transport.TPM, s tpm2.TPMISHPolicy, nonce tpm2.TPM2BNonce) error {
			_, err := tpm2.PolicySecret{
				AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(o.auth)},
				PolicySession: s,
				NonceTPM:      nonce,
			}.Execute(t)
			return err
		})
	}
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: obj, Name: objName, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ek, Name: ekName, Auth: ekAuth},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: blob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: secret},
	}.Execute(o.t)
	if err != nil {
		return nil, err
	}
	return rsp.CertInfo.Buffer, nil
}

func (o *tpmOps) flush(h tpm2.TPMHandle) {
	tpm2.FlushContext{FlushHandle: h}.Execute(o.t)
}
