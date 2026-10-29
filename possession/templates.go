package possession

import (
	"encoding/hex"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// Policy digests of the TCG EK Credential Profile (version 2.5, section
// "EK Templates"). PolicyA is TPM2_PolicySecret(TPM_RH_ENDORSEMENT) and is
// used by the low range templates. The high range templates use PolicyB,
// PolicyOR(PolicyA, PolicyC) with PolicyC = TPM2_PolicyAuthorizeNV of the EK
// policy index. Wrong values cannot produce a false positive: the TPM would
// create a different key, which is reported as a key mismatch. PolicyB_SHA384
// (H-3) is confirmed on Intel PTT hardware.
var (
	policyASHA256 = mustHex("837197674484B3F81A90CC8D46A5D724FD52D76E06520B64F2A1DA1B331469AA")
	policyBSHA256 = mustHex("CA3D0A99A2B93906F7A3342414EFCFB3A385D44CD1FD459089D19B5071C0B7A0")
	policyBSHA384 = mustHex("B26E7D28D11A50BC53D882BCF5FD3A1A074148BB35D3B4E4CB1C0AD9BDE419CACB47BA09699646150F9FC000F3F80E12")
	policyBSHA512 = mustHex("B8221CA69E8550A4914DE3FAA6A18C072CC01208073A928D5D66D59EF79E49A429C41A6B269571D57EDB25FBDB1838426512B93BF1F2B53E0FB0CEFFD0E30F")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// lowAttrs are the object attributes of the low range EK templates: the EK
// can only be used with PolicySecret(TPM_RH_ENDORSEMENT).
var lowAttrs = tpm2.TPMAObject{
	FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
	AdminWithPolicy: true, Restricted: true, Decrypt: true,
}

// highAttrs add userWithAuth: the high range EKs have an empty auth value.
var highAttrs = func() tpm2.TPMAObject { a := lowAttrs; a.UserWithAuth = true; return a }()

func aes(bits int) tpm2.TPMTSymDefObject {
	return tpm2.TPMTSymDefObject{
		Algorithm: tpm2.TPMAlgAES,
		KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(bits)),
		Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
	}
}

func rsaTemplate(nameAlg tpm2.TPMIAlgHash, attrs tpm2.TPMAObject, policy []byte, symBits int, keyBits int, unique int) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          nameAlg,
		ObjectAttributes: attrs,
		AuthPolicy:       tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: aes(symBits),
			KeyBits:   tpm2.TPMKeyBits(keyBits),
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, unique)}),
	}
}

func eccTemplate(nameAlg tpm2.TPMIAlgHash, attrs tpm2.TPMAObject, policy []byte, symBits int, curve tpm2.TPMECCCurve, unique int) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          nameAlg,
		ObjectAttributes: attrs,
		AuthPolicy:       tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: aes(symBits),
			CurveID:   curve,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, unique)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, unique)},
		}),
	}
}

// defaultTemplates are the TCG EK templates per EK certificate NV index:
// L-1 and L-2 (low range) and H-1 to H-7 (high range, except H-5 SM2).
var defaultTemplates = map[uint32]struct {
	name string
	tmpl tpm2.TPMTPublic
}{
	0x01C00002: {"TCG template L-1 (RSA 2048)", tpm2.RSAEKTemplate},
	0x01C0000A: {"TCG template L-2 (ECC NIST P-256)", tpm2.ECCEKTemplate},
	0x01C00012: {"TCG template H-1 (RSA 2048)", rsaTemplate(tpm2.TPMAlgSHA256, highAttrs, policyBSHA256, 128, 2048, 0)},
	0x01C00014: {"TCG template H-2 (ECC NIST P-256)", eccTemplate(tpm2.TPMAlgSHA256, highAttrs, policyBSHA256, 128, tpm2.TPMECCNistP256, 0)},
	0x01C00016: {"TCG template H-3 (ECC NIST P-384)", eccTemplate(tpm2.TPMAlgSHA384, highAttrs, policyBSHA384, 256, tpm2.TPMECCNistP384, 0)},
	0x01C00018: {"TCG template H-4 (ECC NIST P-521)", eccTemplate(tpm2.TPMAlgSHA512, highAttrs, policyBSHA512, 256, tpm2.TPMECCNistP521, 0)},
	0x01C0001C: {"TCG template H-6 (RSA 3072)", rsaTemplate(tpm2.TPMAlgSHA384, highAttrs, policyBSHA384, 256, 3072, 0)},
	0x01C0001E: {"TCG template H-7 (RSA 4096)", rsaTemplate(tpm2.TPMAlgSHA384, highAttrs, policyBSHA384, 256, 4096, 0)},
}

// Template returns the EK template for the EK certificate stored at index.
// For the low range, a template stored by the vendor in the EK template
// index (index+2) replaces the default, and a nonce in the EK nonce index
// (index+1) is filled into the unique field, as the TCG EK Credential
// Profile specifies. nvTemplate and nvNonce may be nil.
func Template(index uint32, nvTemplate, nvNonce []byte) (tpm2.TPMTPublic, string, error) {
	d, ok := defaultTemplates[index]
	if !ok {
		return tpm2.TPMTPublic{}, "", fmt.Errorf("no EK template known for NV index 0x%08X", index)
	}
	tmpl, name := d.tmpl, d.name
	low := index == 0x01C00002 || index == 0x01C0000A
	if low && len(nvTemplate) > 0 {
		t, err := tpm2.Unmarshal[tpm2.TPMTPublic](nvTemplate)
		if err != nil {
			return tpm2.TPMTPublic{}, "", fmt.Errorf("EK template in NV 0x%08X: %w", index+2, err)
		}
		tmpl, name = *t, fmt.Sprintf("template from NV 0x%08X", index+2)
	}
	if low && len(nvNonce) > 0 {
		var err error
		if tmpl, err = withNonce(tmpl, nvNonce); err != nil {
			return tpm2.TPMTPublic{}, "", err
		}
		name += fmt.Sprintf(", nonce from NV 0x%08X", index+1)
	}
	return tmpl, name, nil
}

// withNonce fills the nonce into the unique field: RSA n is the nonce padded
// with zeros to 256 bytes; ECC x is the nonce padded to 32 bytes, y 32 zeros.
func withNonce(t tpm2.TPMTPublic, nonce []byte) (tpm2.TPMTPublic, error) {
	pad := func(n int) []byte {
		b := make([]byte, max(n, len(nonce)))
		copy(b, nonce)
		return b
	}
	switch t.Type {
	case tpm2.TPMAlgRSA:
		t.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: pad(256)})
	case tpm2.TPMAlgECC:
		t.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: pad(32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		})
	default:
		return t, fmt.Errorf("EK nonce for key type 0x%04X not supported", t.Type)
	}
	return t, nil
}
