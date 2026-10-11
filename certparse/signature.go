package certparse

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
)

// CheckSignature verifies that child was signed by parent's key and that
// parent may sign certificates (CA flag, keyCertSign).
//
// The standard library refuses SHA-1 signatures. Some older TPM vendor PKIs
// still use them, so they are verified here; the caller sees the
// insecure-signature-algorithm quirk on the child.
func CheckSignature(child, parent *x509.Certificate) error {
	err := child.CheckSignatureFrom(parent)
	var insecure x509.InsecureAlgorithmError
	if !errors.As(err, &insecure) {
		return err
	}
	if parent.Version == 3 && (!parent.BasicConstraintsValid || !parent.IsCA) {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	return checkSHA1(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature, parent.PublicKey)
}

// CheckCRLSignature verifies a CRL signature, accepting SHA-1 like
// CheckSignature does.
func CheckCRLSignature(crl *x509.RevocationList, issuer *x509.Certificate) error {
	err := crl.CheckSignatureFrom(issuer)
	var insecure x509.InsecureAlgorithmError
	if !errors.As(err, &insecure) {
		return err
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("x509: issuer may not sign CRLs")
	}
	return checkSHA1(crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature, issuer.PublicKey)
}

func checkSHA1(alg x509.SignatureAlgorithm, signed, sig []byte, pub any) error {
	h := sha1.Sum(signed)
	switch alg {
	case x509.SHA1WithRSA:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("x509: SHA1WithRSA signature with non-RSA key")
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA1, h[:], sig)
	case x509.ECDSAWithSHA1:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("x509: ECDSAWithSHA1 signature with non-ECDSA key")
		}
		if !ecdsa.VerifyASN1(k, h[:], sig) {
			return errors.New("x509: ECDSA verification failure")
		}
		return nil
	}
	return fmt.Errorf("x509: unsupported signature algorithm %v", alg)
}
