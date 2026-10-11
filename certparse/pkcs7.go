package certparse

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// ParsePKCS7Certificates extracts the certificates from a DER or PEM encoded
// PKCS#7 / CMS SignedData structure, the "certs-only" format (.p7c, .p7b)
// some CAs publish at their AIA "CA Issuers" URL. Signatures and other
// content are ignored.
func ParsePKCS7Certificates(data []byte) ([]*Certificate, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue // [0] EXPLICIT, unwrapped below
	}
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil, fmt.Errorf("certparse: PKCS#7: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("certparse: PKCS#7: content type %s is not SignedData", ci.ContentType)
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 {
		return nil, errors.New("certparse: PKCS#7: missing content")
	}
	fields, err := unwrapSequence(ci.Content.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certparse: PKCS#7 SignedData: %w", err)
	}
	// version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
	for len(fields) > 0 {
		var f asn1.RawValue
		if fields, err = asn1.Unmarshal(fields, &f); err != nil {
			return nil, fmt.Errorf("certparse: PKCS#7 SignedData: %w", err)
		}
		if f.Class == asn1.ClassContextSpecific && f.Tag == 0 {
			return ParseAll(f.Bytes)
		}
	}
	return nil, errors.New("certparse: PKCS#7 contains no certificates")
}

// ParseCertificatesAny parses certificates in any format found at AIA URLs:
// DER, PEM, concatenated DER, or PKCS#7 certs-only.
func ParseCertificatesAny(data []byte) ([]*Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PKCS7")) {
		return ParsePKCS7Certificates(trimmed)
	}
	certs, err := ParseAll(data)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}
	if p7, p7err := ParsePKCS7Certificates(data); p7err == nil {
		return p7, nil
	}
	if err == nil {
		err = errors.New("certparse: no certificates found")
	}
	return nil, err
}
