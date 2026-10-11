package certparse

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// GeneralName tags (RFC 5280, section 4.2.1.6).
const (
	gnDirectoryName = 4
	gnURI           = 6
)

type generalName struct {
	tag   int
	bytes []byte
}

// parseGeneralNames parses the content octets of a GeneralNames SEQUENCE.
func parseGeneralNames(b []byte) ([]generalName, error) {
	var out []generalName
	for len(b) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(b, &rv)
		if err != nil {
			return out, err
		}
		if rv.Class == asn1.ClassContextSpecific {
			out = append(out, generalName{rv.Tag, rv.Bytes})
		}
		b = rest
	}
	return out, nil
}

// splitGeneralNames returns the URIs and the raw DER of all directory names.
// A directoryName is EXPLICITLY tagged, so its content is a complete Name.
func splitGeneralNames(gns []generalName) (uris []string, dirNames [][]byte) {
	for _, gn := range gns {
		switch gn.tag {
		case gnURI:
			uris = append(uris, string(gn.bytes))
		case gnDirectoryName:
			dirNames = append(dirNames, gn.bytes)
		}
	}
	return uris, dirNames
}

// unwrapSequence returns the content octets of the DER SEQUENCE in b.
func unwrapSequence(b []byte) ([]byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after SEQUENCE")
	}
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagSequence {
		return nil, errors.New("not a SEQUENCE")
	}
	return rv.Bytes, nil
}

// SameName reports whether two DER encoded X.501 Names are equal. Identical
// encodings match directly; otherwise the decoded RDN sequences are compared.
func SameName(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var ra, rb pkix.RDNSequence
	if _, err := asn1.Unmarshal(a, &ra); err != nil {
		return false
	}
	if _, err := asn1.Unmarshal(b, &rb); err != nil {
		return false
	}
	return ra.String() == rb.String()
}

// NameString renders a DER encoded Name in RFC 4514 form, or "<empty>".
func NameString(raw []byte) string {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdn); err != nil {
		return "<unparsable name>"
	}
	if s := rdn.String(); s != "" {
		return s
	}
	return "<empty>"
}
