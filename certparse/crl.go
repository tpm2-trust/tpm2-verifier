package certparse

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

var (
	OIDExtIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	OIDEntryCertificateIssuer      = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// CRL wraps an x509.RevocationList with indirect CRL support (RFC 5280,
// sections 5.2.5 and 5.3.3).
type CRL struct {
	*x509.RevocationList

	// Indirect is set if the issuingDistributionPoint marks the CRL as indirect,
	// i.e. it may list certificates issued by CAs other than the CRL issuer.
	Indirect bool
	// URIs are the distribution point names from issuingDistributionPoint.
	URIs []string

	// entryIssuers[i] is the DER Name of the issuer of RevokedCertificateEntries[i].
	entryIssuers [][]byte
}

// ParseCRL parses a DER (or PEM) encoded CRL.
func ParseCRL(data []byte) (*CRL, error) {
	ders, err := SplitAny(data)
	if err != nil {
		return nil, err
	}
	if len(ders) != 1 {
		return nil, fmt.Errorf("certparse: expected one CRL, found %d elements", len(ders))
	}
	rl, err := x509.ParseRevocationList(ders[0])
	if err != nil {
		return nil, err
	}
	c := &CRL{RevocationList: rl}
	for _, ext := range rl.Extensions {
		if ext.Id.Equal(OIDExtIssuingDistributionPoint) {
			if err := c.parseIDP(ext.Value); err != nil {
				return nil, fmt.Errorf("certparse: issuing distribution point: %w", err)
			}
		}
	}
	// Entries of an indirect CRL belong to the CRL issuer until a
	// certificateIssuer entry extension switches to another CA; the switch
	// stays in effect for all following entries.
	current := rl.RawIssuer
	for _, e := range rl.RevokedCertificateEntries {
		for _, ext := range e.Extensions {
			if !ext.Id.Equal(OIDEntryCertificateIssuer) {
				continue
			}
			content, err := unwrapSequence(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("certparse: certificate issuer entry: %w", err)
			}
			gns, err := parseGeneralNames(content)
			if err != nil {
				return nil, fmt.Errorf("certparse: certificate issuer entry: %w", err)
			}
			if _, dns := splitGeneralNames(gns); len(dns) > 0 {
				current = dns[0]
			}
		}
		c.entryIssuers = append(c.entryIssuers, current)
	}
	return c, nil
}

func (c *CRL) parseIDP(b []byte) error {
	content, err := unwrapSequence(b)
	if err != nil {
		return err
	}
	for len(content) > 0 {
		var f asn1.RawValue
		content, err = asn1.Unmarshal(content, &f)
		if err != nil {
			return err
		}
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		switch f.Tag {
		case 0:
			var name asn1.RawValue
			if _, err := asn1.Unmarshal(f.Bytes, &name); err != nil {
				return err
			}
			if name.Tag == 0 {
				gns, err := parseGeneralNames(name.Bytes)
				if err != nil {
					return err
				}
				c.URIs, _ = splitGeneralNames(gns)
			}
		case 4: // indirectCRL [4] BOOLEAN (implicit)
			c.Indirect = len(f.Bytes) == 1 && f.Bytes[0] != 0
		}
	}
	return nil
}

// Lookup returns the revocation entry for the certificate with the given
// serial number issued by issuer (DER Name), if any.
func (c *CRL) Lookup(serial *big.Int, issuer []byte) (*x509.RevocationListEntry, bool) {
	for i := range c.RevokedCertificateEntries {
		e := &c.RevokedCertificateEntries[i]
		if e.SerialNumber.Cmp(serial) == 0 && SameName(c.entryIssuers[i], issuer) {
			return e, true
		}
	}
	return nil, false
}

// IssuerString returns the CRL issuer in RFC 4514 form.
func (c *CRL) IssuerString() string { return NameString(c.RawIssuer) }
