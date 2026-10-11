// Package certparse parses TPM endorsement key certificates and the CA
// certificates above them, including the TCG specific encodings that the Go
// standard library does not understand on its own.
package certparse

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// Well known object identifiers.
var (
	OIDExtSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDExtSubjectDirectoryAttrs = asn1.ObjectIdentifier{2, 5, 29, 9}
	OIDExtCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

	OIDTPMManufacturer  = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	OIDTPMModel         = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	OIDTPMVersion       = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	OIDTPMSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 16}

	OIDEKUEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
)

// Quirk codes. Quirks are deviations from what a generic X.509 validator
// expects; they are informational and do not make a certificate invalid.
const (
	QuirkEmptySubject           = "empty-subject"
	QuirkTCGSubjectAltName      = "tcg-san-directory-name"
	QuirkTCGSubjectDirAttrs     = "tcg-subject-directory-attributes"
	QuirkNegativeSerial         = "negative-serial"
	QuirkUnhandledCriticalExt   = "unhandled-critical-extension"
	QuirkMissingKeyIdentifiers  = "missing-key-identifiers"
	QuirkLegacyVersion          = "legacy-x509-version"
	QuirkInsecureSignatureAlg   = "insecure-signature-algorithm"
	QuirkNameConstraintsPresent = "name-constraints-present"
)

// Quirk describes one deviation found while parsing.
type Quirk struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// TPMInfo is the TPM identity encoded in an EK certificate (TCG EK Credential
// Profile, subjectAltName directoryName).
type TPMInfo struct {
	// Manufacturer is the decoded 4 character vendor ID, e.g. "INTC".
	Manufacturer string `json:"manufacturer,omitempty"`
	// ManufacturerRaw is the attribute as encoded, e.g. "id:494E5443".
	ManufacturerRaw string `json:"manufacturer_raw,omitempty"`
	Model           string `json:"model,omitempty"`
	Version         string `json:"version,omitempty"`
}

// DistributionPoint is one entry of the CRL distribution points extension.
// The standard library keeps only the URIs and drops cRLIssuer, which is
// required for indirect CRLs such as Intel's OnDie_CA_CSME_Indirect.crl.
type DistributionPoint struct {
	URIs []string `json:"uris,omitempty"`
	// CRLIssuer holds DER encoded Names of the CRL issuer if it is not the
	// certificate issuer.
	CRLIssuer [][]byte `json:"-"`
}

// Certificate wraps an x509.Certificate with TPM specific information.
type Certificate struct {
	*x509.Certificate

	// Fingerprint is the hex SHA-256 of the DER encoding.
	Fingerprint string
	// TPM is set if the certificate carries TCG TPM identity attributes.
	TPM *TPMInfo
	// IsEK is set if the certificate has the TCG EK certificate extended key usage.
	IsEK bool
	// DistributionPoints is the parsed CRL distribution points extension.
	DistributionPoints []DistributionPoint
	// Quirks lists deviations noticed while parsing.
	Quirks []Quirk
}

// Parse parses a single DER encoded certificate.
//
// The TCG critical subjectAltName (which only contains a directoryName) and
// critical subjectDirectoryAttributes are decoded here and removed from
// UnhandledCriticalExtensions so that they do not fail chain validation.
//
// Since Go 1.23 certificates with a negative serial number are rejected
// unless the program is built with "//go:debug x509negativeserial=1" (the
// tpm2-ek command is) or run with GODEBUG=x509negativeserial=1.
func Parse(der []byte) (*Certificate, error) {
	xc, err := x509.ParseCertificate(der)
	if err != nil {
		if strings.Contains(err.Error(), "negative serial") {
			return nil, fmt.Errorf("%w (set GODEBUG=x509negativeserial=1 to accept it)", err)
		}
		return nil, err
	}
	sum := sha256.Sum256(xc.Raw)
	c := &Certificate{Certificate: xc, Fingerprint: hex.EncodeToString(sum[:])}

	for _, ext := range xc.Extensions {
		switch {
		case ext.Id.Equal(OIDExtSubjectAltName):
			c.parseSAN(ext)
		case ext.Id.Equal(OIDExtSubjectDirectoryAttrs):
			c.parseSubjectDirectoryAttributes(ext)
		case ext.Id.Equal(OIDExtCRLDistributionPoints):
			dps, err := parseDistributionPoints(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("certparse: CRL distribution points: %w", err)
			}
			c.DistributionPoints = dps
		}
	}
	c.IsEK = slices.ContainsFunc(xc.UnknownExtKeyUsage, OIDEKUEKCertificate.Equal)

	if len(xc.RawSubject) == 0 || len(xc.Subject.Names) == 0 {
		c.addQuirk(QuirkEmptySubject, "subject is empty, identity is in subjectAltName")
	}
	if xc.SerialNumber.Sign() < 0 {
		c.addQuirk(QuirkNegativeSerial, "serial number is negative")
	}
	if xc.Version < 3 {
		c.addQuirk(QuirkLegacyVersion, fmt.Sprintf("X.509 version %d", xc.Version))
	}
	if !c.IsSelfSigned() && len(xc.AuthorityKeyId) == 0 {
		c.addQuirk(QuirkMissingKeyIdentifiers, "no authority key identifier")
	}
	switch xc.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.DSAWithSHA1:
		c.addQuirk(QuirkInsecureSignatureAlg, xc.SignatureAlgorithm.String())
	}
	if len(xc.PermittedDNSDomains)+len(xc.ExcludedDNSDomains)+len(xc.PermittedIPRanges)+
		len(xc.ExcludedIPRanges)+len(xc.PermittedEmailAddresses)+len(xc.ExcludedEmailAddresses)+
		len(xc.PermittedURIDomains)+len(xc.ExcludedURIDomains) > 0 {
		c.addQuirk(QuirkNameConstraintsPresent, "name constraints are not evaluated")
	}
	for _, oid := range xc.UnhandledCriticalExtensions {
		c.addQuirk(QuirkUnhandledCriticalExt, oid.String())
	}
	return c, nil
}

// ParseAll parses PEM or concatenated DER input into certificates.
func ParseAll(data []byte) ([]*Certificate, error) {
	ders, err := SplitAny(data)
	if err != nil {
		return nil, err
	}
	out := make([]*Certificate, 0, len(ders))
	for i, der := range ders {
		c, err := Parse(der)
		if err != nil {
			return out, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// IsSelfSigned reports whether subject equals issuer and the certificate's
// signature verifies with its own key.
func (c *Certificate) IsSelfSigned() bool {
	if !SameName(c.RawSubject, c.RawIssuer) {
		return false
	}
	return CheckSignature(c.Certificate, c.Certificate) == nil
}

// SubjectString returns the subject in RFC 4514 form or "<empty>".
func (c *Certificate) SubjectString() string { return NameString(c.RawSubject) }

// IssuerString returns the issuer in RFC 4514 form.
func (c *Certificate) IssuerString() string { return NameString(c.RawIssuer) }

// HasQuirk reports whether the quirk with the given code was found.
func (c *Certificate) HasQuirk(code string) bool {
	return slices.ContainsFunc(c.Quirks, func(q Quirk) bool { return q.Code == code })
}

// CRLURIs returns all CRL distribution point URIs.
func (c *Certificate) CRLURIs() []string {
	var out []string
	for _, dp := range c.DistributionPoints {
		out = append(out, dp.URIs...)
	}
	return out
}

func (c *Certificate) addQuirk(code, detail string) {
	c.Quirks = append(c.Quirks, Quirk{code, detail})
}

// markHandled removes oid from UnhandledCriticalExtensions.
func (c *Certificate) markHandled(oid asn1.ObjectIdentifier) {
	c.UnhandledCriticalExtensions = slices.DeleteFunc(c.UnhandledCriticalExtensions, oid.Equal)
}

func (c *Certificate) parseSAN(ext pkix.Extension) {
	content, err := unwrapSequence(ext.Value)
	if err != nil {
		return
	}
	gns, err := parseGeneralNames(content)
	if err != nil {
		return
	}
	_, dirNames := splitGeneralNames(gns)
	for _, dn := range dirNames {
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(dn, &rdn); err != nil {
			continue
		}
		if info := tpmInfoFromAttributes(rdn); info != nil {
			c.TPM = info
			if ext.Critical {
				c.markHandled(OIDExtSubjectAltName)
			}
			c.addQuirk(QuirkTCGSubjectAltName, "TPM identity in subjectAltName directoryName")
		}
	}
}

func tpmInfoFromAttributes(rdn pkix.RDNSequence) *TPMInfo {
	var info TPMInfo
	found := false
	for _, set := range rdn {
		for _, atv := range set {
			s := fmt.Sprint(atv.Value)
			switch {
			case atv.Type.Equal(OIDTPMManufacturer):
				info.ManufacturerRaw = s
				info.Manufacturer = DecodeManufacturer(s)
				found = true
			case atv.Type.Equal(OIDTPMModel):
				info.Model = s
				found = true
			case atv.Type.Equal(OIDTPMVersion):
				info.Version = s
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return &info
}

// DecodeManufacturer turns the TCG encoding "id:494E5443" into "INTC".
// Values that are not in that form are returned unchanged.
func DecodeManufacturer(s string) string {
	h, ok := strings.CutPrefix(strings.ToLower(s), "id:")
	if !ok {
		return s
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return s
	}
	return NormalizeManufacturer(string(b))
}

// NormalizeManufacturer trims NUL bytes and spaces from a TPM manufacturer ID
// ("IFX\x00" -> "IFX") and upper-cases it.
func NormalizeManufacturer(s string) string {
	return strings.ToUpper(strings.Trim(s, "\x00 "))
}

// parseSubjectDirectoryAttributes accepts the TCG TPM specification
// attribute. The content is not interpreted further.
func (c *Certificate) parseSubjectDirectoryAttributes(ext pkix.Extension) {
	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	var attrs []attribute
	if _, err := asn1.Unmarshal(ext.Value, &attrs); err != nil {
		return
	}
	for _, a := range attrs {
		if a.Type.Equal(OIDTPMSpecification) {
			if ext.Critical {
				c.markHandled(OIDExtSubjectDirectoryAttrs)
			}
			c.addQuirk(QuirkTCGSubjectDirAttrs, "TPM specification in subjectDirectoryAttributes")
			return
		}
	}
}

func parseDistributionPoints(b []byte) ([]DistributionPoint, error) {
	content, err := unwrapSequence(b)
	if err != nil {
		return nil, err
	}
	var out []DistributionPoint
	for len(content) > 0 {
		var dpSeq asn1.RawValue
		content, err = asn1.Unmarshal(content, &dpSeq)
		if err != nil {
			return out, err
		}
		var dp DistributionPoint
		fields := dpSeq.Bytes
		for len(fields) > 0 {
			var f asn1.RawValue
			fields, err = asn1.Unmarshal(fields, &f)
			if err != nil {
				return out, err
			}
			if f.Class != asn1.ClassContextSpecific {
				continue
			}
			switch f.Tag {
			case 0: // distributionPoint: DistributionPointName (CHOICE, explicit)
				var name asn1.RawValue
				if _, err := asn1.Unmarshal(f.Bytes, &name); err != nil {
					return out, err
				}
				if name.Class == asn1.ClassContextSpecific && name.Tag == 0 { // fullName
					gns, err := parseGeneralNames(name.Bytes)
					if err != nil {
						return out, err
					}
					dp.URIs, _ = splitGeneralNames(gns)
				}
			case 2: // cRLIssuer: GeneralNames (implicit)
				gns, err := parseGeneralNames(f.Bytes)
				if err != nil {
					return out, err
				}
				_, dp.CRLIssuer = splitGeneralNames(gns)
			}
		}
		out = append(out, dp)
	}
	return out, nil
}
