package testpki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

// URLs used by IntelLike.
const (
	URLRootCRL     = "https://crl.example/OnDie_CA.crl"
	URLProductCRL  = "https://crl.example/OnDie_CA_CSME_Product.crl"
	URLIssuingCRL  = "https://crl.example/MCC_OnDie_CA.crl"
	URLIndirectCRL = "https://crl.example/OnDie_CA_CSME_Indirect.crl"
)

// IntelChain mirrors the structure of an Intel PTT EK hierarchy.
type IntelChain struct {
	Root, Int1, Int2 *CA // static, published by the vendor
	ROM, Kernel, PTT *CA // per device, stored in NV 0x01C00100
	EK               *x509.Certificate
	Now              time.Time
}

// IntelLike builds a synthetic hierarchy with the same shape and quirks as
// Intel's: empty EK subject, critical TCG subjectAltName, TCG EK extended key
// usage, and per-device CAs whose CRL is an indirect CRL issued by Int1.
func IntelLike(t testing.TB) *IntelChain {
	t.Helper()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	c := &IntelChain{Now: now}
	c.Root = NewRoot(t, pkix.Name{Organization: []string{"Test Corp"}, OrganizationalUnit: []string{"OnDie CA Root Cert Signing"}, CommonName: "test.example"},
		now.AddDate(-7, 0, 0), now.AddDate(23, 0, 0))
	c.Int1 = c.Root.IssueCA(t, pkix.Name{OrganizationalUnit: []string{"OnDie CA CSME Intermediate CA"}, CommonName: "test.example"},
		CRLDistributionPoint(URLRootCRL, nil))
	c.Int2 = c.Int1.IssueCA(t, pkix.Name{OrganizationalUnit: []string{"On Die CSME P_MCC 00001881 Issuing CA"}, CommonName: "test.example"},
		CRLDistributionPoint(URLProductCRL, nil))
	c.ROM = c.Int2.IssueCA(t, pkix.Name{CommonName: "CSME MCC ROM CA"},
		CRLDistributionPoint(URLIssuingCRL, nil))
	int1Name := c.Int1.Cert.Subject
	c.Kernel = c.ROM.IssueCA(t, pkix.Name{CommonName: "CSME MCC SVN01 Kernel CA"},
		CRLDistributionPoint(URLIndirectCRL, &int1Name))
	c.PTT = c.Kernel.IssueCA(t, pkix.Name{CommonName: "CSME MCC PTT 01SVN"},
		CRLDistributionPoint(URLIndirectCRL, &int1Name))
	c.EK = c.PTT.Issue(t, &x509.Certificate{
		NotBefore:             c.PTT.Cert.NotBefore,
		NotAfter:              c.PTT.Cert.NotAfter,
		KeyUsage:              x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		ExtraExtensions: []pkix.Extension{
			TPMSubjectAltName("id:494E5443", "PTT", "id:00020008"),
			CRLDistributionPoint(URLIndirectCRL, &int1Name),
		},
	})
	return c
}

// DeviceChain returns the per-device intermediates as stored in NV
// 0x01C00100: concatenated DER, ROM CA first, followed by NV padding.
func (c *IntelChain) DeviceChain() []byte {
	var b []byte
	for _, ca := range []*CA{c.ROM, c.Kernel, c.PTT} {
		b = append(b, ca.Cert.Raw...)
	}
	for range 64 {
		b = append(b, 0xff)
	}
	return b
}

// CRLs returns the four CRLs of the hierarchy. Certificates in revoked are
// listed on the CRL responsible for them.
func (c *IntelChain) CRLs(t testing.TB, revoked ...*x509.Certificate) map[string][]byte {
	t.Helper()
	issued := func(by *CA) []x509.RevocationListEntry {
		var out []x509.RevocationListEntry
		for _, r := range revoked {
			if string(r.RawIssuer) == string(by.Cert.RawSubject) {
				out = append(out, x509.RevocationListEntry{SerialNumber: r.SerialNumber, RevocationTime: c.Now.AddDate(0, -1, 0)})
			}
		}
		return out
	}
	this, next := c.Now.AddDate(0, -1, 0), c.Now.AddDate(0, 3, 0)

	// The indirect CRL covers certificates issued by ROM, Kernel and PTT.
	var indirect []x509.RevocationListEntry
	for _, ca := range []*CA{c.ROM, c.Kernel, c.PTT} {
		entries := issued(ca)
		if len(entries) > 0 {
			entries[0].ExtraExtensions = []pkix.Extension{CertificateIssuer(ca.Cert.Subject)}
		}
		indirect = append(indirect, entries...)
	}
	return map[string][]byte{
		URLRootCRL:     c.Root.CRL(t, 1, this, next, issued(c.Root)),
		URLProductCRL:  c.Int1.CRL(t, 1, this, next, issued(c.Int1)),
		URLIssuingCRL:  c.Int2.CRL(t, 1, this, next, issued(c.Int2)),
		URLIndirectCRL: c.Int1.CRL(t, 2, this, next, indirect, IndirectIDP(URLIndirectCRL)),
	}
}
