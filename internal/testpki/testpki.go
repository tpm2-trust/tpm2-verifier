// Package testpki builds synthetic TPM certificate hierarchies for tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

var serial atomic.Int64

// CA is a certificate together with its private key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func newKey(t testing.TB) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func create(t testing.TB, tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// NewRoot creates a self-signed root CA.
func NewRoot(t testing.TB, name pkix.Name, notBefore, notAfter time.Time) *CA {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               name,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return &CA{create(t, tmpl, tmpl, k.Public(), k), k}
}

// IssueCA issues a subordinate CA. Validity defaults to the parent's.
func (ca *CA) IssueCA(t testing.TB, name pkix.Name, extra ...pkix.Extension) *CA {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               name,
		NotBefore:             ca.Cert.NotBefore,
		NotAfter:              ca.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IssuingCertificateURL: []string{AIAURL(ca.Cert)},
		ExtraExtensions:       extra,
	}
	return &CA{create(t, tmpl, ca.Cert, k.Public(), ca.Key), k}
}

// Issue signs an arbitrary template with this CA. A fresh key is generated.
func (ca *CA) Issue(t testing.TB, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	return ca.IssueFor(t, tmpl, newKey(t).Public())
}

// IssueFor signs a template for the public key pub, e.g. a TPM's EK.
func (ca *CA) IssueFor(t testing.TB, tmpl *x509.Certificate, pub any) *x509.Certificate {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(serial.Add(1))
	}
	if tmpl.IssuingCertificateURL == nil {
		tmpl.IssuingCertificateURL = []string{AIAURL(ca.Cert)}
	}
	return create(t, tmpl, ca.Cert, pub, ca.Key)
}

// CRL creates a DER encoded CRL signed by this CA.
func (ca *CA) CRL(t testing.TB, number int64, thisUpdate, nextUpdate time.Time, entries []x509.RevocationListEntry, extra ...pkix.Extension) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
		ExtraExtensions:           extra,
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// AIAURL is the AIA "CA Issuers" URL under which issuer is published.
func AIAURL(issuer *x509.Certificate) string {
	return "https://aia.example/" + issuer.SerialNumber.String() + ".cer"
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func dirName(name pkix.RDNSequence) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: mustMarshal(name)}
}

func uriName(uri string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}
}

func seq(elems ...asn1.RawValue) []byte {
	var b []byte
	for _, e := range elems {
		b = append(b, mustMarshal(e)...)
	}
	return mustMarshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: b})
}

func ctx(tag int, content []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: content}
}

// TPMSubjectAltName returns a critical subjectAltName holding the TCG TPM
// identity in a directoryName, as found in EK certificates.
func TPMSubjectAltName(manufacturer, model, version string) pkix.Extension {
	rdn := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: manufacturer}},
		{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: model}},
		{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: version}},
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: seq(dirName(rdn))}
}

// CRLDistributionPoint returns a CRL distribution points extension with one
// URI and, if crlIssuer is set, a cRLIssuer directoryName.
func CRLDistributionPoint(uri string, crlIssuer *pkix.Name) pkix.Extension {
	content := mustMarshal(ctx(0, mustMarshal(ctx(0, mustMarshal(uriName(uri))))))
	if crlIssuer != nil {
		content = append(content, mustMarshal(ctx(2, mustMarshal(dirName(crlIssuer.ToRDNSequence()))))...)
	}
	dp := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: content}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: seq(dp)}
}

// IndirectIDP returns a critical issuingDistributionPoint marking a CRL as indirect.
func IndirectIDP(uri string) pkix.Extension {
	content := mustMarshal(ctx(0, mustMarshal(ctx(0, mustMarshal(uriName(uri))))))
	content = append(content, mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, Bytes: []byte{0xff}})...)
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 28},
		Critical: true,
		Value:    mustMarshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: content}),
	}
}

// CertificateIssuer returns the CRL entry extension naming the issuer of
// this and all following entries of an indirect CRL.
func CertificateIssuer(name pkix.Name) pkix.Extension {
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: seq(dirName(name.ToRDNSequence()))}
}
