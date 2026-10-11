package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/store"
)

func runInspect(args []string, stdout io.Writer) error {
	fs := newFlagSet("inspect", "<file>...",
		"Shows certificates and CRLs. A file may contain several concatenated DER or PEM\n"+
			"certificates. Certificates found in the vendor store are marked.")
	asJSON := fs.Bool("json", false, "JSON output")
	overlay := fs.String("store", "", "additional vendor store directory")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		fs.Usage()
		return exitError(2)
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	var all []any
	for _, f := range pos {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if crl, err := certparse.ParseCRL(data); err == nil {
			info := crlInfo(f, crl)
			if *asJSON {
				all = append(all, info)
			} else {
				printCRL(stdout, info)
			}
			continue
		}
		certs, err := certparse.ParseAll(data)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		for i, c := range certs {
			info := certInfo(fmt.Sprintf("%s[%d]", f, i), c, st)
			if *asJSON {
				all = append(all, info)
			} else {
				printCert(stdout, info)
			}
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(all)
	}
	return nil
}

type certSummary struct {
	File               string               `json:"file"`
	Subject            string               `json:"subject"`
	Issuer             string               `json:"issuer"`
	Serial             string               `json:"serial"`
	NotBefore          time.Time            `json:"not_before"`
	NotAfter           time.Time            `json:"not_after"`
	SHA256             string               `json:"sha256"`
	SignatureAlgorithm string               `json:"signature_algorithm"`
	PublicKey          string               `json:"public_key"`
	CA                 bool                 `json:"ca"`
	PathLen            *int                 `json:"path_len,omitempty"`
	SelfSigned         bool                 `json:"self_signed"`
	EK                 bool                 `json:"ek_certificate"`
	TPM                *certparse.TPMInfo   `json:"tpm,omitempty"`
	SubjectKeyID       string               `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string               `json:"authority_key_id,omitempty"`
	CAIssuers          []string             `json:"ca_issuers,omitempty"`
	CRLs               []crlDistributionDTO `json:"crl_distribution_points,omitempty"`
	UnhandledCritical  []string             `json:"unhandled_critical_extensions,omitempty"`
	Quirks             []certparse.Quirk    `json:"quirks,omitempty"`
	Store              string               `json:"store,omitempty"`
}

type crlDistributionDTO struct {
	URIs      []string `json:"uris"`
	CRLIssuer []string `json:"crl_issuer,omitempty"`
}

func certInfo(file string, c *certparse.Certificate, st *store.Store) certSummary {
	s := certSummary{
		File:               file,
		Subject:            c.SubjectString(),
		Issuer:             c.IssuerString(),
		Serial:             c.SerialNumber.Text(16),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		SHA256:             c.Fingerprint,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKey:          describeKey(c.PublicKey),
		CA:                 c.IsCA,
		SelfSigned:         c.IsSelfSigned(),
		EK:                 c.IsEK,
		TPM:                c.TPM,
		SubjectKeyID:       colonHex(c.SubjectKeyId),
		AuthorityKeyID:     colonHex(c.AuthorityKeyId),
		CAIssuers:          c.IssuingCertificateURL,
		Quirks:             c.Quirks,
	}
	if c.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
		n := c.MaxPathLen
		s.PathLen = &n
	}
	for _, dp := range c.DistributionPoints {
		d := crlDistributionDTO{URIs: dp.URIs}
		for _, n := range dp.CRLIssuer {
			d.CRLIssuer = append(d.CRLIssuer, certparse.NameString(n))
		}
		s.CRLs = append(s.CRLs, d)
	}
	for _, oid := range c.UnhandledCriticalExtensions {
		s.UnhandledCritical = append(s.UnhandledCritical, oidName(oid))
	}
	if e := st.ByFingerprint(c.Fingerprint); e != nil {
		s.Store = fmt.Sprintf("%s/%s (%s)", e.Vendor.ID, e.File, e.Role)
	}
	return s
}

func printCert(w io.Writer, s certSummary) {
	fmt.Fprintf(w, "== %s\n", s.File)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "  %-20s %s\n", k+":", v)
		}
	}
	row("Subject", s.Subject)
	row("Issuer", s.Issuer)
	row("Serial", s.Serial)
	row("Validity", fmt.Sprintf("%s .. %s", s.NotBefore.Format(time.DateOnly), s.NotAfter.Format(time.DateOnly)))
	row("SHA-256", s.SHA256)
	row("Signature", s.SignatureAlgorithm)
	row("Public key", s.PublicKey)
	kind := "end entity"
	if s.CA {
		kind = "CA"
		if s.PathLen != nil {
			kind += fmt.Sprintf(", pathlen %d", *s.PathLen)
		}
	}
	if s.SelfSigned {
		kind += ", self-signed"
	}
	if s.EK {
		kind += ", TCG EK certificate"
	}
	row("Type", kind)
	if s.TPM != nil {
		row("TPM", fmt.Sprintf("manufacturer %s (%s), model %q, version %s", s.TPM.Manufacturer, s.TPM.ManufacturerRaw, s.TPM.Model, s.TPM.Version))
	}
	row("Subject key ID", s.SubjectKeyID)
	row("Authority key ID", s.AuthorityKeyID)
	for _, u := range s.CAIssuers {
		row("AIA CA issuers", u)
	}
	for _, d := range s.CRLs {
		for _, u := range d.URIs {
			row("CRL", u)
		}
		for _, n := range d.CRLIssuer {
			row("CRL issuer", n)
		}
	}
	row("Unhandled critical", strings.Join(s.UnhandledCritical, ", "))
	for _, q := range s.Quirks {
		row("Quirk", q.Code+": "+q.Detail)
	}
	row("Vendor store", s.Store)
	fmt.Fprintln(w)
}

type crlSummary struct {
	File       string    `json:"file"`
	Issuer     string    `json:"issuer"`
	Number     string    `json:"number,omitempty"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
	Indirect   bool      `json:"indirect"`
	URIs       []string  `json:"distribution_point,omitempty"`
	Revoked    int       `json:"revoked_entries"`
}

func crlInfo(file string, crl *certparse.CRL) crlSummary {
	s := crlSummary{
		File:       file,
		Issuer:     crl.IssuerString(),
		ThisUpdate: crl.ThisUpdate,
		NextUpdate: crl.NextUpdate,
		Indirect:   crl.Indirect,
		URIs:       crl.URIs,
		Revoked:    len(crl.RevokedCertificateEntries),
	}
	if crl.Number != nil {
		s.Number = crl.Number.String()
	}
	return s
}

func printCRL(w io.Writer, s crlSummary) {
	fmt.Fprintf(w, "== %s (CRL)\n", s.File)
	fmt.Fprintf(w, "  %-20s %s\n", "Issuer:", s.Issuer)
	fmt.Fprintf(w, "  %-20s %s\n", "CRL number:", s.Number)
	fmt.Fprintf(w, "  %-20s %s .. %s\n", "Validity:", s.ThisUpdate.Format(time.DateOnly), s.NextUpdate.Format(time.DateOnly))
	fmt.Fprintf(w, "  %-20s %v\n", "Indirect:", s.Indirect)
	fmt.Fprintf(w, "  %-20s %d\n\n", "Revoked entries:", s.Revoked)
}

func describeKey(k any) string {
	switch k := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", k)
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

func oidName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(certparse.OIDExtSubjectAltName):
		return oid.String() + " (subjectAltName)"
	case oid.Equal(certparse.OIDExtSubjectDirectoryAttrs):
		return oid.String() + " (subjectDirectoryAttributes)"
	}
	return oid.String()
}
