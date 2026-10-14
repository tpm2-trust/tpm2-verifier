// Package vendorinfo collects what is needed to add a TPM vendor to the
// vendor store, without anything that identifies the TPM it came from.
//
// It is the anonymous counterpart of a debug bundle. It contains:
//
//   - the TPM identity (manufacturer, vendor string, firmware, spec) and the
//     NV index layout (index, attributes, size, readability), no NV content;
//   - the DER files of the public CA certificates of each EK chain: those in
//     the store, downloaded via AIA, or explicitly included;
//   - a structural description of every other certificate (the EK and
//     per-device CAs): names with device specific values redacted, key and
//     signature algorithm, extensions, URLs, TCG attributes, quirks. Serial
//     numbers, public keys, signatures, key identifiers, fingerprints and
//     validity dates are not included;
//   - a draft vendor directory (vendor.yaml, README.md, roots/,
//     intermediates/) that can be used as a store overlay.
package vendorinfo

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/possession"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

// FormatVersion of info.json.
const FormatVersion = 1

// Options configure Build.
type Options struct {
	// Tool is recorded in info.json, e.g. "tpm2-ek v0.4.0".
	Tool string
	// Created is recorded truncated to the day (default now).
	Created time.Time
	// Published maps fingerprints of certificates known to be published by
	// the vendor to the URL they were downloaded from. Certificates of the
	// store are public without being listed.
	Published map[string]string
	// Include lists fingerprints of further certificates read from the TPM
	// to include in full, e.g. a vendor CA stored in NV that is shared by
	// all devices but published nowhere.
	Include []string
	// Strict redacts all attribute values of non-public CA names except
	// country and organization, not only serial numbers, IDs and long
	// hex/digit runs.
	Strict bool
	// Platform is recorded as is (e.g. DMI vendor/model); nil omits it.
	Platform map[string]string
}

// EKReport is the verification of one EK certificate index.
type EKReport struct {
	Index  uint32
	Report *verify.Report
	// Possession is the proof of EK possession, if one was made.
	Possession *possession.Result
}

// Info is the content of info.json.
type Info struct {
	Format   int               `json:"format"`
	Tool     string            `json:"tool,omitempty"`
	Created  string            `json:"created"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Platform map[string]string `json:"platform,omitempty"`
	TPM      *tpm.Info         `json:"tpm"`
	NV       []NVIndex         `json:"nv"`
	EK       []EK              `json:"ek"`
	// Certificates are the public CA certificates included as files.
	Certificates []PublicCert `json:"certificates"`
	// Draft is the path of the draft vendor directory.
	Draft string `json:"draft"`

	files map[string][]byte
}

// NVIndex describes one NV index without its content.
type NVIndex struct {
	Index         string    `json:"index"`
	Label         string    `json:"label"`
	Attributes    string    `json:"attributes,omitempty"`
	AttributesRaw uint32    `json:"attributes_raw,omitempty"`
	NameAlg       uint16    `json:"name_alg,omitempty"`
	AuthPolicy    string    `json:"auth_policy,omitempty"`
	Size          uint16    `json:"size,omitempty"`
	Readable      bool      `json:"readable"`
	ReadError     string    `json:"read_error,omitempty"`
	Certificates  []CertRef `json:"certificates,omitempty"`
	ParseError    string    `json:"parse_error,omitempty"`
}

// CertRef is a certificate found in an NV index.
type CertRef struct {
	Subject      string `json:"subject"`
	KeyAlgorithm string `json:"key_algorithm"`
	CA           bool   `json:"ca"`
	Public       bool   `json:"public"`
	SHA256       string `json:"sha256,omitempty"` // public certificates only
}

// EK is the verification result of one EK certificate index.
type EK struct {
	Index  string        `json:"index"`
	Label  string        `json:"label"`
	Status verify.Status `json:"status"`
	Vendor string        `json:"vendor,omitempty"`
	// Possession is the result of the proof of EK possession, if one was
	// made: it shows whether the vendor's EKs follow the TCG templates.
	Possession *Possession `json:"possession,omitempty"`
	// Structure summarizes the chain: levels and certificate types.
	Structure Structure `json:"structure"`
	// Chain starts with the EK certificate.
	Chain []Cert `json:"chain"`
}

// Possession is the non-identifying part of a possession.Result.
type Possession struct {
	Status   possession.Status `json:"status"`
	Template string            `json:"template,omitempty"`
}

// Roles of certificates in a chain.
const (
	RoleEK       = "ek"        // the EK certificate
	RoleDeviceCA = "device-ca" // CA certificate not published (usually per device, from the TPM)
	RoleVendorCA = "vendor-ca" // published intermediate CA
	RoleRoot     = "root"      // self-signed
)

// Structure is the shape of an EK chain, independent of the device.
type Structure struct {
	// Levels is the number of certificates, EK included.
	Levels int `json:"levels"`
	// Complete is false if no issuer was found for the last certificate.
	Complete bool    `json:"complete"`
	Shape    []Level `json:"shape"`
	// Summary reads root first, e.g.
	// "root(ECDSA P-384) > vendor-ca(ECDSA P-384) > device-ca(ECDSA P-256) x3 > ek(RSA 2048)".
	Summary string `json:"summary"`
}

// Level is one certificate of a Structure, starting with the EK.
type Level struct {
	Role         string        `json:"role"`
	KeyAlgorithm string        `json:"key_algorithm"`
	Source       verify.Source `json:"source"`
	InTPM        bool          `json:"in_tpm"`
}

func structure(chain []Cert, status verify.Status) Structure {
	st := Structure{Levels: len(chain), Complete: status != verify.StatusIncomplete}
	for i, c := range chain {
		role := RoleDeviceCA
		switch {
		case i == 0:
			role = RoleEK
		case c.SelfSigned:
			role = RoleRoot
		case c.Public:
			role = RoleVendorCA
		}
		st.Shape = append(st.Shape, Level{Role: role, KeyAlgorithm: c.KeyAlgorithm, Source: c.Source,
			InTPM: c.Source == verify.SourceLeaf || c.Source == verify.SourceProvided})
	}
	st.Summary = ShapeSummary(st.Shape, st.Complete)
	return st
}

// ShapeSummary renders a chain shape root first, collapsing repeated levels.
func ShapeSummary(shape []Level, complete bool) string {
	var parts []string
	if !complete {
		parts = append(parts, "?")
	}
	for i := len(shape) - 1; i >= 0; {
		l := shape[i]
		n := 1
		for i-n >= 0 && shape[i-n].Role == l.Role && shape[i-n].KeyAlgorithm == l.KeyAlgorithm {
			n++
		}
		p := fmt.Sprintf("%s(%s)", l.Role, l.KeyAlgorithm)
		if n > 1 {
			p += fmt.Sprintf(" x%d", n)
		}
		parts = append(parts, p)
		i -= n
	}
	return strings.Join(parts, " > ")
}

// Cert describes one certificate of a chain. For non-public certificates,
// identifying values are omitted or redacted.
type Cert struct {
	Depth  int           `json:"depth"`
	Source verify.Source `json:"source"`
	Public bool          `json:"public"`
	// SHA256, File and URL are set for public certificates only.
	SHA256    string `json:"sha256,omitempty"`
	File      string `json:"file,omitempty"`
	URL       string `json:"url,omitempty"`
	StorePath string `json:"store_path,omitempty"`

	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	// Redacted is set if values of Subject or Issuer were redacted.
	Redacted bool `json:"redacted,omitempty"`

	Version            int    `json:"version"`
	SerialLength       int    `json:"serial_length"`
	KeyAlgorithm       string `json:"key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	// NotBefore and NotAfter are set for public certificates only.
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	ValidityDays int        `json:"validity_days"`

	CA          bool        `json:"ca"`
	SelfSigned  bool        `json:"self_signed,omitempty"`
	MaxPathLen  *int        `json:"max_path_len,omitempty"`
	KeyUsage    []string    `json:"key_usage,omitempty"`
	ExtKeyUsage []string    `json:"ext_key_usage,omitempty"`
	Extensions  []Extension `json:"extensions,omitempty"`
	CRLs        []string    `json:"crl_distribution_points,omitempty"`
	CRLIssuers  []string    `json:"crl_issuers,omitempty"`
	AIAIssuers  []string    `json:"aia_ca_issuers,omitempty"`
	OCSP        []string    `json:"ocsp,omitempty"`
	Policies    []string    `json:"policies,omitempty"`

	TPM        *certparse.TPMInfo      `json:"tpm,omitempty"`
	Quirks     []certparse.Quirk       `json:"quirks,omitempty"`
	Revocation verify.RevocationStatus `json:"revocation"`
}

// Extension is an extension present in a certificate (without its value).
type Extension struct {
	OID      string `json:"oid"`
	Name     string `json:"name,omitempty"`
	Critical bool   `json:"critical,omitempty"`
}

// PublicCert is a public certificate included as a file.
type PublicCert struct {
	SHA256    string `json:"sha256"`
	File      string `json:"file"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Root      bool   `json:"self_signed,omitempty"`
	URL       string `json:"url,omitempty"`
	StorePath string `json:"store_path,omitempty"`
	Included  bool   `json:"included_on_request,omitempty"`
}

// Build collects the vendor information from a scan and the verification of
// its EK certificates.
func Build(s *tpm.Scan, eks []EKReport, st *store.Store, opts Options) (*Info, error) {
	created := opts.Created
	if created.IsZero() {
		created = time.Now()
	}
	created = created.UTC()
	info := &Info{
		Format:   FormatVersion,
		Tool:     opts.Tool,
		Created:  created.Format(time.DateOnly),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Platform: opts.Platform,
		files:    map[string][]byte{},
	}
	ti := *s.Info
	ti.Properties = nil
	info.TPM = &ti

	include := map[string]bool{}
	for _, fp := range opts.Include {
		include[strings.ToLower(fp)] = true
	}
	public := func(c *certparse.Certificate) (bool, string, *store.Entry) {
		e := st.ByFingerprint(c.Fingerprint)
		if u, ok := opts.Published[c.Fingerprint]; ok {
			return true, u, e
		}
		return e != nil || include[c.Fingerprint], "", e
	}
	pub := map[string]*PublicCert{}
	addPublic := func(c *certparse.Certificate, url string, e *store.Entry) *PublicCert {
		if p, ok := pub[c.Fingerprint]; ok {
			return p
		}
		p := &PublicCert{
			SHA256: c.Fingerprint, File: "certs/" + c.Fingerprint + ".der",
			Subject: c.SubjectString(), Issuer: c.IssuerString(), Root: c.IsSelfSigned(), URL: url,
		}
		if e != nil {
			p.StorePath = e.Vendor.ID + "/" + e.File
		} else if url == "" {
			p.Included = true
		}
		pub[c.Fingerprint] = p
		info.files[p.File] = c.Raw
		info.Certificates = append(info.Certificates, *p)
		return p
	}

	for _, e := range s.Entries {
		n := NVIndex{Index: tpm.HexIndex(e.Index), Label: e.Label.String(), ReadError: e.ReadError, ParseError: e.ParseError}
		if p := e.Public; p != nil {
			n.Attributes, n.AttributesRaw, n.NameAlg, n.Size = p.Attributes.String(), uint32(p.Attributes), p.NameAlg, p.Size
			n.AuthPolicy = fmt.Sprintf("%x", p.AuthPolicy)
		}
		n.Readable = tpm.IsTCG(e.Index) && e.ReadError == "" && e.Public != nil
		for _, c := range e.Certificates {
			ok, _, _ := public(c)
			ref := CertRef{CA: c.IsCA, Public: ok, KeyAlgorithm: keyAlgorithm(c.Certificate)}
			if ok {
				ref.Subject, ref.SHA256 = c.SubjectString(), c.Fingerprint
			} else {
				ref.Subject, _ = redactName(c.RawSubject, opts.Strict || !c.IsCA)
			}
			n.Certificates = append(n.Certificates, ref)
		}
		info.NV = append(info.NV, n)
	}

	for _, r := range eks {
		label := tpm.Describe(r.Index).String()
		ek := EK{Index: tpm.HexIndex(r.Index), Label: label, Status: r.Report.Status, Vendor: r.Report.Vendor}
		chain := r.Report.Chain
		for i, l := range chain {
			c := l.Cert
			d := describe(c)
			d.Depth, d.Source, d.Revocation = i, l.Source, l.Revocation.Status
			ok, url, e := public(c)
			if l.Source == verify.SourceAIA || l.Source == verify.SourceStore {
				ok = true
			}
			if ok {
				p := addPublic(c, url, e)
				d.Public, d.SHA256, d.File, d.URL, d.StorePath = true, c.Fingerprint, p.File, p.URL, p.StorePath
				d.Subject, d.Issuer = c.SubjectString(), c.IssuerString()
				nb, na := c.NotBefore, c.NotAfter
				d.NotBefore, d.NotAfter = &nb, &na
			} else {
				var r1, r2 bool
				d.Subject, r1 = redactName(c.RawSubject, opts.Strict || !c.IsCA)
				d.Issuer = c.IssuerString()
				// The issuer's name is redacted like its subject if the
				// issuer is not public; an unknown issuer is kept, it is
				// what has to be found.
				if i+1 < len(chain) {
					if pc := chain[i+1].Cert; !c.IsSelfSigned() {
						if pok, _, _ := public(pc); !pok && chain[i+1].Source != verify.SourceAIA && chain[i+1].Source != verify.SourceStore {
							d.Issuer, r2 = redactName(c.RawIssuer, opts.Strict || !pc.IsCA)
						}
					}
				}
				d.Redacted = r1 || r2
				d.TPM = c.TPM
			}
			ek.Chain = append(ek.Chain, d)
		}
		ek.Structure = structure(ek.Chain, ek.Status)
		if p := r.Possession; p != nil {
			ek.Possession = &Possession{Status: p.Status, Template: p.Template}
		}
		info.EK = append(info.EK, ek)
	}
	if err := info.buildDraft(s, eks, st, created); err != nil {
		return nil, err
	}
	return info, nil
}

// describe returns the non-identifying properties of a certificate.
func describe(c *certparse.Certificate) Cert {
	d := Cert{
		Version:            c.Version,
		SerialLength:       len(c.SerialNumber.Bytes()),
		KeyAlgorithm:       keyAlgorithm(c.Certificate),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		ValidityDays:       int(c.NotAfter.Sub(c.NotBefore).Round(24*time.Hour) / (24 * time.Hour)),
		CA:                 c.IsCA,
		SelfSigned:         c.IsSelfSigned(),
		KeyUsage:           keyUsage(c.KeyUsage),
		CRLs:               c.CRLURIs(),
		AIAIssuers:         c.IssuingCertificateURL,
		OCSP:               c.OCSPServer,
		Quirks:             c.Quirks,
		TPM:                c.TPM,
	}
	if c.BasicConstraintsValid && c.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
		n := c.MaxPathLen
		d.MaxPathLen = &n
	}
	for _, dp := range c.DistributionPoints {
		for _, raw := range dp.CRLIssuer {
			d.CRLIssuers = append(d.CRLIssuers, certparse.NameString(raw))
		}
	}
	for _, u := range c.ExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, extKeyUsage(u))
	}
	for _, o := range c.UnknownExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, oidName(o))
	}
	for _, p := range c.PolicyIdentifiers {
		d.Policies = append(d.Policies, p.String())
	}
	for _, e := range c.Extensions {
		d.Extensions = append(d.Extensions, Extension{OID: e.Id.String(), Name: extensionNames[e.Id.String()], Critical: e.Critical})
	}
	return d
}

func keyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	}
	return c.PublicKeyAlgorithm.String()
}

func keyUsage(u x509.KeyUsage) []string {
	names := []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
		"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}
	var out []string
	for i, n := range names {
		if u&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return out
}

func extKeyUsage(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	}
	return fmt.Sprintf("x509.ExtKeyUsage(%d)", u)
}

func oidName(o asn1.ObjectIdentifier) string {
	if n, ok := oidNames[o.String()]; ok {
		return o.String() + " (" + n + ")"
	}
	return o.String()
}

var oidNames = map[string]string{
	"2.23.133.8.1": "TCG EK certificate",
	"2.23.133.8.2": "TCG platform certificate",
	"2.23.133.8.3": "TCG AIK certificate",
}

var extensionNames = map[string]string{
	"2.5.29.9":          "subjectDirectoryAttributes",
	"2.5.29.14":         "subjectKeyIdentifier",
	"2.5.29.15":         "keyUsage",
	"2.5.29.17":         "subjectAltName",
	"2.5.29.19":         "basicConstraints",
	"2.5.29.30":         "nameConstraints",
	"2.5.29.31":         "cRLDistributionPoints",
	"2.5.29.32":         "certificatePolicies",
	"2.5.29.35":         "authorityKeyIdentifier",
	"2.5.29.36":         "policyConstraints",
	"2.5.29.37":         "extKeyUsage",
	"2.5.29.46":         "freshestCRL",
	"2.5.29.54":         "inhibitAnyPolicy",
	"1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
}

const (
	oidCountry      = "2.5.4.6"
	oidOrganization = "2.5.4.10"
	oidSerialNumber = "2.5.4.5"
	oidUID          = "0.9.2342.19200300.100.1.1"
	oidEmail        = "1.2.840.113549.1.9.1"
)

// Redacted replaces attribute values that may identify a device.
const Redacted = "REDACTED"

// redactName returns the string form of a raw Name. Country, organization
// and TCG attributes are always kept. With all set every other value is
// redacted; otherwise only serial numbers, UIDs, e-mail addresses and runs
// of 8 or more hex digits.
func redactName(raw []byte, all bool) (string, bool) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdn); err != nil {
		return Redacted, true
	}
	changed := false
	for _, set := range rdn {
		for i := range set {
			atv := &set[i]
			switch o := atv.Type.String(); {
			case o == oidCountry || o == oidOrganization || strings.HasPrefix(o, "2.23.133."):
			case all || o == oidSerialNumber || o == oidUID || o == oidEmail:
				atv.Value, changed = Redacted, true
			default:
				if s, ok := atv.Value.(string); ok {
					if m := maskHexRuns(s); m != s {
						atv.Value, changed = m, true
					}
				}
			}
		}
	}
	if len(rdn) == 0 {
		return "<empty>", false
	}
	return rdn.String(), changed
}

// maskHexRuns replaces runs of 8 or more hex digits containing a decimal
// digit by 'X': such runs are usually serial numbers or device IDs.
func maskHexRuns(s string) string {
	b := []byte(s)
	isHex := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
	for i := 0; i < len(b); {
		if !isHex(b[i]) {
			i++
			continue
		}
		j, digit := i, false
		for j < len(b) && isHex(b[j]) {
			digit = digit || b[j] <= '9'
			j++
		}
		if j-i >= 8 && digit {
			for k := i; k < j; k++ {
				b[k] = 'X'
			}
		}
		i = j
	}
	return string(b)
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Published downloads the AIA "CA Issuers" URLs of every certificate in the
// scan and in the chains and maps the fingerprints of the certificates found
// there to their URL (for Options.Published).
func Published(ctx context.Context, s *tpm.Scan, eks []EKReport, f verify.CertFetcher) map[string]string {
	out := map[string]string{}
	if f == nil {
		return out
	}
	var urls []string
	for _, e := range s.Entries {
		for _, c := range e.Certificates {
			urls = append(urls, c.IssuingCertificateURL...)
		}
	}
	for _, r := range eks {
		for _, l := range r.Report.Chain {
			urls = append(urls, l.Cert.IssuingCertificateURL...)
		}
	}
	done := map[string]bool{}
	for _, u := range urls {
		if done[u] {
			continue
		}
		done[u] = true
		if res, err := f.FetchCertificates(ctx, u); err == nil {
			for _, c := range res.Certificates {
				if _, ok := out[c.Fingerprint]; !ok {
					out[c.Fingerprint] = u
				}
			}
		}
	}
	return out
}
