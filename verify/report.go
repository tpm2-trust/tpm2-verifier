package verify

import (
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/store"
)

// Status is the overall verification result.
type Status string

const (
	// StatusTrusted: the chain ends at a trust anchor of the store and all
	// checks passed.
	StatusTrusted Status = "trusted"
	// StatusUntrustedRoot: the chain is complete but ends at a self-signed
	// certificate that is not in the store.
	StatusUntrustedRoot Status = "untrusted-root"
	// StatusIncomplete: no issuer was found for the last certificate.
	StatusIncomplete Status = "incomplete"
	// StatusRevoked: a certificate of the chain is listed on a CRL.
	StatusRevoked Status = "revoked"
	// StatusInvalid: the chain is complete but a check failed (validity
	// period, critical extension, path length, unknown revocation status in
	// RevocationRequire mode).
	StatusInvalid Status = "invalid"
)

// Source tells where a certificate of the chain came from.
type Source string

const (
	SourceLeaf     Source = "leaf"
	SourceProvided Source = "provided" // passed by the caller, e.g. read from the TPM
	SourceStore    Source = "store"
)

// RevocationStatus of one certificate.
type RevocationStatus string

const (
	RevocationNotChecked RevocationStatus = "not-checked"
	RevocationGood       RevocationStatus = "good"
	RevocationRevoked    RevocationStatus = "revoked"
	RevocationUnknown    RevocationStatus = "unknown"
	// RevocationNoCDP: the certificate names no CRL distribution point.
	RevocationNoCDP RevocationStatus = "no-distribution-point"
)

// Revocation is the revocation result for one certificate.
type Revocation struct {
	Status RevocationStatus `json:"status"`
	Detail string           `json:"detail,omitempty"`
	// CRLIssuer and CRLNumber identify the CRL that was used.
	CRLIssuer string     `json:"crl_issuer,omitempty"`
	CRLNumber string     `json:"crl_number,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Link is one certificate of the chain.
type Link struct {
	Cert *certparse.Certificate `json:"-"`

	Subject     string            `json:"subject"`
	Issuer      string            `json:"issuer"`
	Serial      string            `json:"serial"`
	Fingerprint string            `json:"sha256"`
	NotBefore   time.Time         `json:"not_before"`
	NotAfter    time.Time         `json:"not_after"`
	Source      Source            `json:"source"`
	StoreEntry  *store.Entry      `json:"-"`
	StorePath   string            `json:"store_path,omitempty"`
	Anchor      bool              `json:"trust_anchor,omitempty"`
	Quirks      []certparse.Quirk `json:"quirks,omitempty"`
	Problems    []string          `json:"problems,omitempty"`
	Revocation  Revocation        `json:"revocation"`
}

// Report is the result of a verification.
type Report struct {
	Status Status `json:"status"`
	// Vendor is the store vendor ID of the trust anchor, if trusted.
	Vendor string `json:"vendor,omitempty"`
	// TPM is the TPM identity claimed by the leaf certificate.
	TPM *certparse.TPMInfo `json:"tpm,omitempty"`
	// Chain starts with the leaf.
	Chain    []*Link   `json:"chain"`
	Problems []string  `json:"problems,omitempty"`
	Hints    []string  `json:"hints,omitempty"`
	Time     time.Time `json:"time"`
}

func newLink(c *certparse.Certificate, src Source, e *store.Entry) *Link {
	l := &Link{
		Cert:        c,
		Subject:     c.SubjectString(),
		Issuer:      c.IssuerString(),
		Serial:      c.SerialNumber.Text(16),
		Fingerprint: c.Fingerprint,
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		Source:      src,
		StoreEntry:  e,
		Quirks:      c.Quirks,
		Revocation:  Revocation{Status: RevocationNotChecked},
	}
	if e != nil {
		l.StorePath = e.Vendor.ID + "/" + e.File
		l.Anchor = e.Role == store.RoleRoot
	}
	return l
}
