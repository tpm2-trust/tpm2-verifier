package verify

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/fetch"
)

// CRLFetcher retrieves CRLs from distribution point URLs.
// *fetch.Fetcher implements it.
type CRLFetcher interface {
	FetchCRL(ctx context.Context, url string) (*fetch.Result, error)
}

// CertFetcher retrieves issuer certificates from AIA URLs.
// *fetch.Fetcher implements it.
type CertFetcher interface {
	FetchCertificates(ctx context.Context, url string) (*fetch.CertResult, error)
}

// checkRevocation sets Link.Revocation for every certificate of the chain
// except trust anchors and self-signed roots.
func (v *Verifier) checkRevocation(ctx context.Context, r *Report, pool []candidate, now time.Time) {
	revoked, unknown := false, false
	for i, l := range r.Chain {
		if l.Anchor || (i == len(r.Chain)-1 && l.Cert.IsSelfSigned()) {
			continue
		}
		l.Revocation = v.revocationOf(ctx, l.Cert, r.Chain[i+1:], pool, now)
		switch l.Revocation.Status {
		case RevocationRevoked:
			revoked = true
		case RevocationUnknown:
			unknown = true
		}
	}
	switch {
	case revoked:
		r.Status = StatusRevoked
	case unknown && v.mode == RevocationRequire && r.Status == StatusTrusted:
		r.Status = StatusInvalid
		r.Problems = append(r.Problems, "revocation status of at least one certificate is unknown")
	}
}

// revocationOf determines the revocation status of c. CRLs passed with
// WithCRLs are tried first, then the distribution point URLs are fetched.
// above are the chain links above c; CRL signers are searched there first.
func (v *Verifier) revocationOf(ctx context.Context, c *certparse.Certificate, above []*Link, pool []candidate, now time.Time) Revocation {
	if len(c.DistributionPoints) == 0 {
		return Revocation{Status: RevocationNoCDP}
	}
	var reasons []string
	for _, dp := range c.DistributionPoints {
		crlIssuers := dp.CRLIssuer
		if len(crlIssuers) == 0 {
			crlIssuers = [][]byte{c.RawIssuer}
		}
		matches := func(crl *certparse.CRL) bool {
			return slices.ContainsFunc(crlIssuers, func(n []byte) bool { return certparse.SameName(n, crl.RawIssuer) })
		}

		for _, crl := range v.crls {
			if !matches(crl) || (len(crl.URIs) > 0 && len(dp.URIs) > 0 && !intersects(crl.URIs, dp.URIs)) {
				continue
			}
			res, ok := v.checkCRL(c, crl, above, pool, now)
			if ok {
				res.Source = "file"
				return res
			}
			reasons = append(reasons, res.Detail)
		}

		if v.fetcher == nil {
			continue
		}
		for _, u := range dp.URIs {
			fr, err := v.fetcher.FetchCRL(ctx, u)
			if err != nil {
				reasons = append(reasons, err.Error())
				continue
			}
			if !matches(fr.CRL) {
				reasons = append(reasons, fmt.Sprintf("%s is issued by %s, expected %s", u, fr.CRL.IssuerString(), certparse.NameString(crlIssuers[0])))
				continue
			}
			res, ok := v.checkCRL(c, fr.CRL, above, pool, now)
			res.Source, res.Origin, res.Warning = u, string(fr.Origin), fr.Warning
			if ok {
				return res
			}
			reasons = append(reasons, res.Detail)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("no CRL available for %v", c.CRLURIs()))
	}
	return Revocation{Status: RevocationUnknown, Detail: strings.Join(reasons, "; ")}
}

// checkCRL evaluates one CRL. ok is false if the CRL cannot be used, in which
// case the returned Revocation only carries the reason in Detail.
func (v *Verifier) checkCRL(c *certparse.Certificate, crl *certparse.CRL, above []*Link, pool []candidate, now time.Time) (Revocation, bool) {
	res := Revocation{CRLIssuer: crl.IssuerString()}
	if crl.Number != nil {
		res.CRLNumber = crl.Number.String()
	}
	fail := func(format string, args ...any) (Revocation, bool) {
		res.Detail = fmt.Sprintf("CRL from %s: ", res.CRLIssuer) + fmt.Sprintf(format, args...)
		return res, false
	}
	if !certparse.SameName(crl.RawIssuer, c.RawIssuer) && !crl.Indirect {
		return fail("issuer differs from certificate issuer but CRL is not marked indirect")
	}
	signer, err := v.crlSigner(crl, above, pool)
	if err != nil {
		return fail("%v", err)
	}
	res.SignedBy = signer.Fingerprint
	if now.Before(crl.ThisUpdate) {
		return fail("not valid before %s", crl.ThisUpdate.Format(time.RFC3339))
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return fail("stale, next update was due %s", crl.NextUpdate.Format(time.RFC3339))
	}
	if e, revoked := crl.Lookup(c.SerialNumber, c.RawIssuer); revoked {
		at := e.RevocationTime
		res.Status, res.RevokedAt = RevocationRevoked, &at
		res.Detail = fmt.Sprintf("revoked at %s (reason code %d)", at.Format(time.RFC3339), e.ReasonCode)
		return res, true
	}
	res.Status = RevocationGood
	res.Detail = "not listed"
	return res, true
}

// crlSigner returns the certificate whose key verifies the CRL signature,
// preferring the chain. Outside the chain only store certificates may sign
// CRLs; caller provided certificates could be forged.
func (v *Verifier) crlSigner(crl *certparse.CRL, above []*Link, pool []candidate) (*certparse.Certificate, error) {
	var signers []*certparse.Certificate
	for _, l := range above {
		signers = append(signers, l.Cert)
	}
	for _, p := range pool {
		if p.src == SourceStore {
			signers = append(signers, p.cert)
		}
	}
	var lastErr error
	for _, s := range signers {
		if !certparse.SameName(s.RawSubject, crl.RawIssuer) {
			continue
		}
		if lastErr = certparse.CheckCRLSignature(crl.RevocationList, s.Certificate); lastErr == nil {
			return s, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("signature verification failed: %v", lastErr)
	}
	return nil, fmt.Errorf("no trusted signer certificate for this CRL")
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}
