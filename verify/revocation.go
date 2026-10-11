package verify

import (
	"fmt"
	"slices"
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
)

// checkRevocation sets Link.Revocation for every certificate of the chain
// except trust anchors and self-signed roots.
func (v *Verifier) checkRevocation(r *Report, pool []candidate, now time.Time) {
	revoked, unknown := false, false
	for i, l := range r.Chain {
		if l.Anchor || (i == len(r.Chain)-1 && l.Cert.IsSelfSigned()) {
			continue
		}
		l.Revocation = v.revocationOf(l.Cert, r.Chain[i+1:], pool, now)
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

// revocationOf determines the revocation status of c from the configured
// CRLs. above are the chain links above c; CRL signers are searched there
// first, then in the pool.
func (v *Verifier) revocationOf(c *certparse.Certificate, above []*Link, pool []candidate, now time.Time) Revocation {
	if len(c.DistributionPoints) == 0 {
		return Revocation{Status: RevocationNoCDP}
	}
	var reasons []string
	for _, dp := range c.DistributionPoints {
		crlIssuers := dp.CRLIssuer
		if len(crlIssuers) == 0 {
			crlIssuers = [][]byte{c.RawIssuer}
		}
		for _, crl := range v.crls {
			if !slices.ContainsFunc(crlIssuers, func(n []byte) bool { return certparse.SameName(n, crl.RawIssuer) }) {
				continue
			}
			if len(crl.URIs) > 0 && len(dp.URIs) > 0 && !intersects(crl.URIs, dp.URIs) {
				continue
			}
			res, ok := v.checkCRL(c, crl, above, pool, now)
			if ok {
				return res
			}
			reasons = append(reasons, res.Detail)
		}
		if len(reasons) == 0 {
			reasons = append(reasons, fmt.Sprintf("no CRL from %s available (%v)", certparse.NameString(crlIssuers[0]), dp.URIs))
		}
	}
	return Revocation{Status: RevocationUnknown, Detail: joinReasons(reasons)}
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
	if err := v.checkCRLSigner(crl, above, pool); err != nil {
		return fail("%v", err)
	}
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

// checkCRLSigner finds a certificate that signed crl, preferring the chain.
func (v *Verifier) checkCRLSigner(crl *certparse.CRL, above []*Link, pool []candidate) error {
	var signers []*certparse.Certificate
	for _, l := range above {
		signers = append(signers, l.Cert)
	}
	// Outside the chain only trust anchors and store intermediates may sign
	// CRLs; caller provided certificates could be forged.
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
			return nil
		}
	}
	if lastErr != nil {
		return fmt.Errorf("signature: %v", lastErr)
	}
	return fmt.Errorf("signer certificate not found")
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func joinReasons(r []string) string {
	out := ""
	for i, s := range r {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
