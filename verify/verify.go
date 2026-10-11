// Package verify builds and validates certificate chains from a TPM EK
// certificate up to a vendor trust anchor of the store, including CRL based
// revocation checks with support for indirect CRLs.
//
// The validator is purpose-built instead of using x509.Certificate.Verify:
// TPM vendor PKIs contain encodings the standard library rejects (empty
// subjects with critical TCG subjectAltName, SHA-1, vendor critical
// extensions), and a report of every link is more useful than a single error.
package verify

import (
	"bytes"
	"context"
	"encoding/asn1"
	"fmt"
	"slices"
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/store"
)

// RevocationMode controls CRL checking.
type RevocationMode int

const (
	// RevocationBestEffort checks CRLs that are available; missing or stale
	// CRLs are reported but do not change the status. This is the default.
	RevocationBestEffort RevocationMode = iota
	// RevocationOff disables CRL checking.
	RevocationOff
	// RevocationRequire makes a chain invalid if the revocation status of a
	// certificate with a CRL distribution point cannot be determined.
	RevocationRequire
)

const maxDepth = 16

// Verifier validates EK certificate chains against a store.
type Verifier struct {
	store    *store.Store
	now      func() time.Time
	crls     []*certparse.CRL
	mode     RevocationMode
	accepted []asn1.ObjectIdentifier
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithTime validates at a fixed time instead of now.
func WithTime(t time.Time) Option { return func(v *Verifier) { v.now = func() time.Time { return t } } }

// WithCRLs adds CRLs used for revocation checks.
func WithCRLs(crls ...*certparse.CRL) Option {
	return func(v *Verifier) { v.crls = append(v.crls, crls...) }
}

// WithRevocation sets the revocation mode.
func WithRevocation(m RevocationMode) Option { return func(v *Verifier) { v.mode = m } }

// WithAcceptedCriticalExtensions accepts additional critical extensions on
// every certificate (in addition to those listed per vendor in the store).
func WithAcceptedCriticalExtensions(oids ...asn1.ObjectIdentifier) Option {
	return func(v *Verifier) { v.accepted = append(v.accepted, oids...) }
}

// New returns a Verifier using the trust anchors and intermediates of s.
func New(s *store.Store, opts ...Option) *Verifier {
	v := &Verifier{store: s, now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v
}

type candidate struct {
	cert  *certparse.Certificate
	src   Source
	entry *store.Entry
}

// Verify builds the best chain from leaf to a trust anchor using the given
// intermediates (e.g. the per-device chain read from the TPM) and the store,
// and validates it. The returned error is only non-nil for unusable input;
// validation failures are reported in Report.Status.
func (v *Verifier) Verify(ctx context.Context, leaf *certparse.Certificate, intermediates []*certparse.Certificate) (*Report, error) {
	if leaf == nil {
		return nil, fmt.Errorf("verify: no leaf certificate")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := v.now()
	pool := v.candidates(intermediates)

	start := candidate{cert: leaf, src: SourceLeaf, entry: v.store.ByFingerprint(leaf.Fingerprint)}
	p := v.build([]candidate{start}, pool)

	r := &Report{Status: p.status, TPM: leaf.TPM, Time: now}
	for _, c := range p.path {
		r.Chain = append(r.Chain, newLink(c.cert, c.src, c.entry))
	}
	if p.status == StatusTrusted {
		r.Vendor = p.path[len(p.path)-1].entry.Vendor.ID
	}
	r.Problems = append(r.Problems, p.problems...)

	v.checkLinks(r, now)
	// Without CRLs best effort has nothing to report.
	if v.mode == RevocationRequire || (v.mode == RevocationBestEffort && len(v.crls) > 0) {
		v.checkRevocation(r, pool, now)
	}
	v.addHints(r)
	return r, nil
}

func (v *Verifier) candidates(intermediates []*certparse.Certificate) []candidate {
	var pool []candidate
	seen := map[string]bool{}
	for _, e := range v.store.Entries() {
		if !seen[e.Cert.Fingerprint] {
			seen[e.Cert.Fingerprint] = true
			pool = append(pool, candidate{cert: e.Cert, src: SourceStore, entry: e})
		}
	}
	for _, c := range intermediates {
		if !seen[c.Fingerprint] {
			seen[c.Fingerprint] = true
			pool = append(pool, candidate{cert: c, src: SourceProvided})
		}
	}
	return pool
}

type pathResult struct {
	path     []candidate
	status   Status
	problems []string
}

func rank(s Status) int {
	switch s {
	case StatusTrusted:
		return 3
	case StatusUntrustedRoot:
		return 2
	}
	return 1
}

func better(a, b pathResult) bool {
	if rank(a.status) != rank(b.status) {
		return rank(a.status) > rank(b.status)
	}
	return len(a.path) > len(b.path)
}

// build extends path depth-first and returns the best chain found.
func (v *Verifier) build(path []candidate, pool []candidate) pathResult {
	cur := path[len(path)-1]
	if cur.entry != nil && cur.entry.Role == store.RoleRoot {
		return pathResult{path: path, status: StatusTrusted}
	}
	if cur.cert.IsSelfSigned() {
		return pathResult{path: path, status: StatusUntrustedRoot}
	}
	best := pathResult{path: path, status: StatusIncomplete}
	if len(path) >= maxDepth {
		best.problems = []string{"maximum chain depth reached"}
		return best
	}
	var sigProblems []string
	for _, cand := range v.issuers(cur.cert, path, pool) {
		if err := certparse.CheckSignature(cur.cert.Certificate, cand.cert.Certificate); err != nil {
			sigProblems = append(sigProblems, fmt.Sprintf("candidate issuer %q (%s): %v", cand.cert.SubjectString(), short(cand.cert.Fingerprint), err))
			continue
		}
		res := v.build(append(slices.Clip(path), cand), pool)
		if better(res, best) {
			best = res
		}
	}
	if best.status == StatusIncomplete && len(best.path) == len(path) {
		best.problems = sigProblems
	}
	return best
}

// issuers returns the pool certificates whose subject matches c's issuer,
// trust anchors first.
func (v *Verifier) issuers(c *certparse.Certificate, path, pool []candidate) []candidate {
	var out []candidate
	for _, cand := range pool {
		if !certparse.SameName(cand.cert.RawSubject, c.RawIssuer) {
			continue
		}
		if len(c.AuthorityKeyId) > 0 && len(cand.cert.SubjectKeyId) > 0 && !bytes.Equal(c.AuthorityKeyId, cand.cert.SubjectKeyId) {
			continue
		}
		if slices.ContainsFunc(path, func(p candidate) bool { return p.cert.Fingerprint == cand.cert.Fingerprint }) {
			continue
		}
		out = append(out, cand)
	}
	slices.SortStableFunc(out, func(a, b candidate) int {
		return isRoot(b) - isRoot(a)
	})
	return out
}

func isRoot(c candidate) int {
	if c.entry != nil && c.entry.Role == store.RoleRoot {
		return 1
	}
	return 0
}

// checkLinks validates validity periods, critical extensions and path
// length constraints of the chosen chain.
func (v *Verifier) checkLinks(r *Report, now time.Time) {
	accepted := slices.Clone(v.accepted)
	if r.Vendor != "" {
		accepted = append(accepted, v.store.Vendor(r.Vendor).AcceptedCriticalOIDs()...)
	}
	failed := false
	for i, l := range r.Chain {
		c := l.Cert
		if now.Before(c.NotBefore) {
			l.Problems = append(l.Problems, fmt.Sprintf("not valid before %s", c.NotBefore.Format(time.RFC3339)))
		}
		if now.After(c.NotAfter) {
			l.Problems = append(l.Problems, fmt.Sprintf("expired at %s", c.NotAfter.Format(time.RFC3339)))
		}
		for _, oid := range c.UnhandledCriticalExtensions {
			if !slices.ContainsFunc(accepted, oid.Equal) {
				l.Problems = append(l.Problems, fmt.Sprintf("unhandled critical extension %s", oid))
			}
		}
		// Number of intermediate CAs between this CA and the leaf.
		if i > 0 && c.BasicConstraintsValid && (c.MaxPathLen > 0 || c.MaxPathLenZero) && i-1 > c.MaxPathLen {
			l.Problems = append(l.Problems, fmt.Sprintf("path length constraint %d exceeded (%d intermediates below)", c.MaxPathLen, i-1))
		}
		if len(l.Problems) > 0 {
			failed = true
		}
	}
	if failed && r.Status == StatusTrusted {
		r.Status = StatusInvalid
	}
}

func (v *Verifier) addHints(r *Report) {
	last := r.Chain[len(r.Chain)-1]
	var vendor *store.Vendor
	if r.TPM != nil && r.TPM.Manufacturer != "" {
		vendor = v.store.VendorForManufacturer(r.TPM.Manufacturer)
		if vendor == nil {
			r.Hints = append(r.Hints, fmt.Sprintf("TPM manufacturer %q is not in the vendor store", r.TPM.Manufacturer))
		} else if r.Vendor != "" && r.Vendor != vendor.ID {
			r.Hints = append(r.Hints, fmt.Sprintf("EK claims manufacturer %s (%s) but chains to vendor %s", r.TPM.Manufacturer, vendor.ID, r.Vendor))
		}
	}
	switch r.Status {
	case StatusIncomplete:
		r.Hints = append(r.Hints, fmt.Sprintf("no issuer found for %q", last.Subject))
		if vendor != nil && len(vendor.ChainNVIndices) > 0 {
			r.Hints = append(r.Hints, fmt.Sprintf("%s stores per-device intermediates in NV %v; pass them as intermediates", vendor.Name, vendor.ChainNVIndices))
		}
		for _, u := range last.Cert.IssuingCertificateURL {
			r.Hints = append(r.Hints, "issuer certificate is published at "+u)
		}
	case StatusUntrustedRoot:
		r.Hints = append(r.Hints, fmt.Sprintf("root %q (sha256 %s) is not in the vendor store; verify its fingerprint with the vendor before adding it", last.Subject, last.Fingerprint))
	}
}

func short(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}
