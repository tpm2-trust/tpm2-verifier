// Package vendorimport turns submissions (tpm2-ek debug bundles and
// debug-anon output) into changes of a vendor directory tree such as the
// vendors/ directory of this repository.
//
// Submissions come from strangers, so nothing in them is trusted:
//
//   - every certificate is downloaded again from its source URL and only
//     taken if the vendor serves the identical bytes;
//   - roots are never added without explicit approval (Options.Accept);
//   - intermediates are added automatically only if they were downloaded
//     and chain to a root of the store or an approved root;
//   - certificates from hosts outside the vendor's domains, or without a
//     URL, need approval too.
//
// Review computes a Plan without changing anything; Plan.Apply writes it.
package vendorimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/bundle"
	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/vendorinfo"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

// Submission kinds.
const (
	KindBundle = "debug-bundle"
	KindAnon   = "debug-anon"
)

// Submission is a loaded debug bundle or debug-anon output.
type Submission struct {
	Path string
	Kind string
	Info *vendorinfo.Info
	// Bundle is set for full debug bundles.
	Bundle *bundle.Bundle
}

// Load reads a submission. A debug bundle is replayed and verified against
// st, completing chains via AIA with f (may be nil); include lists
// fingerprints of certificates from the TPM to treat as public (vendor CAs
// stored in NV but published nowhere).
func Load(ctx context.Context, path string, st *store.Store, f verify.CertFetcher, include []string) (*Submission, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		info, err := vendorinfo.Load(path)
		if err != nil {
			return nil, err
		}
		return &Submission{Path: path, Kind: KindAnon, Info: info}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	info, anonErr := vendorinfo.Read(bytes.NewReader(data))
	if anonErr == nil {
		return &Submission{Path: path, Kind: KindAnon, Info: info}, nil
	}
	b, bundleErr := bundle.Read(bytes.NewReader(data))
	if bundleErr != nil {
		return nil, fmt.Errorf("%s is neither debug-anon output (%v) nor a debug bundle (%v)", path, anonErr, bundleErr)
	}
	info, err = FromBundle(ctx, b, st, f, include)
	if err != nil {
		return nil, err
	}
	return &Submission{Path: path, Kind: KindBundle, Info: info, Bundle: b}, nil
}

// FromBundle replays a debug bundle and collects its vendor information,
// like tpm2-ek debug-anon does on the device.
func FromBundle(ctx context.Context, b *bundle.Bundle, st *store.Store, f verify.CertFetcher, include []string) (*vendorinfo.Info, error) {
	s, err := tpm.New(b.Fake()).Scan(ctx)
	if err != nil {
		return nil, err
	}
	opts := []verify.Option{verify.WithRevocation(verify.RevocationOff), verify.WithTime(b.Manifest.Created)}
	if f != nil {
		opts = append(opts, verify.WithAIAFetcher(f))
	}
	v := verify.New(st, opts...)
	intermediates := s.ChainCertificates()
	if vd := st.VendorForManufacturer(s.Info.Manufacturer); vd != nil {
		for _, i := range vd.ChainNVIndices {
			if uint32(i) < tpm.ChainRangeFirst || uint32(i) > tpm.ChainRangeLast {
				intermediates = append(intermediates, s.ChainCertificates(uint32(i))...)
			}
		}
	}
	var eks []vendorinfo.EKReport
	for _, e := range s.EKCertificates() {
		rep, err := v.Verify(ctx, e.Certificates[0], append(intermediates, e.Certificates[1:]...))
		if err != nil {
			return nil, err
		}
		eks = append(eks, vendorinfo.EKReport{Index: e.Index, Report: rep})
	}
	return vendorinfo.Build(s, eks, st, vendorinfo.Options{
		Tool:      b.Manifest.Tool,
		Created:   b.Manifest.Created,
		Published: vendorinfo.Published(ctx, s, eks, f),
		Include:   include,
	})
}

// Options configure Review and Apply.
type Options struct {
	// Vendors is the vendor directory tree to update.
	Vendors string
	// Fetcher downloads candidate certificates again from their URL. It
	// should not use a cache. Without it nothing is added automatically.
	Fetcher verify.CertFetcher
	// Accept lists fingerprints approved by the maintainer: roots after
	// comparing them with the vendor, unpublished or off-domain CAs.
	Accept []string
	// Now is the date recorded for new observations (default today).
	Now time.Time
}

// Severity of a finding.
type Severity string

const (
	SeverityError   Severity = "error"   // blocks the import
	SeverityWarning Severity = "warning" // needs attention
	SeverityInfo    Severity = "info"
)

// Finding is one result of the review.
type Finding struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Candidate is a certificate of the submission that is not in the store yet.
type Candidate struct {
	SHA256  string `json:"sha256"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	URL     string `json:"url,omitempty"`
	Root    bool   `json:"root"`
	// InTPM is set for certificates read from the TPM; they are usually
	// device specific even if published.
	InTPM bool `json:"in_tpm"`
	// Downloaded is set if URL serves exactly this certificate.
	Downloaded bool `json:"downloaded"`
	Accepted   bool `json:"accepted"`
	// Pending explains why the certificate is not added.
	Pending string `json:"pending,omitempty"`
	// File is the path in the vendor directory, e.g. roots/foo.der.
	File string `json:"file,omitempty"`

	cert *certparse.Certificate
	host string
}

// Plan is the result of a review.
type Plan struct {
	Submission *Submission `json:"-"`
	VendorID   string      `json:"vendor_id"`
	VendorName string      `json:"vendor_name"`
	NewVendor  bool        `json:"new_vendor"`
	// Certificates are all candidates, accepted or pending.
	Certificates []*Candidate `json:"certificates"`
	// Values to add to vendor.yaml.
	ManufacturerIDs []string `json:"add_manufacturer_ids,omitempty"`
	ChainNVIndices  []string `json:"add_chain_nv_indices,omitempty"`
	Domains         []string `json:"add_domains,omitempty"`

	Observation    Observation `json:"observation"`
	NewObservation bool        `json:"new_observation"`
	Findings       []Finding   `json:"findings"`

	vendor *store.Vendor
	store  *store.Store
}

// HasErrors reports whether a finding blocks the import.
func (p *Plan) HasErrors() bool {
	return slices.ContainsFunc(p.Findings, func(f Finding) bool { return f.Severity == SeverityError })
}

// Accepted returns the certificates that Apply adds.
func (p *Plan) Accepted() []*Candidate {
	var out []*Candidate
	for _, c := range p.Certificates {
		if c.Accepted {
			out = append(out, c)
		}
	}
	return out
}

// Changes reports whether Apply would change anything.
func (p *Plan) Changes() bool {
	return p.NewVendor || len(p.Accepted()) > 0 || len(p.ManufacturerIDs) > 0 || len(p.ChainNVIndices) > 0 ||
		len(p.Domains) > 0 || p.NewObservation
}

func (p *Plan) add(s Severity, format string, args ...any) {
	p.Findings = append(p.Findings, Finding{s, fmt.Sprintf(format, args...)})
}

// Review compares a submission with the vendor directory tree and decides
// what to add. It downloads candidate certificates but changes nothing.
func Review(ctx context.Context, sub *Submission, opts Options) (*Plan, error) {
	st, err := store.LoadDir(opts.Vendors)
	if err != nil {
		return nil, fmt.Errorf("vendor directory %s: %w", opts.Vendors, err)
	}
	info := sub.Info
	p := &Plan{Submission: sub, store: st}
	m := info.TPM.Manufacturer
	if m == "" {
		return nil, errors.New("submission has no TPM manufacturer")
	}

	// Vendor.
	p.vendor = st.VendorForManufacturer(m)
	if p.vendor != nil {
		p.VendorID, p.VendorName = p.vendor.ID, p.vendor.Name
	} else {
		p.NewVendor = true
		p.VendorID, p.VendorName = vendorinfo.Slug(m), vendorinfo.VendorName(m)
		p.ManufacturerIDs = []string{m}
		if p.VendorID == "" {
			p.add(SeverityError, "manufacturer %q gives no usable vendor ID", m)
		} else if st.Vendor(p.VendorID) != nil {
			p.add(SeverityError, "vendor ID %q exists but does not list manufacturer %s; add it there by hand", p.VendorID, m)
		}
	}
	if info.Tool != "" {
		p.add(SeverityInfo, "created %s by %s", info.Created, info.Tool)
	}

	// EK chains.
	accepted := map[string]bool{}
	for _, fp := range opts.Accept {
		accepted[strings.ToLower(fp)] = true
	}
	for _, ek := range info.EK {
		p.add(SeverityInfo, "EK %s: %s, %d levels: %s", ek.Index, ek.Status, ek.Structure.Levels, ek.Structure.Summary)
		if len(ek.Chain) == 0 {
			continue
		}
		if t := ek.Chain[0].TPM; t != nil && t.Manufacturer != "" && certparse.NormalizeManufacturer(t.Manufacturer) != m {
			p.add(SeverityWarning, "EK %s claims manufacturer %s, the TPM reports %s", ek.Index, t.Manufacturer, m)
		}
		if last := ek.Chain[len(ek.Chain)-1]; ek.Status == verify.StatusIncomplete {
			msg := fmt.Sprintf("EK %s: chain incomplete, no certificate for issuer %q", ek.Index, last.Issuer)
			if len(last.AIAIssuers) > 0 {
				msg += " (AIA " + strings.Join(last.AIAIssuers, ", ") + ")"
			}
			p.add(SeverityWarning, "%s; obtain it from the vendor", msg)
		}
		for _, c := range ek.Chain {
			for _, q := range c.Quirks {
				if q.Code == certparse.QuirkUnhandledCriticalExt && (p.vendor == nil || !slices.Contains(p.vendor.AcceptedCriticalExtensions, q.Detail)) {
					p.add(SeverityWarning, "EK %s depth %d: unhandled critical extension %s; consider accepted_critical_extensions", ek.Index, c.Depth, q.Detail)
				}
			}
		}
		p.checkSignatures(ek)
	}

	// Candidates.
	inTPM := map[string]bool{}
	for _, ek := range info.EK {
		for _, c := range ek.Chain {
			if c.Source == verify.SourceLeaf || c.Source == verify.SourceProvided {
				inTPM[c.SHA256] = true
			}
		}
	}
	for _, pc := range info.Certificates {
		if st.ByFingerprint(pc.SHA256) != nil {
			continue
		}
		c, err := certparse.Parse(info.Certificate(pc.SHA256))
		if err != nil {
			p.add(SeverityError, "certificate %s: %v", pc.SHA256, err)
			continue
		}
		if !c.IsCA {
			p.add(SeverityWarning, "certificate %q is not a CA, ignored", pc.Subject)
			continue
		}
		cand := &Candidate{SHA256: c.Fingerprint, Subject: c.SubjectString(), Issuer: c.IssuerString(), URL: pc.URL, Root: c.IsSelfSigned(), InTPM: inTPM[c.Fingerprint], cert: c}
		p.Certificates = append(p.Certificates, cand)
		p.check(ctx, cand, opts, accepted[c.Fingerprint])
	}
	slices.Reverse(p.Certificates) // chains are listed leaf first; root first reads better
	p.resolve(accepted)
	p.assignFiles(opts.Vendors)
	for _, c := range p.Certificates {
		if accepted[c.SHA256] && !c.Accepted {
			p.add(SeverityWarning, "%s was approved but cannot be added: %s", c.SHA256, c.Pending)
		}
	}

	// vendor.yaml values.
	var have []string
	if p.vendor != nil {
		for _, n := range p.vendor.ChainNVIndices {
			have = append(have, n.String())
		}
	}
	for _, n := range info.NV {
		if strings.HasPrefix(n.Label, string(tpm.KindEKChain)) && len(n.Certificates) > 0 && !slices.Contains(have, n.Index) {
			p.ChainNVIndices = append(p.ChainNVIndices, n.Index)
		}
	}
	for _, c := range p.Accepted() {
		if c.host != "" && !p.domainKnown(c.host) && !slices.Contains(p.Domains, c.host) {
			p.Domains = append(p.Domains, c.host)
		}
	}

	// Observation.
	p.Observation = observe(info, opts.Now)
	obs, err := readObservations(opts.Vendors, p.VendorID)
	if err != nil {
		p.add(SeverityError, "%v", err)
	}
	p.NewObservation = !slices.ContainsFunc(obs, p.Observation.same)
	return p, nil
}

// check downloads a candidate again and decides whether it may be added
// without approval.
func (p *Plan) check(ctx context.Context, c *Candidate, opts Options, approved bool) {
	var pending []string
	if c.URL == "" {
		pending = append(pending, "not published at a URL (included from the TPM)")
	} else if u, err := url.Parse(c.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		pending = append(pending, "invalid URL")
	} else {
		c.host = strings.ToLower(u.Hostname())
		if u.Scheme == "http" {
			p.add(SeverityInfo, "%s is served over http; it is checked by comparing the download with the submission", c.URL)
		}
		if p.vendor != nil && len(p.vendor.Domains) > 0 && !p.domainKnown(c.host) {
			pending = append(pending, fmt.Sprintf("host %s is not in the domains of vendor %s", c.host, p.VendorID))
		}
		switch {
		case opts.Fetcher == nil:
			pending = append(pending, "not downloaded again (no network)")
		default:
			res, err := opts.Fetcher.FetchCertificates(ctx, c.URL)
			switch {
			case err != nil:
				pending = append(pending, "download failed: "+err.Error())
			case slices.ContainsFunc(res.Certificates, func(x *certparse.Certificate) bool { return x.Fingerprint == c.SHA256 }):
				c.Downloaded = true
			default:
				p.add(SeverityError, "%s serves a different certificate than the submission claims for %q", c.URL, c.Subject)
				c.Pending = "the URL serves a different certificate"
				return
			}
		}
	}
	if c.InTPM && !approved {
		pending = append(pending, "read from the TPM, usually device specific; approve only if all devices share it")
	}
	if c.Root && !approved {
		pending = append(pending, "roots need approval: compare the SHA-256 with one the vendor publishes, then approve it")
	}
	if approved {
		pending = nil
	}
	c.Pending = strings.Join(pending, "; ")
}

// resolve accepts candidates without pending reasons whose issuer is in the
// store or accepted, until nothing changes.
func (p *Plan) resolve(approved map[string]bool) {
	for changed := true; changed; {
		changed = false
		for _, c := range p.Certificates {
			// Approved candidates have no pending reason (see check).
			if c.Accepted || c.Pending != "" {
				continue
			}
			if c.Root && approved[c.SHA256] || p.issuerTrusted(c) {
				c.Accepted, changed = true, true
			}
		}
	}
	for _, c := range p.Certificates {
		if !c.Accepted && c.Pending == "" {
			c.Pending = "its issuer is neither in the store nor added (approve the root first)"
		}
	}
}

func (p *Plan) issuerTrusted(c *Candidate) bool {
	for _, e := range p.store.Entries() {
		if certparse.CheckSignature(c.cert.Certificate, e.Cert.Certificate) == nil {
			return true
		}
	}
	for _, o := range p.Certificates {
		if o.Accepted && o != c && certparse.CheckSignature(c.cert.Certificate, o.cert.Certificate) == nil {
			return true
		}
	}
	return false
}

func (p *Plan) domainKnown(host string) bool {
	if p.vendor == nil {
		return false
	}
	for _, d := range p.vendor.Domains {
		d = strings.ToLower(d)
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// checkSignatures verifies the links between the public certificates of a
// chain, using the files of the submission and the store.
func (p *Plan) checkSignatures(ek vendorinfo.EK) {
	cert := func(c vendorinfo.Cert) *certparse.Certificate {
		if !c.Public {
			return nil
		}
		if e := p.store.ByFingerprint(c.SHA256); e != nil {
			return e.Cert
		}
		x, _ := certparse.Parse(p.Submission.Info.Certificate(c.SHA256))
		return x
	}
	for i := 0; i+1 < len(ek.Chain); i++ {
		child, parent := cert(ek.Chain[i]), cert(ek.Chain[i+1])
		if child == nil || parent == nil {
			continue
		}
		if err := certparse.CheckSignature(child.Certificate, parent.Certificate); err != nil {
			p.add(SeverityError, "EK %s: %q is not signed by %q: %v", ek.Index, child.SubjectString(), parent.SubjectString(), err)
		}
	}
}
