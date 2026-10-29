package vendorimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/manifest"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/vendorinfo"
)

// assignFiles chooses a file name for every candidate that is unique in the
// vendor directory.
func (p *Plan) assignFiles(vendors string) {
	used := map[string]bool{}
	if p.vendor != nil {
		for _, e := range p.vendor.Certificates {
			used[e.File] = true
		}
	}
	for _, c := range p.Certificates {
		role := "intermediates"
		if c.Root {
			role = "roots"
		}
		base := vendorinfo.CertFileName(c.cert)
		file := role + "/" + base + ".der"
		for n := 2; used[file] || exists(filepath.Join(vendors, p.VendorID, file)); n++ {
			file = fmt.Sprintf("%s/%s-%d.der", role, base, n)
		}
		used[file] = true
		c.File = file
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Apply writes the plan into the vendor directory tree: certificate files,
// vendor.yaml (merged line by line, keeping comments and layout),
// observations.yaml and the generated block of README.md. The result is
// loaded as a store; on failure every change is undone. It returns the
// changed files relative to opts.Vendors.
func (p *Plan) Apply(opts Options) (changed []string, err error) {
	if p.HasErrors() {
		return nil, errors.New("the review found errors; nothing written")
	}
	if !p.Changes() {
		return nil, nil
	}
	dir := filepath.Join(opts.Vendors, p.VendorID)
	tx := &transaction{}
	defer func() {
		if err != nil {
			tx.rollback()
			changed = nil
		}
	}()

	for _, c := range p.Accepted() {
		if err := tx.write(filepath.Join(dir, filepath.FromSlash(c.File)), c.cert.Raw); err != nil {
			return nil, err
		}
	}

	yamlPath := filepath.Join(dir, "vendor.yaml")
	var y []byte
	if p.NewVendor {
		y = p.newVendorYAML(opts)
	} else {
		cur, err := os.ReadFile(yamlPath)
		if err != nil {
			return nil, err
		}
		y, err = mergeVendorYAML(cur, p.yamlAdditions(opts))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", yamlPath, err)
		}
	}
	if err := tx.writeIfChanged(yamlPath, y); err != nil {
		return nil, err
	}

	obs, err := readObservations(opts.Vendors, p.VendorID)
	if err != nil {
		return nil, err
	}
	if p.NewObservation {
		obs = append(obs, p.Observation)
	}
	if len(obs) > 0 {
		data, err := encodeObservations(obs)
		if err != nil {
			return nil, err
		}
		if err := tx.writeIfChanged(filepath.Join(dir, ObservationsFile), data); err != nil {
			return nil, err
		}
	}
	readmePath := filepath.Join(dir, "README.md")
	readme, err := os.ReadFile(readmePath)
	if errors.Is(err, fs.ErrNotExist) {
		readme = []byte(fmt.Sprintf("# %s\n\nTODO: describe the hierarchy, where the certificates are published and\nthe quirks of this vendor.\n", p.VendorName))
	} else if err != nil {
		return nil, err
	}
	if len(obs) > 0 {
		readme = []byte(updateReadme(string(readme), observationsMarkdown(obs)))
	}
	if err := tx.writeIfChanged(readmePath, readme); err != nil {
		return nil, err
	}

	// The manifest of the tree; the old signature no longer matches.
	if m, changed, err := manifest.Update(opts.Vendors, "", now(opts)); err != nil {
		return nil, fmt.Errorf("%s: %w", manifest.File, err)
	} else if changed {
		if err := tx.write(filepath.Join(opts.Vendors, manifest.File), m.Marshal()); err != nil {
			return nil, err
		}
		if err := tx.remove(filepath.Join(opts.Vendors, manifest.SigFile)); err != nil {
			return nil, err
		}
	}

	// The result must load, and contain what was added.
	st, err := store.LoadDir(opts.Vendors)
	if err != nil {
		return nil, fmt.Errorf("the updated vendor directory does not load (changes undone): %w", err)
	}
	for _, c := range p.Accepted() {
		if st.ByFingerprint(c.SHA256) == nil {
			return nil, fmt.Errorf("%s missing after the update (changes undone)", c.File)
		}
	}
	for _, f := range tx.files {
		rel, _ := filepath.Rel(opts.Vendors, f.path)
		changed = append(changed, filepath.ToSlash(rel))
	}
	slices.Sort(changed)
	return changed, nil
}

type additions struct {
	ManufacturerIDs []string
	ChainNVIndices  []string
	Domains         []string
	Certificates    []string // rendered list items
}

func (p *Plan) yamlAdditions(opts Options) additions {
	a := additions{ManufacturerIDs: p.ManufacturerIDs, ChainNVIndices: p.ChainNVIndices, Domains: p.Domains}
	date := now(opts)
	for _, c := range p.Accepted() {
		role := "intermediate"
		if c.Root {
			role = "root"
		}
		src := c.URL
		if src == "" {
			src = "TPM NV (approved by the maintainer)"
		}
		a.Certificates = append(a.Certificates, fmt.Sprintf("- file: %s\n  role: %s\n  subject: %s\n  source: %s\n  sha256: %s\n  retrieved: %s",
			c.File, role, quote(c.Subject), quote(src), c.SHA256, date.UTC().Format(time.DateOnly)))
	}
	return a
}

func now(opts Options) time.Time {
	if opts.Now.IsZero() {
		return time.Now()
	}
	return opts.Now
}

func (p *Plan) newVendorYAML(opts Options) []byte {
	a := p.yamlAdditions(opts)
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\nname: %s\n", p.VendorID, quote(p.VendorName))
	fmt.Fprintf(&b, "# TPM2_PT_MANUFACTURER as returned by TPM2_GetCapability.\nmanufacturer_ids: [%s]\n", strings.Join(a.ManufacturerIDs, ", "))
	fmt.Fprintf(&b, "description: %s\n", quote("TODO"))
	if len(a.ChainNVIndices) > 0 {
		fmt.Fprintf(&b, "# NV indices holding chain certificates as concatenated DER.\nchain_nv_indices: [%s]\n", strings.Join(a.ChainNVIndices, ", "))
	}
	if len(a.Domains) > 0 {
		fmt.Fprintf(&b, "# Hosts the vendor publishes certificates on (tpm2-verifier vendor import).\ndomains: [%s]\n", strings.Join(a.Domains, ", "))
	}
	if len(a.Certificates) == 0 {
		b.WriteString("certificates: []\n")
	} else {
		b.WriteString("certificates:\n")
		for _, c := range a.Certificates {
			b.WriteString(indent(c, "  ") + "\n")
		}
	}
	return []byte(b.String())
}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}

// quote returns s as a YAML double quoted scalar.
func quote(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// transaction records written files so they can be restored.
type transaction struct {
	files []txFile
}

type txFile struct {
	path    string
	old     []byte
	existed bool
	dirs    []string // directories created
}

func (t *transaction) write(p string, data []byte) error {
	f := txFile{path: p}
	if old, err := os.ReadFile(p); err == nil {
		f.old, f.existed = old, true
	}
	for d := filepath.Dir(p); !exists(d); d = filepath.Dir(d) {
		f.dirs = append(f.dirs, d)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	t.files = append(t.files, f)
	return os.WriteFile(p, data, 0o644)
}

// remove deletes p, if it exists.
func (t *transaction) remove(p string) error {
	old, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	t.files = append(t.files, txFile{path: p, old: old, existed: true})
	return os.Remove(p)
}

func (t *transaction) writeIfChanged(p string, data []byte) error {
	if old, err := os.ReadFile(p); err == nil && string(old) == string(data) {
		return nil
	}
	return t.write(p, data)
}

func (t *transaction) rollback() {
	for i := len(t.files) - 1; i >= 0; i-- {
		f := t.files[i]
		if f.existed {
			os.WriteFile(f.path, f.old, 0o644)
		} else {
			os.Remove(f.path)
		}
		for _, d := range f.dirs {
			os.Remove(d)
		}
	}
}
