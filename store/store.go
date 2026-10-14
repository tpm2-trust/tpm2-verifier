// Package store loads the vendor trust store: per TPM vendor metadata, trust
// anchors (roots) and static intermediates.
//
// The curated store is embedded in the binary (package vendors). A local
// overlay directory with the same layout can add vendors or certificates,
// see Default.
package store

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/vendors"
)

// Role of a certificate in the store.
type Role string

const (
	RoleRoot         Role = "root"
	RoleIntermediate Role = "intermediate"
)

// Entry is one certificate of a vendor.
type Entry struct {
	File    string `yaml:"file"`
	Role    Role   `yaml:"role"`
	Subject string `yaml:"subject,omitempty"`
	Source  string `yaml:"source,omitempty"`
	// SHA256 is the fingerprint of the DER encoding (also for PEM files).
	SHA256    string `yaml:"sha256"`
	Retrieved string `yaml:"retrieved,omitempty"`

	Cert   *certparse.Certificate `yaml:"-"`
	Vendor *Vendor                `yaml:"-"`
	// Origin is "embedded" or the overlay directory the entry was loaded from.
	Origin string `yaml:"-"`
}

// Vendor describes one TPM vendor PKI.
type Vendor struct {
	ID              string   `yaml:"id"`
	Name            string   `yaml:"name"`
	ManufacturerIDs []string `yaml:"manufacturer_ids"`
	Description     string   `yaml:"description,omitempty"`
	// ChainNVIndices are NV indices holding concatenated DER intermediates.
	ChainNVIndices []NVIndex `yaml:"chain_nv_indices,omitempty"`
	// AcceptedCriticalExtensions are extension OIDs (dotted) that this
	// vendor marks critical and that may be ignored during validation.
	AcceptedCriticalExtensions []string `yaml:"accepted_critical_extensions,omitempty"`
	// Domains are the hosts (and their subdomains) the vendor publishes its
	// certificates on. tpm2-ek vendor import flags certificates from others.
	Domains      []string `yaml:"domains,omitempty"`
	Certificates []*Entry `yaml:"certificates"`

	// Readme is the content of README.md, if present.
	Readme string `yaml:"-"`
}

// NVIndex is a TPM NV index; it accepts hex (0x01C00100) or decimal in YAML.
type NVIndex uint32

func (n NVIndex) String() string { return fmt.Sprintf("0x%08X", uint32(n)) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (n *NVIndex) UnmarshalYAML(v *yaml.Node) error {
	u, err := strconv.ParseUint(v.Value, 0, 32)
	if err != nil {
		return fmt.Errorf("invalid NV index %q: %w", v.Value, err)
	}
	*n = NVIndex(u)
	return nil
}

// Roots returns the vendor's trust anchors.
func (v *Vendor) Roots() []*Entry { return v.byRole(RoleRoot) }

// Intermediates returns the vendor's static intermediates.
func (v *Vendor) Intermediates() []*Entry { return v.byRole(RoleIntermediate) }

func (v *Vendor) byRole(r Role) []*Entry {
	var out []*Entry
	for _, e := range v.Certificates {
		if e.Role == r {
			out = append(out, e)
		}
	}
	return out
}

// AcceptedCriticalOIDs parses AcceptedCriticalExtensions.
func (v *Vendor) AcceptedCriticalOIDs() []asn1.ObjectIdentifier {
	var out []asn1.ObjectIdentifier
	for _, s := range v.AcceptedCriticalExtensions {
		if oid, err := parseOID(s); err == nil {
			out = append(out, oid)
		}
	}
	return out
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	return oid, nil
}

// Store is a set of vendors.
type Store struct {
	vendors []*Vendor
}

// New returns an empty store.
func New() *Store { return &Store{} }

// LoadDir loads a vendor directory tree (like the vendors/ directory of the
// repository) without the embedded store.
func LoadDir(dir string) (*Store, error) {
	s := New()
	if err := s.AddFS(os.DirFS(dir), dir); err != nil {
		return nil, err
	}
	return s, nil
}

// Embedded loads the store compiled into the binary.
func Embedded() (*Store, error) {
	s := &Store{}
	if err := s.AddFS(vendors.FS, "embedded"); err != nil {
		return nil, err
	}
	return s, nil
}

// OverlayDir returns the default overlay directory,
// $XDG_CONFIG_HOME/tpm2-verifier/vendors (%AppData% on Windows).
func OverlayDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tpm2-verifier", "vendors"), nil
}

// Default loads the embedded store and, if it exists, the overlay directory.
func Default() (*Store, error) {
	s, err := Embedded()
	if err != nil {
		return nil, err
	}
	dir, err := OverlayDir()
	if err != nil {
		return s, nil
	}
	if _, err := os.Stat(dir); err != nil {
		return s, nil
	}
	if err := s.AddFS(os.DirFS(dir), dir); err != nil {
		return nil, err
	}
	return s, nil
}

// AddFS loads every <vendor>/vendor.yaml found in fsys. A vendor whose ID
// already exists is merged: its certificates are added (duplicates by
// SHA-256 are skipped) and non-empty metadata replaces the existing values.
func (s *Store) AddFS(fsys fs.FS, origin string) error {
	dirs, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		v, err := loadVendor(fsys, d.Name(), origin)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.merge(v)
	}
	return errors.Join(errs...)
}

func loadVendor(fsys fs.FS, dir, origin string) (*Vendor, error) {
	raw, err := fs.ReadFile(fsys, path.Join(dir, "vendor.yaml"))
	if err != nil {
		return nil, err
	}
	var v Vendor
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("store: %s/vendor.yaml: %w", dir, err)
	}
	if v.ID == "" {
		v.ID = dir
	}
	if readme, err := fs.ReadFile(fsys, path.Join(dir, "README.md")); err == nil {
		v.Readme = string(readme)
	}
	for i, id := range v.ManufacturerIDs {
		v.ManufacturerIDs[i] = certparse.NormalizeManufacturer(id)
	}
	for _, s := range v.AcceptedCriticalExtensions {
		if _, err := parseOID(s); err != nil {
			return nil, fmt.Errorf("store: %s: %w", dir, err)
		}
	}
	var errs []error
	for _, e := range v.Certificates {
		if err := e.load(fsys, dir, origin, &v); err != nil {
			errs = append(errs, fmt.Errorf("store: %s/%s: %w", dir, e.File, err))
		}
	}
	return &v, errors.Join(errs...)
}

func (e *Entry) load(fsys fs.FS, dir, origin string, v *Vendor) error {
	data, err := fs.ReadFile(fsys, path.Join(dir, e.File))
	if err != nil {
		return err
	}
	certs, err := certparse.ParseAll(data) // DER or PEM
	if err != nil {
		return err
	}
	if len(certs) != 1 {
		return fmt.Errorf("expected one certificate, found %d", len(certs))
	}
	c := certs[0]
	if !strings.EqualFold(c.Fingerprint, e.SHA256) {
		return fmt.Errorf("sha256 mismatch: manifest %s, file %s", e.SHA256, c.Fingerprint)
	}
	switch e.Role {
	case RoleRoot:
		if !c.IsSelfSigned() {
			return errors.New("root is not self-signed")
		}
	case RoleIntermediate:
	default:
		return fmt.Errorf("unknown role %q", e.Role)
	}
	if !c.IsCA {
		return errors.New("certificate is not a CA")
	}
	e.Cert, e.Vendor, e.Origin = c, v, origin
	if e.Subject == "" {
		e.Subject = c.SubjectString()
	}
	return nil
}

func (s *Store) merge(v *Vendor) {
	cur := s.Vendor(v.ID)
	if cur == nil {
		s.vendors = append(s.vendors, v)
		return
	}
	if v.Name != "" {
		cur.Name = v.Name
	}
	if v.Description != "" {
		cur.Description = v.Description
	}
	if v.Readme != "" {
		cur.Readme = v.Readme
	}
	for _, id := range v.ManufacturerIDs {
		if !slices.Contains(cur.ManufacturerIDs, id) {
			cur.ManufacturerIDs = append(cur.ManufacturerIDs, id)
		}
	}
	for _, n := range v.ChainNVIndices {
		if !slices.Contains(cur.ChainNVIndices, n) {
			cur.ChainNVIndices = append(cur.ChainNVIndices, n)
		}
	}
	for _, d := range v.Domains {
		if !slices.Contains(cur.Domains, d) {
			cur.Domains = append(cur.Domains, d)
		}
	}
	for _, o := range v.AcceptedCriticalExtensions {
		if !slices.Contains(cur.AcceptedCriticalExtensions, o) {
			cur.AcceptedCriticalExtensions = append(cur.AcceptedCriticalExtensions, o)
		}
	}
	for _, e := range v.Certificates {
		if s.ByFingerprint(e.Cert.Fingerprint) == nil {
			e.Vendor = cur
			cur.Certificates = append(cur.Certificates, e)
		}
	}
}

// Vendors returns all vendors.
func (s *Store) Vendors() []*Vendor { return s.vendors }

// Vendor returns the vendor with the given ID (case-insensitive), or nil.
func (s *Store) Vendor(id string) *Vendor {
	for _, v := range s.vendors {
		if strings.EqualFold(v.ID, id) {
			return v
		}
	}
	return nil
}

// VendorForManufacturer returns the vendor for a TPM manufacturer ID as
// reported by TPM2_PT_MANUFACTURER or the EK certificate ("INTC", "IFX\x00").
func (s *Store) VendorForManufacturer(id string) *Vendor {
	id = certparse.NormalizeManufacturer(id)
	for _, v := range s.vendors {
		if slices.Contains(v.ManufacturerIDs, id) {
			return v
		}
	}
	return nil
}

// Entries returns all certificates of all vendors.
func (s *Store) Entries() []*Entry {
	var out []*Entry
	for _, v := range s.vendors {
		out = append(out, v.Certificates...)
	}
	return out
}

// ByFingerprint returns the entry with the given SHA-256 fingerprint, or nil.
func (s *Store) ByFingerprint(fp string) *Entry {
	for _, e := range s.Entries() {
		if strings.EqualFold(e.Cert.Fingerprint, fp) {
			return e
		}
	}
	return nil
}

// RootPool returns an x509.CertPool with all trust anchors.
func (s *Store) RootPool() *x509.CertPool {
	p := x509.NewCertPool()
	for _, e := range s.Entries() {
		if e.Role == RoleRoot {
			p.AddCert(e.Cert.Certificate)
		}
	}
	return p
}
