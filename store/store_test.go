package store_test

import (
	"io/fs"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mrwiora/tpm2-verifier/store"
	"github.com/mrwiora/tpm2-verifier/vendors"
)

func TestEmbeddedStoreLoads(t *testing.T) {
	s, err := store.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	intel := s.VendorForManufacturer("INTC")
	if intel == nil || intel.ID != "intel" {
		t.Fatalf("intel not found: %+v", intel)
	}
	if len(intel.Roots()) != 1 || len(intel.Intermediates()) != 2 {
		t.Errorf("roots=%d intermediates=%d", len(intel.Roots()), len(intel.Intermediates()))
	}
	if len(intel.ChainNVIndices) != 1 || intel.ChainNVIndices[0] != 0x01C00100 {
		t.Errorf("chain indices %v", intel.ChainNVIndices)
	}
	if intel.Readme == "" {
		t.Error("README not loaded")
	}
	if s.VendorForManufacturer("INTC\x00") != intel {
		t.Error("manufacturer lookup does not normalize")
	}
}

// Every certificate file in the embedded store must be listed in its vendor
// manifest, so nothing is trusted without a recorded fingerprint and source.
func TestNoUnlistedFiles(t *testing.T) {
	s, err := store.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, v := range s.Vendors() {
		for _, e := range v.Certificates {
			listed[path.Join(v.ID, e.File)] = true
			if e.Source == "" {
				t.Errorf("%s/%s: no source URL", v.ID, e.File)
			}
		}
	}
	fs.WalkDir(vendors.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(p, ".der") && !listed[p] {
			t.Errorf("%s is not listed in vendor.yaml", p)
		}
		return nil
	})
}

func TestFingerprintMismatchRejected(t *testing.T) {
	root, err := fs.ReadFile(vendors.FS, "intel/roots/ondie-ca-root.der")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"bad/vendor.yaml": {Data: []byte(`
id: bad
manufacturer_ids: [BAD]
certificates:
  - file: roots/r.der
    role: root
    sha256: 0000000000000000000000000000000000000000000000000000000000000000
`)},
		"bad/roots/r.der": {Data: root},
	}
	s, _ := store.Embedded()
	if err := s.AddFS(fsys, "test"); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
}

func TestIntermediateAsRootRejected(t *testing.T) {
	der, _ := fs.ReadFile(vendors.FS, "intel/intermediates/ondie-ca-csme-intermediate.der")
	fsys := fstest.MapFS{
		"x/vendor.yaml": {Data: []byte(`
manufacturer_ids: [X]
certificates:
  - file: r.der
    role: root
    sha256: 5e3eee5748ac13e0b3d1227fcdc4751aa1402dde8031d21f63cb4ecf43f02440
`)},
		"x/r.der": {Data: der},
	}
	var s store.Store
	if err := s.AddFS(fsys, "test"); err == nil || !strings.Contains(err.Error(), "not self-signed") {
		t.Fatalf("want self-signed error, got %v", err)
	}
}

func TestOverlayMerge(t *testing.T) {
	fsys := fstest.MapFS{
		"intel/vendor.yaml": {Data: []byte(`
id: intel
chain_nv_indices: [0x01C00101]
accepted_critical_extensions: [1.2.840.113741.1.5.5.1.1]
certificates: []
`)},
	}
	s, _ := store.Embedded()
	if err := s.AddFS(fsys, "overlay"); err != nil {
		t.Fatal(err)
	}
	intel := s.Vendor("intel")
	if len(intel.ChainNVIndices) != 2 || len(intel.Roots()) != 1 || len(intel.AcceptedCriticalOIDs()) != 1 {
		t.Errorf("merge result: %+v", intel)
	}
	if len(s.Vendors()) != 1 {
		t.Errorf("vendor duplicated")
	}
}
