package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-verifier/bundle"
	"github.com/tpm2-trust/tpm2-verifier/certparse"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

// TestBundleFixtures replays every bundle in testdata/bundles and checks that
// the EK verification still gives the status recorded when the bundle was
// created. Certificates that were downloaded via AIA at creation time are
// taken from the bundle, so the test needs no network. Revocation is not
// checked (CRLs change over time); bundles recorded as revoked are skipped.
func TestBundleFixtures(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/bundles/*.tar.gz")
	if len(files) == 0 {
		t.Skip("no fixture bundles")
	}
	st, err := store.LoadDir("../../ekroots/vendors")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := bundle.Load(f)
			if err != nil {
				t.Fatal(err)
			}
			var recorded struct {
				EK []struct {
					Index  string
					Report struct{ Status verify.Status }
				}
			}
			if err := json.Unmarshal(b.Extra["analysis/report.json"], &recorded); err != nil {
				t.Fatal(err)
			}
			var aia []*certparse.Certificate
			for name, data := range b.Extra {
				if strings.HasPrefix(name, "analysis/chains/") && strings.HasSuffix(name, "-aia.der") {
					c, err := certparse.Parse(data)
					if err != nil {
						t.Fatal(err)
					}
					aia = append(aia, c)
				}
			}
			s, err := tpm.New(b.Fake()).Scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			v := verify.New(st, verify.WithRevocation(verify.RevocationOff), verify.WithTime(b.Manifest.Created))
			eks := s.EKCertificates()
			if len(eks) != len(recorded.EK) {
				t.Fatalf("%d EK certificates, recorded %d", len(eks), len(recorded.EK))
			}
			for i, e := range eks {
				want := recorded.EK[i]
				if want.Report.Status == verify.StatusRevoked {
					continue
				}
				rep, err := v.Verify(context.Background(), e.Certificates[0], append(s.ChainCertificates(), aia...))
				if err != nil {
					t.Fatal(err)
				}
				if tpm.HexIndex(e.Index) != want.Index || rep.Status != want.Report.Status {
					t.Errorf("%s: %s, recorded %s %s", tpm.HexIndex(e.Index), rep.Status, want.Index, want.Report.Status)
				}
			}
		})
	}
}
