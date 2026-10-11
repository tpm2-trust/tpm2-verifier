package fetch_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-verifier/fetch"
	"github.com/mrwiora/tpm2-verifier/internal/testpki"
)

var ctx = context.Background()

func readCRL(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../testdata/intel/crls", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// server serves body (or status) and counts requests.
type server struct {
	*httptest.Server
	body     atomic.Pointer[[]byte]
	status   atomic.Int32
	noETag   atomic.Bool
	requests atomic.Int32
}

func newServer(t *testing.T, body []byte) *server {
	s := &server{}
	s.body.Store(&body)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if st := s.status.Load(); st != 0 {
			w.WriteHeader(int(st))
			return
		}
		if s.noETag.Load() {
			w.Write(*s.body.Load())
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(*s.body.Load())
	}))
	t.Cleanup(s.Close)
	return s
}

func TestFetchCachesUnderURLPath(t *testing.T) {
	srv := newServer(t, readCRL(t, "OnDie_CA_CSME_Indirect.crl"))
	dir := t.TempDir()
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	u := srv.URL + "/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl"

	r, err := fetch.New(fetch.WithCacheDir(dir), fetch.WithTime(now)).FetchCRL(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if r.Origin != fetch.OriginNetwork || !r.CRL.Indirect {
		t.Fatalf("origin %s indirect %v", r.Origin, r.CRL.Indirect)
	}
	pu, _ := url.Parse(u)
	want := filepath.Join(dir, "crls", fetch.CachePath(pu))
	if filepath.Base(filepath.Dir(want)) != "crls" || filepath.Base(want) != "OnDie_CA_CSME_Indirect.crl" {
		t.Fatalf("unexpected cache layout %s", want)
	}
	if r.Path != want {
		t.Fatalf("path %s, want %s", r.Path, want)
	}
	if _, err := os.Stat(want + ".json"); err != nil {
		t.Fatal(err)
	}

	// A new fetcher within max age uses the cache without a request.
	r, err = fetch.New(fetch.WithCacheDir(dir), fetch.WithTime(now.Add(time.Hour))).FetchCRL(ctx, u)
	if err != nil || r.Origin != fetch.OriginCache || srv.requests.Load() != 1 {
		t.Fatalf("origin %v err %v requests %d", r.Origin, err, srv.requests.Load())
	}

	// After max age the server is asked; it answers 304 for the same ETag.
	r, err = fetch.New(fetch.WithCacheDir(dir), fetch.WithTime(now.Add(48*time.Hour))).FetchCRL(ctx, u)
	if err != nil || r.Origin != fetch.OriginNotModified || srv.requests.Load() != 2 {
		t.Fatalf("origin %v err %v requests %d", r.Origin, err, srv.requests.Load())
	}

	// Server down: the stale copy is used with a warning.
	srv.status.Store(http.StatusInternalServerError)
	r, err = fetch.New(fetch.WithCacheDir(dir), fetch.WithTime(now.Add(96*time.Hour))).FetchCRL(ctx, u)
	if err != nil || r.Origin != fetch.OriginStaleCache || r.Warning == "" {
		t.Fatalf("origin %v err %v warning %q", r.Origin, err, r.Warning)
	}

	entries, err := fetch.New(fetch.WithCacheDir(dir)).List()
	if err != nil || len(entries) != 1 || entries[0].Meta.URL != u {
		t.Fatalf("list: %v %+v", err, entries)
	}
}

func TestFetchRejectsRollback(t *testing.T) {
	pki := testpki.IntelLike(t)
	now := pki.Now
	newer := pki.Int1.CRL(t, 5, now.AddDate(0, 0, -1), now.AddDate(0, 1, 0), nil)
	older := pki.Int1.CRL(t, 3, now.AddDate(0, 0, -2), now.AddDate(0, 1, 0), nil)

	srv := newServer(t, newer)
	srv.noETag.Store(true)
	dir := t.TempDir()
	if _, err := fetch.New(fetch.WithCacheDir(dir), fetch.WithTime(now)).FetchCRL(ctx, srv.URL+"/x.crl"); err != nil {
		t.Fatal(err)
	}
	srv.body.Store(&older)
	r, err := fetch.New(fetch.WithCacheDir(dir), fetch.WithTime(now), fetch.WithMaxAge(0)).FetchCRL(ctx, srv.URL+"/x.crl")
	if err != nil {
		t.Fatal(err)
	}
	if r.Origin != fetch.OriginStaleCache || r.CRL.Number.Int64() != 5 || r.Warning == "" {
		t.Fatalf("origin %s number %v warning %q", r.Origin, r.CRL.Number, r.Warning)
	}
}

func TestFetchOfflineAndErrors(t *testing.T) {
	f := fetch.New(fetch.WithCacheDir(t.TempDir()), fetch.WithOffline(true))
	if _, err := f.FetchCRL(ctx, "https://example.invalid/a.crl"); !errors.Is(err, fetch.ErrOffline) {
		t.Errorf("offline: %v", err)
	}
	if _, err := fetch.New().FetchCRL(ctx, "ldap://example/a.crl"); err == nil {
		t.Error("ldap accepted")
	}
	srv := newServer(t, []byte("not a crl"))
	if _, err := fetch.New().FetchCRL(ctx, srv.URL+"/a.crl"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCachePathSanitizes(t *testing.T) {
	for in, want := range map[string]string{
		"https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA.crl": filepath.Join("tsci.intel.com", "content", "OnDieCA", "crls", "OnDie_CA.crl"),
		"http://host:8080/../../etc/passwd":                        filepath.Join("host_8080", "etc", "passwd"),
		"http://host/a%20b/.hidden":                                filepath.Join("host", "a_b", "_.hidden"),
		"http://host/":                                             filepath.Join("host", "index"),
	} {
		u, _ := url.Parse(in)
		if got := fetch.CachePath(u); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
