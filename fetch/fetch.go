// Package fetch downloads CRLs named in CRL distribution points and issuer
// certificates named in AIA "CA Issuers" entries, and keeps them in a local
// cache.
//
// The cache mirrors the URL structure, so its content is easy to inspect:
//
//	<cache>/crls/tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
//	<cache>/crls/tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl.json  (metadata)
//	<cache>/certs/tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
//
// Fetched data is only parsed here. CRL signatures are verified by package
// verify against the issuing CA, and fetched certificates are only ever used
// as untrusted intermediates; trust comes from the vendor store alone.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
)

// Origin tells where a returned CRL came from.
type Origin string

const (
	OriginNetwork     Origin = "network"
	OriginNotModified Origin = "network-not-modified" // server confirmed the cached copy
	OriginCache       Origin = "cache"                // fresh enough, no request made
	OriginStaleCache  Origin = "stale-cache"          // download failed, cached copy used
)

// ErrOffline is returned when a CRL is not cached and the fetcher is offline.
var ErrOffline = errors.New("fetch: not in cache and offline")

// Result is a fetched CRL.
type Result struct {
	URL       string
	CRL       *certparse.CRL
	Origin    Origin
	FetchedAt time.Time
	// Path is the cache file, if cached.
	Path string
	// Warning is set when a stale copy or an older download was rejected.
	Warning string
}

// Meta is the sidecar metadata stored next to each cached CRL.
type Meta struct {
	URL          string    `json:"url"`
	FetchedAt    time.Time `json:"fetched_at"`
	SHA256       string    `json:"sha256"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
}

// Fetcher downloads and caches CRLs and AIA issuer certificates. The zero value is not usable; use New.
type Fetcher struct {
	client   *http.Client
	cacheDir string
	maxAge   time.Duration
	offline  bool
	maxSize  int64
	now      func() time.Time

	mu   sync.Mutex
	memo map[string]memoEntry
}

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithClient sets the HTTP client.
func WithClient(c *http.Client) Option { return func(f *Fetcher) { f.client = c } }

// WithCacheDir sets the cache directory; "" disables caching.
func WithCacheDir(dir string) Option { return func(f *Fetcher) { f.cacheDir = dir } }

// WithMaxAge sets how long a cached CRL is used without asking the server
// (default 24h). A CRL past its nextUpdate is always refreshed.
func WithMaxAge(d time.Duration) Option { return func(f *Fetcher) { f.maxAge = d } }

// WithOffline uses the cache only.
func WithOffline(offline bool) Option { return func(f *Fetcher) { f.offline = offline } }

// WithTime fixes the clock (for tests).
func WithTime(t time.Time) Option {
	return func(f *Fetcher) { f.now = func() time.Time { return t } }
}

// DefaultCacheDir returns $XDG_CACHE_HOME/tpm2-verifier (%LocalAppData% on Windows).
func DefaultCacheDir() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tpm2-verifier"), nil
}

// New returns a Fetcher. Without WithCacheDir nothing is cached.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{
		client:  &http.Client{Timeout: 20 * time.Second},
		maxAge:  24 * time.Hour,
		maxSize: 16 << 20,
		now:     time.Now,
		memo:    map[string]memoEntry{},
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

type memoEntry struct {
	obj *object
	err error
}

// object is a cached download of some kind.
type object struct {
	value     any
	origin    Origin
	fetchedAt time.Time
	path      string
	warning   string
}

// kind describes how one type of object is parsed and cached.
type kind struct {
	dir   string
	name  string
	parse func([]byte) (any, error)
	// fresh reports whether a cached value may be used without asking the server.
	fresh func(v any, now time.Time) bool
	// rollback returns a reason if next must not replace cached.
	rollback func(cached, next any) string
}

var crlKind = kind{
	dir:  "crls",
	name: "CRL",
	parse: func(b []byte) (any, error) {
		return certparse.ParseCRL(b)
	},
	fresh: func(v any, now time.Time) bool {
		crl := v.(*certparse.CRL)
		return crl.NextUpdate.IsZero() || now.Before(crl.NextUpdate)
	},
	rollback: func(cached, next any) string {
		c, n := cached.(*certparse.CRL), next.(*certparse.CRL)
		if certparse.SameName(c.RawIssuer, n.RawIssuer) && c.Number != nil && n.Number != nil && n.Number.Cmp(c.Number) < 0 {
			return fmt.Sprintf("server returned older CRL #%s, keeping cached #%s", n.Number, c.Number)
		}
		return ""
	},
}

var certKind = kind{
	dir:  "certs",
	name: "certificate",
	parse: func(b []byte) (any, error) {
		return certparse.ParseCertificatesAny(b)
	},
	fresh:    func(any, time.Time) bool { return true },
	rollback: func(any, any) string { return "" },
}

// FetchCRL returns the CRL at rawURL, from the cache or the network.
// Results are memoized for the lifetime of the fetcher.
func (f *Fetcher) FetchCRL(ctx context.Context, rawURL string) (*Result, error) {
	o, err := f.get(ctx, rawURL, crlKind)
	if err != nil {
		return nil, err
	}
	return &Result{URL: rawURL, CRL: o.value.(*certparse.CRL), Origin: o.origin, FetchedAt: o.fetchedAt, Path: o.path, Warning: o.warning}, nil
}

// CertResult is the content of an AIA "CA Issuers" URL.
type CertResult struct {
	URL          string
	Certificates []*certparse.Certificate
	Origin       Origin
	FetchedAt    time.Time
	Path         string
	Warning      string
}

// FetchCertificates returns the certificates published at an AIA "CA
// Issuers" URL (DER, PEM or PKCS#7), from the cache or the network.
func (f *Fetcher) FetchCertificates(ctx context.Context, rawURL string) (*CertResult, error) {
	o, err := f.get(ctx, rawURL, certKind)
	if err != nil {
		return nil, err
	}
	return &CertResult{URL: rawURL, Certificates: o.value.([]*certparse.Certificate), Origin: o.origin, FetchedAt: o.fetchedAt, Path: o.path, Warning: o.warning}, nil
}

func (f *Fetcher) get(ctx context.Context, rawURL string, k kind) (*object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := k.dir + " " + rawURL
	if m, ok := f.memo[key]; ok {
		return m.obj, m.err
	}
	o, err := f.fetch(ctx, rawURL, k)
	f.memo[key] = memoEntry{o, err}
	return o, err
}

func (f *Fetcher) fetch(ctx context.Context, rawURL string, k kind) (*object, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("fetch: unsupported scheme %q in %s", u.Scheme, rawURL)
	}
	var cached *object
	var meta *Meta
	cachePath := ""
	if f.cacheDir != "" {
		cachePath = filepath.Join(f.cacheDir, k.dir, CachePath(u))
		cached, meta = loadCached(cachePath, k)
	}
	now := f.now()
	if cached != nil {
		fresh := now.Sub(meta.FetchedAt) < f.maxAge && k.fresh(cached.value, now)
		if f.offline || fresh {
			cached.origin = OriginCache
			return cached, nil
		}
	}
	if f.offline {
		return nil, ErrOffline
	}

	data, hdr, status, err := f.download(ctx, rawURL, meta)
	if err != nil {
		if cached != nil {
			cached.origin = OriginStaleCache
			cached.warning = fmt.Sprintf("download failed (%v), using copy fetched %s", err, meta.FetchedAt.Format(time.RFC3339))
			return cached, nil
		}
		return nil, err
	}
	if status == http.StatusNotModified && cached != nil {
		meta.FetchedAt = now
		_ = writeMeta(cachePath, meta)
		cached.origin, cached.fetchedAt = OriginNotModified, now
		return cached, nil
	}
	v, err := k.parse(data)
	if err != nil {
		if cached != nil {
			cached.origin = OriginStaleCache
			cached.warning = fmt.Sprintf("downloaded data is not a %s (%v), using cached copy", k.name, err)
			return cached, nil
		}
		return nil, fmt.Errorf("fetch: %s: %w", rawURL, err)
	}
	if cached != nil {
		if reason := k.rollback(cached.value, v); reason != "" {
			cached.origin, cached.warning = OriginStaleCache, reason
			return cached, nil
		}
	}
	o := &object{value: v, origin: OriginNetwork, fetchedAt: now}
	if cachePath != "" {
		sum := sha256.Sum256(data)
		m := &Meta{URL: rawURL, FetchedAt: now, SHA256: hex.EncodeToString(sum[:]),
			ETag: hdr.Get("ETag"), LastModified: hdr.Get("Last-Modified")}
		if err := writeAtomic(cachePath, data); err != nil {
			return nil, fmt.Errorf("fetch: cache: %w", err)
		}
		if err := writeMeta(cachePath, m); err != nil {
			return nil, fmt.Errorf("fetch: cache: %w", err)
		}
		o.path = cachePath
	}
	return o, nil
}

func (f *Fetcher) download(ctx context.Context, rawURL string, meta *Meta) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", "tpm2-verifier (+https://github.com/tpm2-trust/tpm2-verifier)")
	if meta != nil {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, resp.Header, resp.StatusCode, nil
	default:
		return nil, nil, resp.StatusCode, fmt.Errorf("fetch: %s: HTTP %s", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, nil, 0, err
	}
	if int64(len(data)) > f.maxSize {
		return nil, nil, 0, fmt.Errorf("fetch: %s: larger than %d bytes", rawURL, f.maxSize)
	}
	return data, resp.Header, resp.StatusCode, nil
}

// CachePath maps a URL to a relative, sanitized cache path:
// host/path/segments. Unusual characters become "_", "." and ".." segments
// are dropped, and a query string adds a hash suffix.
func CachePath(u *url.URL) string {
	parts := []string{sanitize(strings.ReplaceAll(u.Host, ":", "_"))}
	for _, s := range strings.Split(path.Clean("/"+u.Path), "/") {
		if s == "" || s == "." || s == ".." {
			continue
		}
		parts = append(parts, sanitize(s))
	}
	if len(parts) == 1 {
		parts = append(parts, "index")
	}
	if u.RawQuery != "" {
		sum := sha256.Sum256([]byte(u.RawQuery))
		parts[len(parts)-1] += "_" + hex.EncodeToString(sum[:4])
	}
	return filepath.Join(parts...)
}

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			b[i] = '_'
		}
	}
	if len(b) == 0 || b[0] == '.' {
		return "_" + string(b)
	}
	return string(b)
}

func loadCached(p string, k kind) (*object, *Meta) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nil
	}
	v, err := k.parse(data)
	if err != nil {
		return nil, nil
	}
	m := &Meta{}
	if raw, err := os.ReadFile(p + ".json"); err == nil {
		_ = json.Unmarshal(raw, m)
	}
	return &object{value: v, fetchedAt: m.FetchedAt, path: p}, m
}

func writeMeta(p string, m *Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(p+".json", append(b, '\n'))
}

func writeAtomic(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// CacheEntry describes one cached CRL.
type CacheEntry struct {
	Path string
	Meta Meta
	CRL  *certparse.CRL
}

// List returns all cached CRLs.
func (f *Fetcher) List() ([]CacheEntry, error) {
	if f.cacheDir == "" {
		return nil, nil
	}
	root := filepath.Join(f.cacheDir, "crls")
	var out []CacheEntry
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return filepath.SkipAll
		}
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".json") || strings.HasPrefix(d.Name(), ".tmp-") {
			return err
		}
		if o, m := loadCached(p, crlKind); o != nil {
			out = append(out, CacheEntry{Path: p, Meta: *m, CRL: o.value.(*certparse.CRL)})
		}
		return nil
	})
	return out, err
}

// Clear removes all cached CRLs and certificates.
func (f *Fetcher) Clear() error {
	if f.cacheDir == "" {
		return nil
	}
	for _, k := range []kind{crlKind, certKind} {
		if err := os.RemoveAll(filepath.Join(f.cacheDir, k.dir)); err != nil {
			return err
		}
	}
	return nil
}
