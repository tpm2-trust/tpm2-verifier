// Package fetch downloads CRLs named in CRL distribution points and keeps
// them in a local cache.
//
// The cache mirrors the URL structure, so its content is easy to inspect:
//
//	<cache>/crls/tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
//	<cache>/crls/tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl.json  (metadata)
//
// Fetched data is only parsed here. Signatures are verified by package
// verify against the issuing CA, which is the only point where the issuer is
// known; an unverified CRL in the cache is therefore harmless.
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

	"github.com/mrwiora/tpm2-verifier/certparse"
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

// CRLFetcher downloads and caches CRLs. The zero value is not usable; use New.
type CRLFetcher struct {
	client   *http.Client
	cacheDir string
	maxAge   time.Duration
	offline  bool
	maxSize  int64
	now      func() time.Time

	mu       sync.Mutex
	memo     map[string]*Result
	memoErrs map[string]error
}

// Option configures a CRLFetcher.
type Option func(*CRLFetcher)

// WithClient sets the HTTP client.
func WithClient(c *http.Client) Option { return func(f *CRLFetcher) { f.client = c } }

// WithCacheDir sets the cache directory; "" disables caching.
func WithCacheDir(dir string) Option { return func(f *CRLFetcher) { f.cacheDir = dir } }

// WithMaxAge sets how long a cached CRL is used without asking the server
// (default 24h). A CRL past its nextUpdate is always refreshed.
func WithMaxAge(d time.Duration) Option { return func(f *CRLFetcher) { f.maxAge = d } }

// WithOffline uses the cache only.
func WithOffline(offline bool) Option { return func(f *CRLFetcher) { f.offline = offline } }

// WithTime fixes the clock (for tests).
func WithTime(t time.Time) Option {
	return func(f *CRLFetcher) { f.now = func() time.Time { return t } }
}

// DefaultCacheDir returns $XDG_CACHE_HOME/tpm2-verifier (%LocalAppData% on Windows).
func DefaultCacheDir() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tpm2-verifier"), nil
}

// New returns a CRLFetcher. Without WithCacheDir nothing is cached.
func New(opts ...Option) *CRLFetcher {
	f := &CRLFetcher{
		client:   &http.Client{Timeout: 20 * time.Second},
		maxAge:   24 * time.Hour,
		maxSize:  16 << 20,
		now:      time.Now,
		memo:     map[string]*Result{},
		memoErrs: map[string]error{},
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// FetchCRL returns the CRL at rawURL, from the cache or the network.
// Results are memoized for the lifetime of the fetcher.
func (f *CRLFetcher) FetchCRL(ctx context.Context, rawURL string) (*Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.memo[rawURL]; ok {
		return r, nil
	}
	if err, ok := f.memoErrs[rawURL]; ok {
		return nil, err
	}
	r, err := f.fetch(ctx, rawURL)
	if err != nil {
		f.memoErrs[rawURL] = err
		return nil, err
	}
	f.memo[rawURL] = r
	return r, nil
}

func (f *CRLFetcher) fetch(ctx context.Context, rawURL string) (*Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("fetch: unsupported scheme %q in %s", u.Scheme, rawURL)
	}
	var cached *Result
	var meta *Meta
	cachePath := ""
	if f.cacheDir != "" {
		cachePath = filepath.Join(f.cacheDir, "crls", CachePath(u))
		cached, meta = loadCached(cachePath)
	}
	now := f.now()
	if cached != nil {
		fresh := now.Sub(meta.FetchedAt) < f.maxAge && (cached.CRL.NextUpdate.IsZero() || now.Before(cached.CRL.NextUpdate))
		if f.offline || fresh {
			cached.Origin = OriginCache
			return cached, nil
		}
	}
	if f.offline {
		return nil, ErrOffline
	}

	data, hdr, status, err := f.download(ctx, rawURL, meta)
	if err != nil {
		if cached != nil {
			cached.Origin = OriginStaleCache
			cached.Warning = fmt.Sprintf("download failed (%v), using copy fetched %s", err, meta.FetchedAt.Format(time.RFC3339))
			return cached, nil
		}
		return nil, err
	}
	if status == http.StatusNotModified && cached != nil {
		meta.FetchedAt = now
		_ = writeMeta(cachePath, meta)
		cached.Origin, cached.FetchedAt = OriginNotModified, now
		return cached, nil
	}
	crl, err := certparse.ParseCRL(data)
	if err != nil {
		if cached != nil {
			cached.Origin = OriginStaleCache
			cached.Warning = fmt.Sprintf("downloaded data is not a CRL (%v), using cached copy", err)
			return cached, nil
		}
		return nil, fmt.Errorf("fetch: %s: %w", rawURL, err)
	}
	// Do not let an older CRL replace a newer one (rollback).
	if cached != nil && certparse.SameName(cached.CRL.RawIssuer, crl.RawIssuer) &&
		cached.CRL.Number != nil && crl.Number != nil && crl.Number.Cmp(cached.CRL.Number) < 0 {
		cached.Origin = OriginStaleCache
		cached.Warning = fmt.Sprintf("server returned older CRL #%s, keeping cached #%s", crl.Number, cached.CRL.Number)
		return cached, nil
	}
	res := &Result{URL: rawURL, CRL: crl, Origin: OriginNetwork, FetchedAt: now}
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
		res.Path = cachePath
	}
	return res, nil
}

func (f *CRLFetcher) download(ctx context.Context, rawURL string, meta *Meta) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", "tpm2-verifier (+https://github.com/mrwiora/tpm2-verifier)")
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

func loadCached(p string) (*Result, *Meta) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nil
	}
	crl, err := certparse.ParseCRL(data)
	if err != nil {
		return nil, nil
	}
	m := &Meta{}
	if raw, err := os.ReadFile(p + ".json"); err == nil {
		_ = json.Unmarshal(raw, m)
	}
	return &Result{URL: m.URL, CRL: crl, FetchedAt: m.FetchedAt, Path: p}, m
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
func (f *CRLFetcher) List() ([]CacheEntry, error) {
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
		if r, m := loadCached(p); r != nil {
			out = append(out, CacheEntry{Path: p, Meta: *m, CRL: r.CRL})
		}
		return nil
	})
	return out, err
}

// Clear removes all cached CRLs.
func (f *CRLFetcher) Clear() error {
	if f.cacheDir == "" {
		return nil
	}
	return os.RemoveAll(filepath.Join(f.cacheDir, "crls"))
}
