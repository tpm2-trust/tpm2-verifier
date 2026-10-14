package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/fetch"
)

// crlFlags are the CRL fetching flags shared by verify and info.
type crlFlags struct {
	noFetch  *bool
	offline  *bool
	cacheDir *string
}

func addCRLFlags(fs *flag.FlagSet) crlFlags {
	def, _ := fetch.DefaultCacheDir()
	return crlFlags{
		noFetch:  fs.Bool("no-fetch", false, "do not download CRLs (CDP) or issuer certificates (AIA)"),
		offline:  fs.Bool("offline", false, "use cached CRLs and certificates only, no network access"),
		cacheDir: fs.String("cache-dir", def, "cache directory for CRLs and certificates (empty disables the cache)"),
	}
}

// fetcher returns nil if fetching is disabled.
func (c crlFlags) fetcher() *fetch.Fetcher {
	if *c.noFetch {
		return nil
	}
	return fetch.New(fetch.WithCacheDir(*c.cacheDir), fetch.WithOffline(*c.offline))
}

func runCache(args []string, stdout io.Writer) error {
	usage := func() error {
		def, _ := fetch.DefaultCacheDir()
		fmt.Fprintf(os.Stderr, `Usage: tpm2-ek cache <subcommand> [-cache-dir dir]

Subcommands:
  list    list cached CRLs
  clear   delete cached CRLs and AIA certificates
  path    print the cache directory

CRLs (CDP) and issuer certificates (AIA) downloaded by verify, info and debug
are cached in %[1]s/crls/<host>/<path> and %[1]s/certs/<host>/<path>,
each with a .json file holding URL, fetch time and SHA-256.
`, def)
		return exitError(2)
	}
	if len(args) == 0 {
		return usage()
	}
	sub := args[0]
	fs := newFlagSet("cache "+sub, "", "Manages the CRL cache.")
	def, _ := fetch.DefaultCacheDir()
	dir := fs.String("cache-dir", def, "CRL cache directory")
	if _, err := parseInterleaved(fs, args[1:]); err != nil {
		return err
	}
	f := fetch.New(fetch.WithCacheDir(*dir))
	switch sub {
	case "path":
		fmt.Fprintln(stdout, *dir)
	case "clear":
		return f.Clear()
	case "list":
		entries, err := f.List()
		if err != nil {
			return err
		}
		now := time.Now()
		for _, e := range entries {
			state := "valid"
			if !e.CRL.NextUpdate.IsZero() && now.After(e.CRL.NextUpdate) {
				state = "STALE"
			}
			fmt.Fprintf(stdout, "%s\n  issuer:  %s\n  number:  %s, %d revoked, indirect %v\n  valid:   %s .. %s (%s)\n  fetched: %s\n  file:    %s\n",
				e.Meta.URL, e.CRL.IssuerString(), e.CRL.Number, len(e.CRL.RevokedCertificateEntries), e.CRL.Indirect,
				e.CRL.ThisUpdate.Format(time.DateOnly), e.CRL.NextUpdate.Format(time.DateOnly), state,
				e.Meta.FetchedAt.Format(time.RFC3339), e.Path)
		}
		if len(entries) == 0 {
			fmt.Fprintln(stdout, "cache is empty")
		}
	default:
		return usage()
	}
	return nil
}
