package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mrwiora/tpm2-verifier/bundle"
	"github.com/mrwiora/tpm2-verifier/tpm"
	"github.com/mrwiora/tpm2-verifier/vendorinfo"
	"github.com/mrwiora/tpm2-verifier/verify"
)

func runDebug(args []string, stdout io.Writer) error {
	fs := newFlagSet("debug", "",
		"Writes a debug bundle (.tar.gz) with everything tpm2-ek reads from the TPM:\n"+
			"properties, all NV public areas, the content of the readable TCG NV indices,\n"+
			"platform information (kernel, TPM sysfs, DMI vendor/model; no serials), and\n"+
			"the verification result including every certificate of the chains, also\n"+
			"those downloaded via AIA. Replay it anywhere with -tpm bundle:<file>.\n\n"+
			"The bundle contains the EK certificate, which uniquely identifies the TPM.\n"+
			"To add a vendor without revealing the TPM, use debug-anon instead.")
	spec := addTPMFlag(fs)
	out := fs.String("o", "", "output file (default tpm2-ek-debug-<manufacturer>-<time>.tar.gz)")
	noPlatform := fs.Bool("no-platform", false, "do not record kernel, sysfs and DMI information")
	overlay := fs.String("store", "", "additional vendor store directory")
	crlf := addCRLFlags(fs)
	if pos, err := parseInterleaved(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		fs.Usage()
		return exitError(2)
	}
	if strings.HasPrefix(*spec, "bundle:") {
		return fmt.Errorf("-tpm bundle: replays a bundle; debug needs a TPM")
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	opts, err := revocationOpts("best-effort", crlf)
	if err != nil {
		return err
	}

	ctx := context.Background()
	t, err := openTPM(*spec)
	if err != nil {
		if h := tpm.PermissionHint(err); h != "" {
			return fmt.Errorf("%w\n  hint: %s", err, h)
		}
		return err
	}
	b, err := bundle.Collect(ctx, t.Backend(), bundle.CollectOptions{Tool: versionString(), TPM: *spec, NoPlatform: *noPlatform})
	t.Close()
	if err != nil {
		return err
	}

	// Analyze the recording, not the live TPM, so the analysis shows exactly
	// what a replay of the bundle shows.
	s, err := tpm.New(b.Fake()).Scan(ctx)
	if err != nil {
		return err
	}
	results, err := verifyScan(ctx, s, st, opts)
	if err != nil {
		return err
	}
	var summary bytes.Buffer
	printInfo(&summary, s, st, results, true)
	b.Extra["analysis/summary.txt"] = summary.Bytes()
	report, err := json.MarshalIndent(infoJSON(s, st, results), "", "  ")
	if err != nil {
		return err
	}
	b.Extra["analysis/report.json"] = append(report, '\n')
	for _, r := range results {
		for depth, l := range r.Report.Chain {
			name := fmt.Sprintf("analysis/chains/%s/%d-%s.der", r.Index, depth, l.Source)
			b.Extra[name] = l.Cert.Raw
		}
	}

	if *out == "" {
		m := sanitizeName(s.Info.Manufacturer)
		if m == "" {
			m = "unknown"
		}
		*out = fmt.Sprintf("tpm2-ek-debug-%s-%s.tar.gz", m, b.Manifest.Created.Format("20060102-150405"))
	}
	if err := b.WriteFile(*out); err != nil {
		return err
	}
	fi, _ := os.Stat(*out)
	fmt.Fprintf(stdout, "Wrote %s (%d bytes)\n\n", *out, fi.Size())
	fmt.Fprintf(stdout, "TPM:  %s, firmware %s\n", s.Info.Manufacturer, s.Info.FirmwareVersion)
	fmt.Fprintf(stdout, "NV:   %d indices, %d EK certificates\n", len(s.Entries), len(results))
	for _, r := range results {
		fmt.Fprintf(stdout, "EK:   %s %s\n", r.Index, strings.ToUpper(string(r.Report.Status)))
		if r.Report.Status != verify.StatusTrusted {
			last := r.Report.Chain[len(r.Report.Chain)-1]
			fmt.Fprintf(stdout, "      chain ends at %q (sha256 %s)\n", last.Subject, last.Fingerprint)
		}
	}
	fmt.Fprintf(stdout, "\nPrivacy: the bundle contains the EK certificate, which uniquely identifies\n"+
		"this TPM. Share it only with people you trust with that, or use debug-anon.\nReplay it with:\n"+
		"  tpm2-ek info -tpm bundle:%s\n", path.Base(*out))
	return nil
}

func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return -1
	}, s)
}

func runDebugAnon(args []string, stdout io.Writer) error {
	fs := newFlagSet("debug-anon", "",
		"Collects what is needed to add the TPM's vendor to the vendor store, without\n"+
			"anything that identifies the TPM:\n\n"+
			"  info.json     TPM manufacturer, vendor string, firmware; NV layout (index,\n"+
			"                attributes, size) without content; per EK the chain, public\n"+
			"                certificates in full, device specific ones (EK, per-device CAs)\n"+
			"                only by structure: no serial number, key, signature, key\n"+
			"                identifier, fingerprint or dates, device specific names redacted\n"+
			"  certs/        public CA certificates (vendor store, downloaded via AIA)\n"+
			"  vendor/<id>/  draft vendor directory (vendor.yaml, README.md, roots/,\n"+
			"                intermediates/), usable with -store\n\n"+
			"-o ending in .tar.gz or .tgz writes an archive, anything else a directory.\n"+
			"-tpm bundle:<file> converts an existing debug bundle.")
	spec := addTPMFlag(fs)
	out := fs.String("o", "", "output archive or directory (default tpm2-ek-debug-anon-<manufacturer>-<date>.tar.gz)")
	platform := fs.Bool("platform", false, "include the DMI vendor/model and TPM sysfs strings")
	strict := fs.Bool("strict", false, "redact all name values of device specific CAs except C and O\n(default: only serial numbers, IDs and long hex/digit runs)")
	var include stringList
	fs.Var(&include, "include", "SHA-256 of a certificate from the TPM to include in full (a vendor CA\nshared by all devices but published nowhere; repeatable)")
	overlay := fs.String("store", "", "additional vendor store directory")
	crlf := addCRLFlags(fs)
	if pos, err := parseInterleaved(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		fs.Usage()
		return exitError(2)
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	opts, err := revocationOpts("best-effort", crlf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	s, err := scanTPM(ctx, *spec)
	if err != nil {
		return err
	}
	results, err := verifyScan(ctx, s, st, opts)
	if err != nil {
		return err
	}
	vopts := vendorinfo.Options{Tool: versionString(), Published: publishedCerts(ctx, s, results, crlf), Include: include, Strict: *strict}
	if *platform && !strings.HasPrefix(*spec, "bundle:") {
		_, p := bundle.PlatformInfo()
		vopts.Platform = map[string]string{}
		for k, v := range p {
			if !strings.HasPrefix(k, "dmi/bios") {
				vopts.Platform[k] = v
			}
		}
	}
	var eks []vendorinfo.EKReport
	for i, e := range s.EKCertificates() {
		eks = append(eks, vendorinfo.EKReport{Index: e.Index, Report: results[i].Report})
	}
	info, err := vendorinfo.Build(s, eks, st, vopts)
	if err != nil {
		return err
	}

	if *out == "" {
		m := sanitizeName(s.Info.Manufacturer)
		if m == "" {
			m = "unknown"
		}
		*out = fmt.Sprintf("tpm2-ek-debug-anon-%s-%s.tar.gz", m, strings.ReplaceAll(info.Created, "-", ""))
	}
	archive := strings.HasSuffix(*out, ".tar.gz") || strings.HasSuffix(*out, ".tgz")
	if archive {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if err := info.WriteArchive(f); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	} else if err := info.WriteDir(*out); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Wrote %s\n\n", *out)
	fmt.Fprintf(stdout, "TPM:  %s (%s), firmware %s\n", s.Info.Manufacturer, s.Info.VendorString, s.Info.FirmwareVersion)
	for _, ek := range info.EK {
		fmt.Fprintf(stdout, "EK:   %s %s\n", ek.Index, strings.ToUpper(string(ek.Status)))
	}
	fmt.Fprintf(stdout, "\nIncluded in full (public):\n")
	if len(info.Certificates) == 0 {
		fmt.Fprintf(stdout, "  none\n")
	}
	for _, c := range info.Certificates {
		from := c.URL
		if c.StorePath != "" {
			from = "store " + c.StorePath
		} else if c.Included {
			from = "-include"
		}
		fmt.Fprintf(stdout, "  %s  (%s)\n", c.Subject, from)
	}
	fmt.Fprintf(stdout, "\nDescribed by structure only (shown here, not written):\n")
	seen := map[string]bool{}
	var deviceCA bool
	for k, r := range results {
		for i, l := range r.Report.Chain {
			d := info.EK[k].Chain[i]
			if d.Public || seen[l.Fingerprint] {
				continue
			}
			seen[l.Fingerprint] = true
			fmt.Fprintf(stdout, "  %s  sha256 %s\n", l.Subject, l.Fingerprint)
			if d.Subject != l.Subject {
				fmt.Fprintf(stdout, "      written as: %s\n", d.Subject)
			}
			deviceCA = deviceCA || l.Cert.IsCA
		}
	}
	if deviceCA {
		fmt.Fprintf(stdout, "\n  CA certificates from the TPM count as device specific because they are not\n"+
			"  published. If one is shared by all devices of the vendor, add -include <sha256>.\n")
	}
	if p := info.Platform; p != nil {
		fmt.Fprintf(stdout, "\nPlatform strings included (-platform): %d\n", len(p))
	}
	draft := info.Draft
	if !archive {
		draft = filepath.Join(*out, filepath.FromSlash(draft))
	}
	fmt.Fprintf(stdout, "\nDraft vendor directory: %s\n", draft)
	if !archive {
		fmt.Fprintf(stdout, "Try it:  tpm2-ek info -store %s\n", filepath.Dir(draft))
	}
	return nil
}

// publishedCerts maps the fingerprints of certificates published at an AIA
// URL of a certificate in the TPM or of the chains to that URL.
func publishedCerts(ctx context.Context, s *tpm.Scan, results []ekResult, crlf crlFlags) map[string]string {
	out := map[string]string{}
	f := crlf.fetcher()
	if f == nil {
		return out
	}
	var urls []string
	for _, e := range s.Entries {
		for _, c := range e.Certificates {
			urls = append(urls, c.IssuingCertificateURL...)
		}
	}
	for _, r := range results {
		for _, l := range r.Report.Chain {
			urls = append(urls, l.Cert.IssuingCertificateURL...)
		}
	}
	for _, u := range urls {
		if _, done := out[u]; done {
			continue
		}
		if res, err := f.FetchCertificates(ctx, u); err == nil {
			for _, c := range res.Certificates {
				if _, ok := out[c.Fingerprint]; !ok {
					out[c.Fingerprint] = u
				}
			}
		}
	}
	return out
}
