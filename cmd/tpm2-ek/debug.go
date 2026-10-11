package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/mrwiora/tpm2-verifier/bundle"
	"github.com/mrwiora/tpm2-verifier/tpm"
	"github.com/mrwiora/tpm2-verifier/verify"
)

func runDebug(args []string, stdout io.Writer) error {
	fs := newFlagSet("debug", "",
		"Writes a debug bundle (.tar.gz) with everything tpm2-ek reads from the TPM:\n"+
			"properties, all NV public areas, the content of the readable TCG NV indices,\n"+
			"platform information (kernel, TPM sysfs, DMI vendor/model; no serials), and\n"+
			"the verification result including every certificate of the chains, also\n"+
			"those downloaded via AIA. Replay it anywhere with -tpm bundle:<file>.\n\n"+
			"The bundle contains the EK certificate, which uniquely identifies the TPM.")
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
		"this TPM. Share it only with people you trust with that. Replay it with:\n"+
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
