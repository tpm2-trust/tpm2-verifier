package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tpm2-trust/tpm2-verifier/fetch"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/vendorimport"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

func runVendor(args []string, stdout io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "review":
			return vendorCommand(args[1:], stdout, false)
		case "import":
			return vendorCommand(args[1:], stdout, true)
		}
	}
	fmt.Fprintf(os.Stderr, `Usage: tpm2-verifier vendor <review|import> [flags] <submission>...

For maintainers: turns submissions (tpm2-verifier debug bundles or debug-anon
output, archive or directory) into changes of a vendor directory tree such as
the ekroots/vendors/ directory of the repository (-store ekroots/vendors).

  review   show what an import would change, and every warning (read-only)
  import   write the changes (certificates, vendor.yaml, observations.yaml,
           README.md, MANIFEST); undone if the result does not load. The
           MANIFEST gets a new version and must be signed again

Nothing in a submission is trusted. Each certificate is downloaded again from
its source URL and only taken if the vendor serves identical bytes. Roots,
certificates read from the TPM, certificates without URL or from a host
outside the vendor's domains need approval with -accept <sha256>.
`)
	return exitError(2)
}

func vendorCommand(args []string, stdout io.Writer, write bool) error {
	name := "vendor review"
	if write {
		name = "vendor import"
	}
	fs := newFlagSet(name, "<submission>...", "See tpm2-verifier vendor -h.")
	vendors := fs.String("store", defaultStore, "vendor data directory to update")
	var accept, include stringList
	fs.Var(&accept, "accept", "SHA-256 of a certificate approved by you (repeatable): a root\nafter comparing it with the vendor, or a CA flagged as pending")
	fs.Var(&include, "include", "debug bundles: SHA-256 of a CA from the TPM to treat as public\n(a vendor CA in NV that is published nowhere; repeatable)")
	noFetch := fs.Bool("no-fetch", false, "do not download certificates again (nothing is added automatically)")
	anonOnly := fs.Bool("anon-only", false, "refuse full debug bundles (for public submissions, e.g. in CI)")
	format := fs.String("format", "text", "output: text, markdown (e.g. for a CI job summary) or json")
	var fixture *string
	if write {
		fixture = fs.String("fixture", "", "copy full debug bundles into this directory as test fixtures\n(only with the contributor's consent: they contain the EK)")
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 || write && len(pos) != 1 {
		fs.Usage()
		return exitError(2)
	}
	if *format != "text" && *format != "markdown" && *format != "json" {
		return fmt.Errorf("invalid -format %q", *format)
	}

	var f verify.CertFetcher
	if !*noFetch {
		f = fetch.New(fetch.WithCacheDir("")) // always from the network
	}
	ctx := context.Background()
	opts := vendorimport.Options{Vendors: *vendors, Fetcher: f, Accept: accept}
	failed := false
	var reports []any
	for _, path := range pos {
		st, err := store.LoadDir(*vendors)
		if err != nil {
			return fmt.Errorf("vendor directory %s: %w", *vendors, err)
		}
		sub, err := vendorimport.Load(ctx, path, st, f, include)
		if err != nil {
			return err
		}
		if *anonOnly && sub.Kind != vendorimport.KindAnon {
			return fmt.Errorf("%s is a full debug bundle; it contains the EK certificate, which identifies the TPM. Submit tpm2-verifier debug-anon output instead", path)
		}
		plan, err := vendorimport.Review(ctx, sub, opts)
		if err != nil {
			return err
		}
		failed = failed || plan.HasErrors()
		var changed []string
		if write {
			if plan.HasErrors() {
				printPlan(stdout, plan, *format, nil)
				return fmt.Errorf("not imported: the review found errors")
			}
			if changed, err = plan.Apply(opts); err != nil {
				return err
			}
			if *fixture != "" && sub.Bundle != nil {
				dst := filepath.Join(*fixture, fmt.Sprintf("%s-%s.tar.gz", plan.VendorID, sanitizeName(sub.Info.TPM.FirmwareVersion)))
				data, err := os.ReadFile(path)
				if err == nil {
					err = os.WriteFile(dst, data, 0o644)
				}
				if err != nil {
					return err
				}
				changed = append(changed, dst)
			}
		}
		if *format == "json" {
			reports = append(reports, map[string]any{"submission": path, "kind": sub.Kind, "plan": plan, "changed": changed})
			continue
		}
		printPlan(stdout, plan, *format, changed)
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	}
	if failed {
		return exitError(1)
	}
	return nil
}

func printPlan(w io.Writer, p *vendorimport.Plan, format string, changed []string) {
	sub := p.Submission
	md := format == "markdown"
	if md {
		fmt.Fprintf(w, "### %s\n\n```\n", filepath.Base(sub.Path))
	}
	t := sub.Info.TPM
	fmt.Fprintf(w, "Submission: %s (%s)\n", sub.Path, sub.Kind)
	fmt.Fprintf(w, "TPM:        %s (%s), firmware %s\n", t.Manufacturer, t.VendorString, t.FirmwareVersion)
	state := "existing"
	if p.NewVendor {
		state = "NEW"
	}
	fmt.Fprintf(w, "Vendor:     %s, %s (%s)\n", p.VendorID, p.VendorName, state)

	if len(p.Certificates) == 0 {
		fmt.Fprintf(w, "\nCertificates: nothing new\n")
	} else {
		fmt.Fprintf(w, "\nCertificates:\n")
	}
	for _, c := range p.Certificates {
		mark := "+"
		if !c.Accepted {
			mark = "?"
		}
		fmt.Fprintf(w, "  %s %s\n      %s\n      sha256 %s\n", mark, c.File, c.Subject, c.SHA256)
		if c.URL != "" {
			dl := "not checked"
			if c.Downloaded {
				dl = "downloaded again, identical"
			}
			fmt.Fprintf(w, "      %s (%s)\n", c.URL, dl)
		}
		if !c.Accepted {
			fmt.Fprintf(w, "      pending: %s\n", c.Pending)
		}
	}
	var meta []string
	for _, x := range [][2]any{{"manufacturer_ids", p.ManufacturerIDs}, {"chain_nv_indices", p.ChainNVIndices}, {"domains", p.Domains}} {
		if v := x[1].([]string); len(v) > 0 {
			meta = append(meta, fmt.Sprintf("+ %s: %s", x[0], strings.Join(v, ", ")))
		}
	}
	if p.NewObservation {
		meta = append(meta, "+ observation: firmware "+p.Observation.Firmware)
	} else {
		meta = append(meta, "  observation already recorded")
	}
	fmt.Fprintf(w, "\nvendor.yaml / observations:\n  %s\n", strings.Join(meta, "\n  "))

	if len(p.Findings) > 0 {
		fmt.Fprintf(w, "\nFindings:\n")
	}
	for _, f := range p.Findings {
		fmt.Fprintf(w, "  %-7s %s\n", f.Severity, f.Message)
	}
	switch {
	case changed != nil:
		fmt.Fprintf(w, "\nWritten:\n  %s\nReview the result with git diff.\n", strings.Join(changed, "\n  "))
	case p.HasErrors():
		fmt.Fprintf(w, "\nResult: ERRORS, would not be imported\n")
	case !p.Changes():
		fmt.Fprintf(w, "\nResult: nothing to import\n")
	default:
		fmt.Fprintf(w, "\nResult: ready to import (%d certificates", len(p.Accepted()))
		if n := len(p.Certificates) - len(p.Accepted()); n > 0 {
			fmt.Fprintf(w, ", %d pending approval", n)
		}
		fmt.Fprintf(w, ")\n")
	}
	if md {
		fmt.Fprintf(w, "```\n\n")
	} else {
		fmt.Fprintln(w)
	}
}
