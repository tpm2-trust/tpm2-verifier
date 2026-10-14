package main

import (
	"context"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mrwiora/tpm2-verifier/certparse"
	"github.com/mrwiora/tpm2-verifier/store"
	"github.com/mrwiora/tpm2-verifier/verify"
)

func runVerify(args []string, stdout io.Writer) error {
	fs := newFlagSet("verify", "[<ek-cert> [intermediates...]]",
		"Builds the chain from the EK certificate to a trust anchor of the vendor store\n"+
			"and validates it, including CRL revocation checks. CRLs are fetched from the\n"+
			"distribution points and cached unless -no-fetch or -offline is given.\n\n"+
			"Without files, the EK certificates and chain are read from the TPM (-tpm).\n"+
			"Intermediates are certificate files (DER, PEM or concatenated DER, e.g. the\n"+
			"raw content of NV 0x01C00100). If the first file holds several certificates,\n"+
			"the first one is the leaf and the others are intermediates.\n\n"+
			"Exit status: 0 trusted, 1 not trusted, 2 error.")
	spec := addTPMFlag(fs)
	var crlFiles, accept stringList
	fs.Var(&crlFiles, "crl", "CRL file for revocation checks (repeatable)")
	fs.Var(&accept, "accept-critical", "accept this critical extension OID on any certificate (repeatable)")
	revMode := fs.String("revocation", "best-effort", "revocation mode: off, best-effort, require")
	at := fs.String("time", "", "validate at this time (RFC 3339) instead of now")
	asJSON := fs.Bool("json", false, "JSON output")
	verbose := fs.Bool("v", false, "show fingerprints, quirks and revocation details")
	overlay := fs.String("store", "", "additional vendor store directory")
	crlf := addCRLFlags(fs)
	pf := addProveFlags(fs)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if *pf.prove && len(pos) > 0 {
		return fmt.Errorf("-prove needs the TPM; it cannot be used with certificate files")
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	opts, err := revocationOpts(*revMode, crlf)
	if err != nil {
		return err
	}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("invalid -time: %w", err)
		}
		opts = append(opts, verify.WithTime(t))
	}
	for _, f := range crlFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		crl, err := certparse.ParseCRL(data)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		opts = append(opts, verify.WithCRLs(crl))
	}
	for _, s := range accept {
		oid, err := parseOID(s)
		if err != nil {
			return err
		}
		opts = append(opts, verify.WithAcceptedCriticalExtensions(oid))
	}

	if len(pos) == 0 {
		return verifyFromTPM(*spec, st, opts, pf, *asJSON, *verbose, stdout)
	}

	var certs []*certparse.Certificate
	for _, f := range pos {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		cs, err := certparse.ParseAll(data)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if len(cs) == 0 {
			return fmt.Errorf("%s: no certificates", f)
		}
		certs = append(certs, cs...)
	}

	rep, err := verify.New(st, opts...).Verify(context.Background(), certs[0], certs[1:])
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printReport(stdout, pos[0], rep, *verbose)
	}
	if rep.Status != verify.StatusTrusted {
		return exitError(1)
	}
	return nil
}

func printReport(w io.Writer, name string, r *verify.Report, verbose bool) {
	defer printAIA(w, r, verbose)
	fmt.Fprintf(w, "%s: %s", name, strings.ToUpper(string(r.Status)))
	if r.Vendor != "" {
		fmt.Fprintf(w, " (vendor %s)", r.Vendor)
	}
	fmt.Fprintln(w)
	if r.TPM != nil {
		fmt.Fprintf(w, "TPM: manufacturer %s, model %q, version %s\n", r.TPM.Manufacturer, r.TPM.Model, r.TPM.Version)
	}
	fmt.Fprintln(w, "Chain:")
	for i, l := range r.Chain {
		src := string(l.Source)
		if l.StorePath != "" {
			src = "store:" + l.StorePath
		}
		if l.Anchor {
			src += ", trust anchor"
		}
		fmt.Fprintf(w, "  depth=%d: %s [%s]", i, l.Subject, src)
		if l.Revocation.Status != verify.RevocationNotChecked {
			fmt.Fprintf(w, " revocation=%s", l.Revocation.Status)
		}
		fmt.Fprintln(w)
		if verbose {
			fmt.Fprintf(w, "           sha256 %s, valid %s .. %s\n", l.Fingerprint, l.NotBefore.Format(time.DateOnly), l.NotAfter.Format(time.DateOnly))
			for _, q := range l.Quirks {
				fmt.Fprintf(w, "           quirk: %s: %s\n", q.Code, q.Detail)
			}
			printRevocation(w, l.Revocation)
		}
		for _, p := range l.Problems {
			fmt.Fprintf(w, "           problem: %s\n", p)
		}
	}
	for _, p := range r.Problems {
		fmt.Fprintf(w, "Problem: %s\n", p)
	}
	for _, h := range r.Hints {
		fmt.Fprintf(w, "Hint: %s\n", h)
	}
}

func verifyFromTPM(spec string, st *store.Store, opts []verify.Option, pf proveFlags, asJSON, verbose bool, stdout io.Writer) error {
	ctx := context.Background()
	s, err := scanTPM(ctx, spec)
	if err != nil {
		return err
	}
	results, err := verifyScan(ctx, s, st, opts)
	if err != nil {
		return err
	}
	if *pf.prove {
		if err := proveResults(ctx, spec, s, results, pf); err != nil {
			return err
		}
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return err
		}
	} else {
		if len(results) == 0 {
			fmt.Fprintln(stdout, "No EK certificate found in the TPM.")
		}
		for i, r := range results {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			printReport(stdout, "TPM "+r.Index+" ("+r.Label+")", r.Report, verbose)
			printPossession(stdout, r)
		}
	}
	return resultsExit(results)
}

func printAIA(w io.Writer, r *verify.Report, verbose bool) {
	for _, a := range r.AIA {
		switch {
		case a.Error != "":
			fmt.Fprintf(w, "AIA: %s: %s\n", a.URL, a.Error)
		case verbose:
			fmt.Fprintf(w, "AIA: %s (%s): %s\n", a.URL, a.Origin, strings.Join(a.Certificates, "; "))
		}
	}
}

func printRevocation(w io.Writer, rv verify.Revocation) {
	if rv.Detail == "" {
		return
	}
	fmt.Fprintf(w, "           revocation: %s\n", rv.Detail)
	if rv.CRLIssuer != "" {
		fmt.Fprintf(w, "           CRL #%s by %s, signature verified with %s\n", rv.CRLNumber, rv.CRLIssuer, short(rv.SignedBy))
	}
	if rv.Source != "" {
		src := rv.Source
		if rv.Origin != "" {
			src += " (" + rv.Origin + ")"
		}
		fmt.Fprintf(w, "           CRL source: %s\n", src)
	}
	if rv.Warning != "" {
		fmt.Fprintf(w, "           warning: %s\n", rv.Warning)
	}
}

func short(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "..."
	}
	return fp
}

func loadStore(overlay string) (*store.Store, error) {
	st, err := store.Default()
	if err != nil {
		return nil, err
	}
	if overlay != "" {
		if err := st.AddFS(os.DirFS(overlay), overlay); err != nil {
			return nil, err
		}
	}
	return st, nil
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
	return oid, nil
}
