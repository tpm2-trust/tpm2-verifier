package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tpm2-trust/tpm2-verifier/bundle"
	"github.com/tpm2-trust/tpm2-verifier/possession"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

func addTPMFlag(fs *flag.FlagSet) *string {
	return fs.String("tpm", "", "TPM to use: device:/dev/tpmrm0, swtpm:host=..,port=.., swtpm:path=.., tbs,\n"+
		"bundle:<file> (replay a debug bundle)\n"+
		"(default: $TPM2TOOLS_TCTI, else /dev/tpmrm0 or /dev/tpm0 on Linux, TBS on Windows)")
}

// openTPM opens a TPM by spec; "bundle:<file>" replays a debug bundle.
func openTPM(spec string) (*tpm.TPM, error) {
	if p, ok := strings.CutPrefix(spec, "bundle:"); ok {
		b, err := bundle.Load(p)
		if err != nil {
			return nil, err
		}
		return tpm.New(b.Fake()), nil
	}
	return tpm.Open(spec)
}

func scanTPM(ctx context.Context, spec string) (*tpm.Scan, error) {
	t, err := openTPM(spec)
	if err != nil {
		if h := tpm.PermissionHint(err); h != "" {
			return nil, fmt.Errorf("%w\n  hint: %s", err, h)
		}
		return nil, err
	}
	defer t.Close()
	s, err := t.Scan(ctx)
	if err != nil {
		if h := tpm.PermissionHint(err); h != "" {
			return nil, fmt.Errorf("%w\n  hint: %s", err, h)
		}
	}
	return s, err
}

// ekResult is the verification of one EK certificate index.
type ekResult struct {
	Index  string         `json:"index"`
	Label  string         `json:"label"`
	Report *verify.Report `json:"report"`
	// Possession is the proof of EK possession (-prove).
	Possession *possession.Result `json:"possession,omitempty"`

	index uint32
}

// verifyScan verifies every EK certificate found in the scan, using all
// certificates from the chain indices as intermediates.
func verifyScan(ctx context.Context, s *tpm.Scan, st *store.Store, opts []verify.Option) ([]ekResult, error) {
	var chainIdx []uint32
	if v := st.VendorForManufacturer(s.Info.Manufacturer); v != nil {
		for _, i := range v.ChainNVIndices {
			chainIdx = append(chainIdx, uint32(i))
		}
	}
	intermediates := s.ChainCertificates()
	for _, i := range chainIdx {
		if i < tpm.ChainRangeFirst || i > tpm.ChainRangeLast {
			intermediates = append(intermediates, s.ChainCertificates(i)...)
		}
	}
	v := verify.New(st, opts...)
	var out []ekResult
	for _, e := range s.EKCertificates() {
		rep, err := v.Verify(ctx, e.Certificates[0], append(intermediates, e.Certificates[1:]...))
		if err != nil {
			return nil, err
		}
		out = append(out, ekResult{Index: tpm.HexIndex(e.Index), Label: e.Label.String(), Report: rep, index: e.Index})
	}
	return out, nil
}

func runInfo(args []string, stdout io.Writer) error {
	fs := newFlagSet("info", "",
		"Shows in one go: the TPM vendor and firmware, all NV indices with the\n"+
			"certificates found in the TCG range, and the verification of every EK\n"+
			"certificate against the vendor store, including CRL checks.\n\n"+
			"Exit status: 0 all EK certificates trusted, 1 otherwise or none found, 2 error.")
	spec := addTPMFlag(fs)
	asJSON := fs.Bool("json", false, "JSON output")
	verbose := fs.Bool("v", false, "show fingerprints, quirks and revocation details")
	overlay := fs.String("store", "", "additional vendor store directory")
	revMode := fs.String("revocation", "best-effort", "revocation mode: off, best-effort, require")
	crlf := addCRLFlags(fs)
	pf := addProveFlags(fs)
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
	opts, err := revocationOpts(*revMode, crlf)
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
	if *pf.prove {
		if err := proveResults(ctx, *spec, s, results, pf); err != nil {
			return err
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(infoJSON(s, st, results)); err != nil {
			return err
		}
	} else {
		printInfo(stdout, s, st, results, *verbose)
	}
	return resultsExit(results)
}

// resultsExit returns exit status 1 unless every EK certificate is trusted
// and, if a proof was made, proven.
func resultsExit(results []ekResult) error {
	if len(results) == 0 {
		return exitError(1)
	}
	for _, r := range results {
		if r.Report.Status != verify.StatusTrusted || r.Possession != nil && r.Possession.Status != possession.StatusProven {
			return exitError(1)
		}
	}
	return nil
}

func revocationOpts(mode string, crlf crlFlags) ([]verify.Option, error) {
	var opts []verify.Option
	switch mode {
	case "off":
		opts = append(opts, verify.WithRevocation(verify.RevocationOff))
	case "best-effort":
	case "require":
		opts = append(opts, verify.WithRevocation(verify.RevocationRequire))
	default:
		return nil, fmt.Errorf("invalid -revocation %q", mode)
	}
	if f := crlf.fetcher(); f != nil {
		opts = append(opts, verify.WithCRLFetcher(f), verify.WithAIAFetcher(f))
	}
	return opts, nil
}

func printInfo(w io.Writer, s *tpm.Scan, st *store.Store, results []ekResult, verbose bool) {
	i := s.Info
	vendor := "not in vendor store"
	if v := st.VendorForManufacturer(i.Manufacturer); v != nil {
		vendor = fmt.Sprintf("%s, vendor store: %s", v.Name, v.ID)
	}
	fmt.Fprintf(w, "TPM\n")
	fmt.Fprintf(w, "  Manufacturer:   %s (%s)\n", i.Manufacturer, vendor)
	if i.VendorString != "" {
		fmt.Fprintf(w, "  Vendor string:  %s\n", i.VendorString)
	}
	fmt.Fprintf(w, "  Firmware:       %s\n", i.FirmwareVersion)
	fmt.Fprintf(w, "  Specification:  TPM %s, revision %s", i.Family, i.SpecRevision)
	if i.SpecDate != "" {
		fmt.Fprintf(w, " (%s)", i.SpecDate)
	}
	fmt.Fprintf(w, "\n\nNV indices\n")
	if len(s.Entries) == 0 {
		fmt.Fprintf(w, "  none defined\n")
	}
	for _, e := range s.Entries {
		size := "-"
		attrs := ""
		if e.Public != nil {
			size = fmt.Sprint(e.Public.Size)
			attrs = e.Public.Attributes.String()
		}
		fmt.Fprintf(w, "  %s  %5s bytes  %s\n", tpm.HexIndex(e.Index), size, e.Label)
		if verbose && attrs != "" {
			fmt.Fprintf(w, "      attributes: %s\n", attrs)
		}
		for _, c := range e.Certificates {
			fmt.Fprintf(w, "      cert: %s  (issuer: %s)\n", c.SubjectString(), c.IssuerString())
		}
		if e.ReadError != "" {
			fmt.Fprintf(w, "      not read: %s\n", strings.TrimPrefix(e.ReadError, "NV "+tpm.HexIndex(e.Index)+": "))
		}
		if e.ParseError != "" {
			fmt.Fprintf(w, "      parse error: %s\n", e.ParseError)
		}
		if !tpm.IsTCG(e.Index) {
			fmt.Fprintf(w, "      (outside the TCG range, content not read)\n")
		}
	}
	fmt.Fprintln(w)
	if len(results) == 0 {
		fmt.Fprintf(w, "No EK certificate found in NV.\n")
		if i.Manufacturer == "INTC" {
			fmt.Fprintf(w, "Older Intel PTT generations do not store it; tpm2_getekcertificate can download it from Intel.\n")
		}
		return
	}
	trusted := true
	for _, r := range results {
		printReport(w, "EK certificate "+r.Index+" ("+r.Label+")", r.Report, verbose)
		printPossession(w, r)
		fmt.Fprintln(w)
		trusted = trusted && r.Report.Status == verify.StatusTrusted
	}
	if !trusted {
		fmt.Fprintf(w, "To analyze this TPM elsewhere or report an unknown vendor: tpm2-ek debug\n")
	}
}

type infoEntryJSON struct {
	*tpm.Entry
	Index        string   `json:"index"`
	Attributes   string   `json:"attributes,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
}

func infoJSON(s *tpm.Scan, st *store.Store, results []ekResult) any {
	vendor := ""
	if v := st.VendorForManufacturer(s.Info.Manufacturer); v != nil {
		vendor = v.ID
	}
	var nv []infoEntryJSON
	for _, e := range s.Entries {
		j := infoEntryJSON{Entry: e, Index: tpm.HexIndex(e.Index)}
		if e.Public != nil {
			j.Attributes = e.Public.Attributes.String()
		}
		for _, c := range e.Certificates {
			j.Certificates = append(j.Certificates, c.SubjectString())
		}
		nv = append(nv, j)
	}
	return map[string]any{"tpm": s.Info, "vendor": vendor, "nv": nv, "ek": results}
}

func runExport(args []string, stdout io.Writer) error {
	fs := newFlagSet("export", "",
		"Writes everything needed to verify the TPM without this tool:\n"+
			"  ek-<index>.der            EK certificates\n"+
			"  chain-<n>.der             intermediates from the chain NV indices\n"+
			"  nv/<index>.bin            raw content of every readable TCG NV index\n"+
			"  store/<vendor>/...        the vendor's root and static intermediates\n"+
			"and prints the matching openssl verify commands.")
	spec := addTPMFlag(fs)
	outDir := fs.String("o", "tpm-export", "output directory")
	withPEM := fs.Bool("pem", false, "also write PEM files")
	overlay := fs.String("store", "", "additional vendor store directory")
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
	s, err := scanTPM(context.Background(), *spec)
	if err != nil {
		return err
	}
	w := &exportWriter{dir: *outDir, pem: *withPEM, out: stdout}
	for _, e := range s.Entries {
		if e.Data != nil {
			w.write(filepath.Join("nv", tpm.HexIndex(e.Index)+".bin"), e.Data, false)
		}
	}
	var ekFiles, chainFiles, storeRoots, storeInts []string
	for _, e := range s.EKCertificates() {
		ekFiles = append(ekFiles, w.write("ek-"+tpm.HexIndex(e.Index)+".der", e.Certificates[0].Raw, true))
	}
	for n, c := range s.ChainCertificates() {
		chainFiles = append(chainFiles, w.write(fmt.Sprintf("chain-%d.der", n+1), c.Raw, true))
	}
	if v := st.VendorForManufacturer(s.Info.Manufacturer); v != nil {
		for _, e := range v.Certificates {
			p := w.write(filepath.Join("store", v.ID, filepath.FromSlash(e.File)), e.Cert.Raw, true)
			if e.Role == store.RoleRoot {
				storeRoots = append(storeRoots, p)
			} else {
				storeInts = append(storeInts, p)
			}
		}
	}
	if w.err != nil {
		return w.err
	}
	if len(ekFiles) == 0 {
		fmt.Fprintln(stdout, "\nNo EK certificate found in NV.")
		return exitError(1)
	}
	if len(storeRoots) == 0 {
		fmt.Fprintf(stdout, "\nManufacturer %s is not in the vendor store; no trust anchor exported.\n", s.Info.Manufacturer)
		return nil
	}
	fmt.Fprintln(stdout, "\nVerify with openssl:")
	for _, ek := range ekFiles {
		cmd := []string{"openssl verify -show_chain"}
		for _, r := range storeRoots {
			cmd = append(cmd, "-trusted "+r)
		}
		for _, f := range append(storeInts, chainFiles...) {
			cmd = append(cmd, "-untrusted "+f)
		}
		cmd = append(cmd, ek)
		fmt.Fprintf(stdout, "  %s\n", strings.Join(cmd, " \\\n    "))
	}
	return nil
}

type exportWriter struct {
	dir string
	pem bool
	out io.Writer
	err error
}

func (w *exportWriter) write(rel string, data []byte, cert bool) string {
	p := filepath.Join(w.dir, rel)
	if w.err != nil {
		return p
	}
	if w.err = os.MkdirAll(filepath.Dir(p), 0o755); w.err != nil {
		return p
	}
	if w.err = os.WriteFile(p, data, 0o644); w.err != nil {
		return p
	}
	fmt.Fprintln(w.out, p)
	if cert && w.pem {
		pp := strings.TrimSuffix(p, ".der") + ".pem"
		w.err = os.WriteFile(pp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}), 0o644)
	}
	return p
}
