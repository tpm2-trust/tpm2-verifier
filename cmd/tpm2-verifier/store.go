package main

import (
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tpm2-trust/tpm2-verifier/store"
)

func runStore(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return storeUsage()
	}
	switch args[0] {
	case "list":
		return storeList(args[1:], stdout)
	case "show":
		return storeShow(args[1:], stdout)
	case "export":
		return storeExport(args[1:], stdout)
	case "-h", "--help", "help":
		storeUsage()
		return nil
	}
	return storeUsage()
}

func storeUsage() error {
	dir, _ := store.OverlayDir()
	fmt.Fprintf(os.Stderr, `Usage: tpm2-verifier store <subcommand> [flags]

Subcommands:
  list                 list vendors
  show <vendor>        show a vendor's metadata, certificates and notes
  export [vendor...]   write the store certificates to files (for openssl)

The embedded store can be extended with an overlay directory using the same
layout (<vendor>/vendor.yaml, roots/, intermediates/): %s
`, dir)
	return exitError(2)
}

func storeList(args []string, stdout io.Writer) error {
	fs := newFlagSet("store list", "", "Lists the vendors of the store.")
	overlay := fs.String("store", "", "additional vendor store directory")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%-12s %-14s %5s %13s  %s\n", "VENDOR", "MANUFACTURER", "ROOTS", "INTERMEDIATES", "NAME")
	for _, v := range st.Vendors() {
		fmt.Fprintf(stdout, "%-12s %-14s %5d %13d  %s\n", v.ID, strings.Join(v.ManufacturerIDs, ","), len(v.Roots()), len(v.Intermediates()), v.Name)
	}
	return nil
}

func storeShow(args []string, stdout io.Writer) error {
	fs := newFlagSet("store show", "<vendor>", "Shows one vendor.")
	overlay := fs.String("store", "", "additional vendor store directory")
	readme := fs.Bool("readme", false, "also print the vendor README")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return exitError(2)
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	v := st.Vendor(pos[0])
	if v == nil {
		if v = st.VendorForManufacturer(pos[0]); v == nil {
			return fmt.Errorf("unknown vendor %q", pos[0])
		}
	}
	fmt.Fprintf(stdout, "Vendor:            %s (%s)\n", v.Name, v.ID)
	fmt.Fprintf(stdout, "Manufacturer IDs:  %s\n", strings.Join(v.ManufacturerIDs, ", "))
	if len(v.ChainNVIndices) > 0 {
		fmt.Fprintf(stdout, "Chain NV indices:  %v\n", v.ChainNVIndices)
	}
	if len(v.AcceptedCriticalExtensions) > 0 {
		fmt.Fprintf(stdout, "Accepted critical: %s\n", strings.Join(v.AcceptedCriticalExtensions, ", "))
	}
	if v.Description != "" {
		fmt.Fprintf(stdout, "Description:       %s\n", v.Description)
	}
	for _, e := range v.Certificates {
		fmt.Fprintf(stdout, "\n  [%s] %s\n", e.Role, e.File)
		fmt.Fprintf(stdout, "    subject:   %s\n", e.Cert.SubjectString())
		fmt.Fprintf(stdout, "    issuer:    %s\n", e.Cert.IssuerString())
		fmt.Fprintf(stdout, "    sha256:    %s\n", e.Cert.Fingerprint)
		fmt.Fprintf(stdout, "    valid:     %s .. %s\n", e.Cert.NotBefore.Format("2006-01-02"), e.Cert.NotAfter.Format("2006-01-02"))
		fmt.Fprintf(stdout, "    source:    %s (retrieved %s)\n", e.Source, e.Retrieved)
		if e.Origin != "embedded" {
			fmt.Fprintf(stdout, "    origin:    %s\n", e.Origin)
		}
	}
	if *readme && v.Readme != "" {
		fmt.Fprintf(stdout, "\n%s", v.Readme)
	}
	return nil
}

func storeExport(args []string, stdout io.Writer) error {
	fs := newFlagSet("store export", "[vendor...]",
		"Writes the store certificates to <dir>/<vendor>/{roots,intermediates}/,\n"+
			"e.g. to use them with openssl verify. Without arguments all vendors are exported.")
	overlay := fs.String("store", "", "additional vendor store directory")
	outDir := fs.String("o", "vendors-export", "output directory")
	withPEM := fs.Bool("pem", false, "also write PEM files")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	st, err := loadStore(*overlay)
	if err != nil {
		return err
	}
	vendors := st.Vendors()
	if len(pos) > 0 {
		vendors = nil
		for _, id := range pos {
			v := st.Vendor(id)
			if v == nil {
				return fmt.Errorf("unknown vendor %q", id)
			}
			vendors = append(vendors, v)
		}
	}
	for _, v := range vendors {
		for _, e := range v.Certificates {
			p := filepath.Join(*outDir, v.ID, filepath.FromSlash(e.File))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, e.Cert.Raw, 0o644); err != nil {
				return err
			}
			fmt.Fprintln(stdout, p)
			if *withPEM {
				pp := strings.TrimSuffix(p, filepath.Ext(p)) + ".pem"
				if err := os.WriteFile(pp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.Cert.Raw}), 0o644); err != nil {
					return err
				}
				fmt.Fprintln(stdout, pp)
			}
		}
	}
	return nil
}
