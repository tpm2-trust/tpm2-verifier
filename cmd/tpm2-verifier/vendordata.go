package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tpm2-trust/tpm2-verifier/manifest"
	"github.com/tpm2-trust/tpm2-verifier/store"
)

// defaultStore is the vendor data directory, relative to the working
// directory.
const defaultStore = "vendors"

// installedStore is where the packages install the vendor data.
const installedStore = "/usr/share/tpm2-verifier/vendors"

// warnOut receives warnings; run sets it to its stderr.
var warnOut io.Writer = os.Stderr

type storeFlags struct {
	dir           *string
	allowUnsigned *bool
	// result is set by load.
	result *manifest.Result
}

func addStoreFlags(fl *flag.FlagSet) *storeFlags {
	return &storeFlags{
		dir: fl.String("store", defaultStore, "vendor data directory (with MANIFEST, MANIFEST.sig, <vendor>/vendor.yaml)"),
		allowUnsigned: fl.Bool("allow-unsigned", false, "use vendor data that is not signed by a trusted key\n"+
			"(e.g. a working copy; the MANIFEST hashes are still checked, if present)"),
	}
}

// load opens the vendor data, verified against its signed manifest.
func (f *storeFlags) load() (*store.Store, error) {
	st, res, err := store.Open(*f.dir, store.OpenOptions{AllowUnsigned: *f.allowUnsigned})
	if errors.Is(err, fs.ErrNotExist) && res == nil {
		return nil, missingStoreError(*f.dir)
	}
	var ue *store.UntrustedError
	if errors.As(err, &ue) {
		return nil, fmt.Errorf("%w\nCheck where the data comes from; pass -allow-unsigned to use it anyway", err)
	}
	if err != nil {
		return nil, err
	}
	f.result = res
	if !res.Trusted() {
		fmt.Fprintf(warnOut, "warning: vendor data %s is not signed by a trusted key (%s)\n", res.Dir, res.Describe())
	}
	return st, nil
}

func missingStoreError(dir string) error {
	abs, _ := filepath.Abs(dir)
	msg := fmt.Sprintf("no vendor data: %s not found.\nRun tpm2-verifier in the directory that contains vendors/, or pass -store <dir>", abs)
	if runtime.GOOS != "windows" && dir != installedStore {
		if _, err := os.Stat(installedStore); err == nil {
			msg += fmt.Sprintf(" (installed: -store %s)", installedStore)
		}
	}
	return errors.New(msg)
}

// storeVerify checks the vendor data and prints its version and signature.
func storeVerify(args []string, stdout io.Writer) error {
	fl := newFlagSet("store verify", "",
		"Checks the vendor data against its MANIFEST and the signature MANIFEST.sig\n"+
			"against the keys compiled into tpm2-verifier, and prints the data version.\n\n"+
			"Exit status: 0 signed by a trusted key (or -allow-unsigned and consistent),\n"+
			"1 not signed by a trusted key, 2 error.")
	sf := addStoreFlags(fl)
	if pos, err := parseInterleaved(fl, args); err != nil {
		return err
	} else if len(pos) > 0 {
		fl.Usage()
		return exitError(2)
	}
	if _, err := os.Stat(*sf.dir); err != nil {
		return missingStoreError(*sf.dir)
	}
	signers, err := manifest.TrustedSigners()
	if err != nil {
		return err
	}
	res, err := manifest.Verify(*sf.dir, signers)
	if err != nil {
		return err
	}
	if _, err := store.LoadDir(*sf.dir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Vendor data: %s\n", res.Dir)
	fmt.Fprintf(stdout, "  %s\n", res.Describe())
	if !res.Trusted() {
		fmt.Fprintf(stdout, "NOT SIGNED by a trusted key (%d trusted keys built in)\n", len(signers))
		if !*sf.allowUnsigned {
			return exitError(1)
		}
		return nil
	}
	fmt.Fprintln(stdout, "OK")
	return nil
}

// storeManifest writes the MANIFEST of the vendor data.
func storeManifest(args []string, stdout io.Writer) error {
	fl := newFlagSet("store manifest", "",
		"Writes the MANIFEST of the vendor data directory: the SHA-256 of every\n"+
			"file and a version. If the files changed, the version is the date\n"+
			"(2026.10.14, then 2026.10.14.2, ...) and MANIFEST.sig is removed: sign\n"+
			"the new MANIFEST with the command printed.")
	dir := fl.String("store", defaultStore, "vendor data directory")
	version := fl.String("version", "", "set this version (default: unchanged, or the date if files changed)")
	if pos, err := parseInterleaved(fl, args); err != nil {
		return err
	} else if len(pos) > 0 {
		fl.Usage()
		return exitError(2)
	}
	if _, err := os.Stat(*dir); err != nil {
		return missingStoreError(*dir)
	}
	if _, err := store.LoadDir(*dir); err != nil {
		return err
	}
	m, changed, err := manifest.Update(*dir, *version, time.Now())
	if err != nil {
		return err
	}
	mp, sp := filepath.Join(*dir, manifest.File), filepath.Join(*dir, manifest.SigFile)
	if !changed {
		fmt.Fprintf(stdout, "%s is up to date (version %s)\n", mp, m.Version)
		return nil
	}
	if err := os.WriteFile(mp, m.Marshal(), 0o644); err != nil {
		return err
	}
	if err := os.Remove(sp); err == nil {
		fmt.Fprintf(stdout, "removed %s (no longer matches)\n", sp)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s (version %s, %d files)\nSign it with:\n  ssh-keygen -Y sign -f <key> -n %s %s\n", mp, m.Version, len(m.Files), manifest.Namespace, mp)
	return nil
}

// vendorDataVersion describes the vendor data in dir in one line.
func vendorDataVersion(dir string) string {
	if _, err := os.Stat(dir); err != nil {
		return "not found"
	}
	signers, err := manifest.TrustedSigners()
	if err != nil {
		return err.Error()
	}
	res, err := manifest.Verify(dir, signers)
	if err != nil {
		return "INVALID: " + err.Error()
	}
	return res.Describe()
}
