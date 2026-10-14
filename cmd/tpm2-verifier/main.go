// Command tpm2-verifier inspects and verifies TPM endorsement key certificates and
// their vendor certificate chains.
//
// Some TPM vendors issue certificates with negative serial numbers, which Go
// rejects by default since 1.23; this binary accepts them.
//
//go:debug x509negativeserial=1
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

var version = "" // set with -ldflags "-X main.version=..."

// exitError carries an exit code without printing anything further.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

type command struct {
	name    string
	summary string
	run     func(args []string, stdout io.Writer) error
}

func commands() []command {
	return []command{
		{"info", "show TPM vendor, NV certificates and EK verification in one go", runInfo},
		{"export", "export EK certificates, chain and vendor CAs from the TPM to files", runExport},
		{"debug", "write a debug bundle of the TPM (for unknown vendors and bug reports)", runDebug},
		{"debug-anon", "collect what is needed to add the TPM vendor, without identifying data", runDebugAnon},
		{"inspect", "show details of certificates and CRLs (DER, PEM or concatenated DER)", runInspect},
		{"split", "split a concatenated DER chain (e.g. NV 0x01C00100) into files", runSplit},
		{"verify", "verify EK certificates (from the TPM or files) against the vendor store", runVerify},
		{"store", "list, show and export the vendor trust store", runStore},
		{"vendor", "maintainers: review and import submissions into the vendor directory", runVendor},
		{"cache", "list or clear the CRL and certificate cache", runCache},
		{"version", "print the version of the program and the vendor data", runVersion},
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: tpm2-verifier <command> [flags] [args]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(w, "\nRun 'tpm2-verifier <command> -h' for the flags of a command.\n")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	warnOut = stderr
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	for _, c := range commands() {
		if c.name != args[0] {
			continue
		}
		err := c.run(args[1:], stdout)
		var code exitError
		switch {
		case err == nil:
			return 0
		case errors.As(err, &code):
			return int(code)
		case errors.Is(err, flag.ErrHelp):
			return 0
		default:
			fmt.Fprintf(stderr, "tpm2-verifier %s: %v\n", c.name, err)
			return 2
		}
	}
	fmt.Fprintf(stderr, "tpm2-verifier: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func runVersion(args []string, stdout io.Writer) error {
	fs := newFlagSet("version", "", "Prints the version of tpm2-verifier and of the vendor data.")
	dir := fs.String("store", defaultStore, "vendor data directory")
	if pos, err := parseInterleaved(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		fs.Usage()
		return exitError(2)
	}
	fmt.Fprintln(stdout, versionString())
	fmt.Fprintf(stdout, "vendor data %s: %s\n", *dir, vendorDataVersion(*dir))
	return nil
}

func versionString() string {
	v := version
	if v == "" {
		v = "(devel)"
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
			v = bi.Main.Version
		}
	}
	return "tpm2-verifier " + v
}

// newFlagSet returns a flag set that prints its usage to stderr.
func newFlagSet(name, args, desc string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: tpm2-verifier %s [flags] %s\n\n%s\n\nFlags:\n", name, args, desc)
		fs.PrintDefaults()
	}
	return fs
}

// parseInterleaved parses flags that may appear before, between or after
// positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
