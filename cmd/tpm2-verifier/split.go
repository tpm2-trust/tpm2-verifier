package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
)

func runSplit(args []string, stdout io.Writer) error {
	fs := newFlagSet("split", "<chain.der>",
		"Splits concatenated DER certificates, as stored in the TCG EK certificate chain\n"+
			"NV range (Intel: 0x01C00100), into one file per certificate. Trailing NV\n"+
			"padding is ignored.\n\n"+
			"intel-ek-dechainer compatible naming: tpm2-verifier split -p intel-int -s 3 chain.der")
	outDir := fs.String("o", ".", "output directory (created if missing)")
	prefix := fs.String("p", "chain-", "file name prefix")
	start := fs.Int("s", 1, "number of the first certificate")
	withPEM := fs.Bool("pem", false, "also write PEM files")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return exitError(2)
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	ders, err := certparse.SplitDER(data)
	if err != nil {
		var se *certparse.SplitError
		if !errors.As(err, &se) || len(ders) == 0 {
			return err
		}
		fmt.Fprintf(os.Stderr, "warning: %v; writing the %d certificates before it\n", err, len(ders))
	}
	if len(ders) == 0 {
		return fmt.Errorf("no certificates found in %s", pos[0])
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	for i, der := range ders {
		base := filepath.Join(*outDir, fmt.Sprintf("%s%d", *prefix, *start+i))
		subject := "<not a certificate>"
		if c, err := certparse.Parse(der); err == nil {
			subject = c.SubjectString()
		}
		if err := os.WriteFile(base+".der", der, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s.der  %5d bytes  %s\n", base, len(der), subject)
		if *withPEM {
			if err := os.WriteFile(base+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "%s.pem\n", base)
		}
	}
	fmt.Fprintf(stdout, "%d certificates extracted\n", len(ders))
	return nil
}
