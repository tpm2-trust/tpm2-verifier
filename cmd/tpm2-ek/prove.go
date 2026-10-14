package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/tpm2-trust/tpm2-verifier/possession"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

// proveFlags are the flags for the proof of EK possession.
type proveFlags struct {
	prove *bool
	auth  *string
}

func addProveFlags(fs *flag.FlagSet) proveFlags {
	return proveFlags{
		prove: fs.Bool("prove", false, "prove that this TPM holds the private key of each EK certificate\n(recreates the EK and decrypts a challenge with TPM2_ActivateCredential)"),
		auth:  fs.String("endorsement-auth", "", "endorsement hierarchy authorization for -prove (usually empty;\n\"hex:...\" for binary values)"),
	}
}

func (p proveFlags) authValue() ([]byte, error) {
	if h, ok := strings.CutPrefix(*p.auth, "hex:"); ok {
		return hex.DecodeString(h)
	}
	return []byte(strings.TrimPrefix(*p.auth, "str:")), nil
}

// proveResults runs the proof of possession for every EK result. The TPM is
// opened again; a recorded bundle cannot prove anything.
func proveResults(ctx context.Context, spec string, s *tpm.Scan, results []ekResult, p proveFlags) error {
	auth, err := p.authValue()
	if err != nil {
		return fmt.Errorf("invalid -endorsement-auth: %w", err)
	}
	unsupported := func(detail string) {
		for i := range results {
			results[i].Possession = &possession.Result{Index: results[i].Index, Status: possession.StatusUnsupported, Detail: detail}
		}
	}
	if strings.HasPrefix(spec, "bundle:") {
		unsupported("a recorded bundle cannot prove possession; run tpm2-ek on the device")
		return nil
	}
	t, err := openTPM(spec)
	if err != nil {
		return err
	}
	defer t.Close()
	d, ok := t.Backend().(*tpm.Device)
	if !ok {
		unsupported("the TPM backend cannot run commands")
		return nil
	}
	data := func(index uint32) []byte {
		for _, e := range s.Entries {
			if e.Index == index && e.ReadError == "" {
				return e.Data
			}
		}
		return nil
	}
	for i, r := range results {
		var tmpl, nonce []byte
		if r.index == 0x01C00002 || r.index == 0x01C0000A {
			tmpl, nonce = data(r.index+2), data(r.index+1)
		}
		res := possession.Prove(d.Transport(), r.index, r.Report.Chain[0].Cert.PublicKey, tmpl, nonce, possession.Options{EndorsementAuth: auth})
		results[i].Possession = &res
	}
	return nil
}

// printPossession prints the proof result and the overall verdict.
func printPossession(w io.Writer, r ekResult) {
	p := r.Possession
	if p == nil {
		return
	}
	fmt.Fprintf(w, "Possession: %s", strings.ToUpper(string(p.Status)))
	if p.Template != "" {
		fmt.Fprintf(w, " (%s, %.1fs)", p.Template, p.Duration.Seconds())
	}
	fmt.Fprintf(w, "\n  %s\n", p.Detail)
	trusted := r.Report.Status == verify.StatusTrusted
	switch {
	case trusted && p.Status == possession.StatusProven:
		fmt.Fprintf(w, "Verdict: GENUINE: the certificate chains to vendor %s and this TPM holds its private key\n", r.Report.Vendor)
	case p.Status == possession.StatusFailed:
		fmt.Fprintf(w, "Verdict: NOT GENUINE: this TPM claims the certificate's key but cannot use it\n")
	case p.Status == possession.StatusKeyMismatch:
		fmt.Fprintf(w, "Verdict: NOT PROVEN: the certificate is not for this TPM's EK (or the vendor uses another EK template)\n")
	case p.Status == possession.StatusProven:
		fmt.Fprintf(w, "Verdict: NOT TRUSTED: this TPM holds the certificate's key, but the chain is %s\n", r.Report.Status)
	default:
		fmt.Fprintf(w, "Verdict: NOT PROVEN\n")
	}
}
