package tpm_test

import (
	"context"
	"fmt"

	"github.com/tpm2-trust/tpm2-verifier/fetch"
	"github.com/tpm2-trust/tpm2-verifier/possession"
	"github.com/tpm2-trust/tpm2-verifier/store"
	"github.com/tpm2-trust/tpm2-verifier/tpm"
	"github.com/tpm2-trust/tpm2-verifier/verify"
)

// Verify every EK certificate of the local TPM, with CRLs fetched and cached,
// and prove that the TPM holds the EK.
func Example() {
	ctx := context.Background()
	t, err := tpm.Open("") // /dev/tpmrm0, TBS, or a TCTI spec like "swtpm:host=localhost,port=2321"
	if err != nil {
		panic(err)
	}
	defer t.Close()
	scan, err := t.Scan(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println(scan.Info.Manufacturer)

	st, err := store.Default()
	if err != nil {
		panic(err)
	}
	cacheDir, _ := fetch.DefaultCacheDir()
	v := verify.New(st, verify.WithCRLFetcher(fetch.New(fetch.WithCacheDir(cacheDir))))

	for _, ek := range scan.EKCertificates() {
		rep, err := v.Verify(ctx, ek.Certificates[0], scan.ChainCertificates())
		if err != nil {
			panic(err)
		}
		fmt.Println(tpm.HexIndex(ek.Index), rep.Status, rep.Vendor)
		for _, l := range rep.Chain {
			fmt.Println(" ", l.Subject, l.Source, l.Revocation.Status, l.Revocation.Source)
		}
		// Prove that this TPM holds the EK (pass the EK template and nonce
		// index contents for the low range if the TPM has them).
		if d, ok := t.Backend().(*tpm.Device); ok {
			res := possession.Prove(d.Transport(), ek.Index, ek.Certificates[0].PublicKey, nil, nil, possession.Options{})
			fmt.Println(" ", res.Status, res.Detail)
		}
	}
}
