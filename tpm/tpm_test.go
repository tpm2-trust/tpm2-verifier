package tpm_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-verifier/internal/swtpmtest"
	"github.com/mrwiora/tpm2-verifier/internal/testpki"
	"github.com/mrwiora/tpm2-verifier/tpm"
)

var ctx = context.Background()

func TestDescribe(t *testing.T) {
	for idx, want := range map[uint32]string{
		0x01C00002: "ek-certificate RSA 2048 (low)",
		0x01C0000A: "ek-certificate ECC NIST P-256 (low)",
		0x01C00016: "ek-certificate ECC NIST P-384 (H-3)",
		0x01C00100: "ek-chain",
		0x01C001FF: "ek-chain",
		0x01C07F01: "ek-policy",
		0x01C08000: "platform-certificate",
		0x01C07000: "tcg-reserved",
		0x01500000: "other",
	} {
		if got := tpm.Describe(idx).String(); got != want {
			t.Errorf("%s: %q, want %q", tpm.HexIndex(idx), got, want)
		}
	}
}

func TestInfoFromProperties(t *testing.T) {
	info := tpm.InfoFromProperties(map[uint32]uint32{
		tpm.PTFamilyIndicator:   0x322E3000, // "2.0\0"
		tpm.PTRevision:          159,
		tpm.PTYear:              2019,
		tpm.PTDayOfYear:         312,
		tpm.PTManufacturer:      0x494E5443, // INTC
		tpm.PTVendorString1:     0x496E7465, // "Inte"
		tpm.PTVendorString1 + 1: 0x6C000000, // "l"
		tpm.PTFirmwareVersion1:  0x00020008,
		tpm.PTFirmwareVersion2:  0x00C80000,
	})
	if info.Manufacturer != "INTC" || info.VendorString != "Intel" || info.Family != "2.0" ||
		info.SpecRevision != "1.59" || info.FirmwareVersion != "2.8.200.0" {
		t.Errorf("%+v", info)
	}
	if got := tpm.InfoFromProperties(map[uint32]uint32{tpm.PTManufacturer: 0x49465800}).Manufacturer; got != "IFX" {
		t.Errorf("IFX: %q", got)
	}
}

func TestAttributesString(t *testing.T) {
	a := tpm.NVOwnerRead | tpm.NVAuthRead | tpm.NVNoDA | tpm.NVWritten
	if got := a.String(); got != "ownerread|authread|no_da|written" {
		t.Errorf("%q", got)
	}
}

func TestScanFake(t *testing.T) {
	pki := testpki.IntelLike(t)
	f := &tpm.Fake{Properties: map[uint32]uint32{tpm.PTManufacturer: 0x494E5443}}
	f.SetCertificate(0x01C00002, append(bytes.Clone(pki.EK.Raw), 0xff, 0xff))
	f.SetCertificate(0x01C00100, pki.DeviceChain())
	f.SetCertificate(0x01C00004, []byte{0x00, 0x01, 0x02}) // template, not parsed
	f.SetCertificate(0x01500001, []byte("owner data"))     // outside TCG range, not read

	s, err := tpm.New(f).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Info.Manufacturer != "INTC" || len(s.Entries) != 4 {
		t.Fatalf("info %+v entries %d", s.Info, len(s.Entries))
	}
	eks := s.EKCertificates()
	if len(eks) != 1 || eks[0].Index != 0x01C00002 || !eks[0].Certificates[0].IsEK {
		t.Fatalf("EK certificates %+v", eks)
	}
	if chain := s.ChainCertificates(); len(chain) != 3 {
		t.Errorf("chain has %d certificates", len(chain))
	}
	if e := s.Entry(0x01500001); e.Data != nil || e.Public == nil {
		t.Errorf("non TCG index: %+v", e)
	}
	if e := s.Entry(0x01C00004); e.Data == nil || e.ParseError != "" {
		t.Errorf("template: %+v", e)
	}
}

// TestSwtpm reads provisioned indices from a real (software) TPM through the
// go-tpm device backend.
func TestSwtpm(t *testing.T) {
	spec := swtpmtest.Start(t)
	tp, err := tpm.Open(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()
	tr := tp.Backend().(*tpm.Device).Transport()

	pki := testpki.IntelLike(t)
	chain := pki.DeviceChain() // > 1 KiB: exercises chunked reads
	swtpmtest.Define(t, tr, 0x01C00002, swtpmtest.EKCertAttrs, 0, pki.EK.Raw)
	swtpmtest.Define(t, tr, 0x01C00100, swtpmtest.EKCertAttrs, 0, chain)
	swtpmtest.Define(t, tr, 0x01C0000A, swtpmtest.EKCertAttrs, 64, nil) // defined, not written
	swtpmtest.Define(t, tr, 0x01C00012, swtpmtest.DAProtectedAttrs, 0, []byte{1})
	swtpmtest.Define(t, tr, 0x01C00014, swtpmtest.PolicyOnlyAttrs, 0, []byte{1})

	s, err := tp.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Info.Manufacturer != "IBM" || s.Info.Family != "2.0" {
		t.Errorf("info %+v", s.Info)
	}
	if e := s.Entry(0x01C00002); e == nil || !bytes.Equal(e.Data, pki.EK.Raw) || len(e.Certificates) != 1 {
		t.Fatalf("EK entry %+v", e)
	}
	if e := s.Entry(0x01C00100); !bytes.Equal(e.Data, chain) || len(e.Certificates) != 3 {
		t.Fatalf("chain: %d bytes, %d certificates, %s", len(e.Data), len(e.Certificates), e.ReadError)
	}
	for idx, want := range map[uint32]error{
		0x01C0000A: tpm.ErrNotWritten,
		0x01C00012: tpm.ErrDARisk,
		0x01C00014: tpm.ErrNotReadable,
	} {
		e := s.Entry(idx)
		if e == nil || !strings.Contains(e.ReadError, want.Error()) {
			t.Errorf("%s: read error %q, want %q", tpm.HexIndex(idx), e.ReadError, want)
		}
	}
	// Direct read of a defined index with owner authorization.
	data, err := tp.Backend().NVRead(ctx, 0x01C00002)
	if err != nil || !bytes.Equal(data, pki.EK.Raw) {
		t.Errorf("NVRead: %v", err)
	}
	var nvErr *tpm.NVError
	if _, err := tp.Backend().NVRead(ctx, 0x01C00012); !errors.As(err, &nvErr) || !errors.Is(err, tpm.ErrDARisk) {
		t.Errorf("DA protected read: %v", err)
	}
}

func TestOpenSpecErrors(t *testing.T) {
	if _, err := tpm.Open("mssim:host=x"); err == nil {
		t.Error("unsupported spec accepted")
	}
	if _, err := tpm.Open("swtpm:path=/nonexistent/sock"); err == nil {
		t.Error("connect to missing socket succeeded")
	}
}
