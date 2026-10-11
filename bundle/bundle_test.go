package bundle_test

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-verifier/bundle"
	"github.com/mrwiora/tpm2-verifier/internal/swtpmtest"
	"github.com/mrwiora/tpm2-verifier/internal/testpki"
	"github.com/mrwiora/tpm2-verifier/tpm"
)

var ctx = context.Background()

func roundTrip(t *testing.T, b *bundle.Bundle) *bundle.Bundle {
	t.Helper()
	var buf bytes.Buffer
	if _, err := b.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	out, err := bundle.Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sameScan compares the scans of two backends entry by entry.
func sameScan(t *testing.T, want, got tpm.Backend) {
	t.Helper()
	a, err := tpm.New(want).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tpm.New(got).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Info, b.Info) {
		t.Errorf("info differs: %+v vs %+v", a.Info, b.Info)
	}
	if len(a.Entries) != len(b.Entries) {
		t.Fatalf("%d entries, replay has %d", len(a.Entries), len(b.Entries))
	}
	for i := range a.Entries {
		x, y := a.Entries[i], b.Entries[i]
		if x.Index != y.Index || x.ReadError != y.ReadError || !bytes.Equal(x.Data, y.Data) ||
			len(x.Certificates) != len(y.Certificates) || (x.Public == nil) != (y.Public == nil) ||
			(x.Public != nil && x.Public.Attributes != y.Public.Attributes) {
			t.Errorf("%s differs:\n  live   %+v\n  replay %+v", tpm.HexIndex(x.Index), x, y)
		}
	}
}

func TestRoundTripFake(t *testing.T) {
	pki := testpki.IntelLike(t)
	f := &tpm.Fake{Properties: map[uint32]uint32{tpm.PTManufacturer: 0x494E5443, tpm.PTFirmwareVersion1: 0x00100002}}
	f.SetCertificate(0x01C00002, pki.EK.Raw)
	f.SetCertificate(0x01C00100, pki.DeviceChain())
	f.SetCertificate(0x01500000, []byte("not read"))
	nv := f.NV[0x01C0000A]
	nv.Public = tpm.NVPublic{Attributes: tpm.NVOwnerRead, Size: 10} // not written
	f.NV[0x01C0000A] = nv

	b, err := bundle.Collect(ctx, f, bundle.CollectOptions{Tool: "test", TPM: "fake", NoPlatform: true})
	if err != nil {
		t.Fatal(err)
	}
	b.Extra["analysis/summary.txt"] = []byte("hello")
	got := roundTrip(t, b)

	if got.Manifest.Tool != "test" || got.Info().Manufacturer != "INTC" || string(got.Extra["analysis/summary.txt"]) != "hello" {
		t.Errorf("manifest %+v extra %v", got.Manifest, got.Extra)
	}
	for _, r := range got.NV {
		switch r.IndexValue() {
		case 0x01500000:
			if r.Skipped == "" || r.Bytes() != nil {
				t.Errorf("non TCG index recorded: %+v", r)
			}
		case 0x01C0000A:
			if !strings.Contains(r.ReadError, "not been written") {
				t.Errorf("read error %q", r.ReadError)
			}
		}
	}
	sameScan(t, f, got.Fake())
}

// TestRoundTripSwtpm records a real (software) TPM through the device
// backend, including indices that cannot be read.
func TestRoundTripSwtpm(t *testing.T) {
	spec := swtpmtest.Start(t)
	tp, err := tpm.Open(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()
	tr := tp.Backend().(*tpm.Device).Transport()
	pki := testpki.IntelLike(t)
	swtpmtest.Define(t, tr, 0x01C00002, swtpmtest.EKCertAttrs, 0, pki.EK.Raw)
	swtpmtest.Define(t, tr, 0x01C00100, swtpmtest.EKCertAttrs, 0, pki.DeviceChain())
	swtpmtest.Define(t, tr, 0x01C0000A, swtpmtest.EKCertAttrs, 32, nil)
	swtpmtest.Define(t, tr, 0x01C00012, swtpmtest.DAProtectedAttrs, 0, []byte{1})
	swtpmtest.Define(t, tr, 0x01C00014, swtpmtest.PolicyOnlyAttrs, 0, []byte{1})
	swtpmtest.Define(t, tr, 0x01800001, swtpmtest.EKCertAttrs, 0, []byte("owner data"))

	b, err := bundle.Collect(ctx, tp.Backend(), bundle.CollectOptions{Tool: "test", TPM: spec})
	if err != nil {
		t.Fatal(err)
	}
	got := roundTrip(t, b)
	if got.Info().Manufacturer != "IBM" || len(got.NV) != 6 {
		t.Fatalf("manufacturer %q, %d NV records", got.Info().Manufacturer, len(got.NV))
	}
	sameScan(t, tp.Backend(), got.Fake())
}

func TestReadRejectsTampering(t *testing.T) {
	f := &tpm.Fake{Properties: map[uint32]uint32{}}
	f.SetCertificate(0x01C00002, []byte("data-data-data"))
	b, err := bundle.Collect(ctx, f, bundle.CollectOptions{NoPlatform: true})
	if err != nil {
		t.Fatal(err)
	}
	b.NV[0].SHA256 = strings.Repeat("0", 64)
	var buf bytes.Buffer
	b.WriteTo(&buf)
	if _, err := bundle.Read(&buf); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("tampered data accepted: %v", err)
	}

	b.Manifest.Format = bundle.FormatVersion + 1
	buf.Reset()
	b.WriteTo(&buf)
	if _, err := bundle.Read(&buf); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("future format accepted: %v", err)
	}
	if _, err := bundle.Read(strings.NewReader("not gzip")); err == nil {
		t.Error("garbage accepted")
	}
}
