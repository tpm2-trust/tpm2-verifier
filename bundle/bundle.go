// Package bundle records everything this module reads from a TPM into a
// debug bundle (a .tar.gz), and replays a bundle as a tpm.Fake.
//
// A bundle makes a TPM of an unknown vendor analyzable on another machine
// and turns it into a regression test fixture. Layout:
//
//	manifest.json        format, tool version, OS, kernel, platform (sysfs, DMI)
//	README.txt           what the bundle contains
//	tpm/properties.json  all TPM_PT_FIXED properties
//	tpm/info.json        decoded identity (manufacturer, firmware, ...)
//	tpm/nv.json          every NV index: public area, read errors, data file
//	tpm/nv/<index>.bin   content of every readable index of the TCG range
//	analysis/...         files added by the creator (e.g. tpm2-ek debug)
//
// A bundle contains the EK certificate, which uniquely identifies the TPM.
package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/mrwiora/tpm2-verifier/tpm"
)

// FormatVersion is the bundle format written by this package.
const FormatVersion = 1

// Manifest describes where and how a bundle was created.
type Manifest struct {
	Format  int       `json:"format"`
	Tool    string    `json:"tool"`
	Created time.Time `json:"created"`
	OS      string    `json:"os"`
	Arch    string    `json:"arch"`
	Kernel  string    `json:"kernel,omitempty"`
	// Platform holds TPM sysfs attributes and DMI vendor/model strings
	// (no serial numbers or UUIDs).
	Platform map[string]string `json:"platform,omitempty"`
	// TPM is the spec the TPM was opened with.
	TPM   string   `json:"tpm"`
	Notes []string `json:"notes,omitempty"`
}

// NVRecord is the recording of one NV index.
type NVRecord struct {
	Index       string        `json:"index"`
	Label       string        `json:"label"`
	Public      *tpm.NVPublic `json:"public,omitempty"`
	PublicError string        `json:"public_error,omitempty"`
	// Data is the bundle path of the content, if it was read.
	Data      string `json:"data,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	ReadError string `json:"read_error,omitempty"`
	// Skipped explains why the content was not read.
	Skipped string `json:"skipped,omitempty"`

	index uint32
	data  []byte
}

// Bytes returns the recorded content of the index, or nil.
func (r *NVRecord) Bytes() []byte { return r.data }

// IndexValue returns the numeric NV index.
func (r *NVRecord) IndexValue() uint32 { return r.index }

// Bundle is a recording of a TPM.
type Bundle struct {
	Manifest   Manifest
	Properties map[uint32]uint32
	NV         []*NVRecord
	// Extra holds additional files by bundle path, e.g. "analysis/summary.txt".
	Extra map[string][]byte
}

// CollectOptions configure Collect.
type CollectOptions struct {
	// Tool is recorded in the manifest, e.g. "tpm2-ek v0.3.0".
	Tool string
	// TPM is the spec used to open the TPM, recorded in the manifest.
	TPM string
	// NoPlatform skips the sysfs and DMI information.
	NoPlatform bool
}

// Collect records the TPM behind b: all fixed properties, all NV public
// areas and the content of every readable NV index in the TCG range.
// Errors of single indices are recorded, not returned.
func Collect(ctx context.Context, b tpm.Backend, opts CollectOptions) (*Bundle, error) {
	bd := &Bundle{
		Manifest: Manifest{
			Format:  FormatVersion,
			Tool:    opts.Tool,
			Created: time.Now().UTC().Truncate(time.Second),
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			TPM:     opts.TPM,
		},
		Extra: map[string][]byte{},
	}
	if !opts.NoPlatform {
		bd.Manifest.Kernel, bd.Manifest.Platform = platformInfo()
	}
	props, err := b.FixedProperties(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundle: reading TPM properties: %w", err)
	}
	bd.Properties = props
	indices, err := b.NVIndices(ctx)
	if err != nil {
		bd.Manifest.Notes = append(bd.Manifest.Notes, "listing NV indices failed: "+err.Error())
	}
	for _, i := range indices {
		rec := &NVRecord{Index: tpm.HexIndex(i), Label: tpm.Describe(i).String(), index: i}
		bd.NV = append(bd.NV, rec)
		pub, err := b.NVReadPublic(ctx, i)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			rec.PublicError = innerError(err)
			continue
		}
		rec.Public = pub
		if !tpm.IsTCG(i) {
			rec.Skipped = "outside the TCG range"
			continue
		}
		data, err := b.NVRead(ctx, i)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			rec.ReadError = innerError(err)
			continue
		}
		rec.setData(data)
	}
	return bd, nil
}

func (r *NVRecord) setData(data []byte) {
	sum := sha256.Sum256(data)
	r.data = data
	r.SHA256 = hex.EncodeToString(sum[:])
	r.Data = "tpm/nv/" + r.Index + ".bin"
}

// innerError strips the "NV 0x...: " prefix so that a replayed error reads
// exactly like the original.
func innerError(err error) string {
	var nvErr *tpm.NVError
	if errors.As(err, &nvErr) {
		return nvErr.Err.Error()
	}
	return err.Error()
}

// Info decodes the recorded properties.
func (b *Bundle) Info() *tpm.Info { return tpm.InfoFromProperties(b.Properties) }

// Fake returns a TPM backend replaying the bundle. Recorded read errors are
// returned again by NVReadPublic and NVRead.
func (b *Bundle) Fake() *tpm.Fake {
	f := &tpm.Fake{Properties: b.Properties, NV: map[uint32]tpm.FakeNV{}}
	for _, r := range b.NV {
		nv := tpm.FakeNV{Data: r.data}
		switch {
		case r.PublicError != "":
			nv.PublicErr = errors.New(r.PublicError)
		case r.Public != nil:
			nv.Public = *r.Public
		}
		if r.ReadError != "" {
			nv.ReadErr = errors.New(r.ReadError)
		}
		f.NV[r.index] = nv
	}
	return f
}

// sortNV orders records by index.
func (b *Bundle) sortNV() {
	sort.Slice(b.NV, func(i, j int) bool { return b.NV[i].index < b.NV[j].index })
}

// PlatformInfo returns the kernel release and the platform information a
// bundle records: TPM sysfs attributes and DMI vendor/model strings (no
// serial numbers or UUIDs).
func PlatformInfo() (kernel string, info map[string]string) { return platformInfo() }
