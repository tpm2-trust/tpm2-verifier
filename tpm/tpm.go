// Package tpm reads the TPM identity and the TCG NV indices holding EK
// certificates and certificate chains.
//
// Only data that is public by design is read and no secrets are used:
// properties, NV public areas, and the content of indices in the TCG range
// (0x01C00000-0x01C0FFFF) that can be read with an empty owner or index
// authorization (see Device.NVRead).
package tpm

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/tpm2-trust/tpm2-verifier/certparse"
)

// TPM_PT_FIXED properties used by Info.
const (
	PTFamilyIndicator  = 0x100
	PTRevision         = 0x102
	PTDayOfYear        = 0x103
	PTYear             = 0x104
	PTManufacturer     = 0x105
	PTVendorString1    = 0x106
	PTVendorString4    = 0x109
	PTVendorTPMType    = 0x10A
	PTFirmwareVersion1 = 0x10B
	PTFirmwareVersion2 = 0x10C
	PTNVBufferMax      = 0x12C
)

// TPM gives access to the TPM identity and EK certificate material.
type TPM struct {
	b Backend
}

// New wraps a Backend.
func New(b Backend) *TPM { return &TPM{b: b} }

// Backend returns the underlying backend.
func (t *TPM) Backend() Backend { return t.b }

// Close closes the backend.
func (t *TPM) Close() error { return t.b.Close() }

// Info is the identity of a TPM.
type Info struct {
	// Manufacturer is the normalized vendor ID, e.g. "INTC" or "IFX".
	Manufacturer    string `json:"manufacturer"`
	ManufacturerRaw uint32 `json:"manufacturer_raw"`
	VendorString    string `json:"vendor_string,omitempty"`
	VendorTPMType   uint32 `json:"vendor_tpm_type"`
	// FirmwareVersion is "major.minor.build.patch" from the two firmware version properties.
	FirmwareVersion string `json:"firmware_version"`
	Family          string `json:"family"`
	// SpecRevision is the TPM library spec revision, e.g. "1.59".
	SpecRevision string `json:"spec_revision"`
	// SpecDate is the date of the spec version, "YYYY day DDD".
	SpecDate   string            `json:"spec_date,omitempty"`
	Properties map[uint32]uint32 `json:"-"`
}

// Info reads the fixed properties of the TPM.
func (t *TPM) Info(ctx context.Context) (*Info, error) {
	p, err := t.b.FixedProperties(ctx)
	if err != nil {
		return nil, err
	}
	return InfoFromProperties(p), nil
}

// InfoFromProperties decodes TPM_PT_FIXED properties.
func InfoFromProperties(p map[uint32]uint32) *Info {
	var vs strings.Builder
	for pt := uint32(PTVendorString1); pt <= PTVendorString4; pt++ {
		vs.WriteString(fourCC(p[pt]))
	}
	fw1, fw2 := p[PTFirmwareVersion1], p[PTFirmwareVersion2]
	info := &Info{
		Manufacturer:    certparse.NormalizeManufacturer(fourCC(p[PTManufacturer])),
		ManufacturerRaw: p[PTManufacturer],
		VendorString:    strings.TrimSpace(vs.String()),
		VendorTPMType:   p[PTVendorTPMType],
		FirmwareVersion: fmt.Sprintf("%d.%d.%d.%d", fw1>>16, fw1&0xffff, fw2>>16, fw2&0xffff),
		Family:          fourCC(p[PTFamilyIndicator]),
		SpecRevision:    fmt.Sprintf("%d.%02d", p[PTRevision]/100, p[PTRevision]%100),
		Properties:      p,
	}
	if y := p[PTYear]; y != 0 {
		info.SpecDate = fmt.Sprintf("%d day %d", y, p[PTDayOfYear])
	}
	return info
}

// fourCC decodes a property holding up to four ASCII characters.
func fourCC(v uint32) string {
	b := binary.BigEndian.AppendUint32(nil, v)
	return strings.TrimRight(strings.Map(func(r rune) rune {
		if r == 0 {
			return -1
		}
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, string(b)), " ")
}

// Entry is one NV index found by Scan.
type Entry struct {
	Index  uint32    `json:"index"`
	Label  Label     `json:"label"`
	Public *NVPublic `json:"public,omitempty"`
	// Data is the raw content; only read for indices in the TCG range.
	Data []byte `json:"-"`
	// Certificates parsed from Data, for certificate and chain indices.
	Certificates []*certparse.Certificate `json:"-"`
	ReadError    string                   `json:"read_error,omitempty"`
	ParseError   string                   `json:"parse_error,omitempty"`
}

// Scan is the result of reading all NV indices.
type Scan struct {
	Info    *Info    `json:"info"`
	Entries []*Entry `json:"nv"`
}

// Scan reads the TPM identity, lists all NV indices and reads the TCG ones.
// Failures of single indices are recorded in the entries.
func (t *TPM) Scan(ctx context.Context) (*Scan, error) {
	info, err := t.Info(ctx)
	if err != nil {
		return nil, err
	}
	idx, err := t.b.NVIndices(ctx)
	if err != nil {
		return nil, err
	}
	s := &Scan{Info: info}
	for _, i := range idx {
		e := &Entry{Index: i, Label: Describe(i)}
		s.Entries = append(s.Entries, e)
		pub, err := t.b.NVReadPublic(ctx, i)
		if err != nil {
			e.ReadError = err.Error()
			continue
		}
		e.Public = pub
		if !IsTCG(i) {
			continue
		}
		data, err := t.b.NVRead(ctx, i)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			e.ReadError = err.Error()
			continue
		}
		e.Data = data
		e.parse()
	}
	return s, nil
}

func (e *Entry) parse() {
	switch e.Label.Kind {
	case KindEKCert, KindEKChain, KindPlatformCert, KindTCGReserved:
	default:
		return
	}
	certs, err := certparse.ParseAll(e.Data)
	e.Certificates = certs
	if err != nil {
		// Unknown TCG indices may hold anything; only report errors for
		// indices that must contain certificates.
		if (e.Label.Kind != KindTCGReserved && e.Label.Kind != KindPlatformCert) || len(certs) > 0 {
			e.ParseError = err.Error()
		}
	}
}

// Entry returns the entry for index, or nil.
func (s *Scan) Entry(index uint32) *Entry {
	for _, e := range s.Entries {
		if e.Index == index {
			return e
		}
	}
	return nil
}

// EKCertificates returns the EK certificate indices that hold a certificate.
func (s *Scan) EKCertificates() []*Entry {
	var out []*Entry
	for _, e := range s.Entries {
		if e.Label.Kind == KindEKCert && len(e.Certificates) > 0 {
			out = append(out, e)
		}
	}
	return out
}

// ChainCertificates returns the certificates stored in the given chain
// indices, or in all indices of the TCG chain range if none are given.
func (s *Scan) ChainCertificates(indices ...uint32) []*certparse.Certificate {
	var out []*certparse.Certificate
	for _, e := range s.Entries {
		if len(indices) > 0 {
			found := false
			for _, i := range indices {
				found = found || i == e.Index
			}
			if !found {
				continue
			}
		} else if e.Label.Kind != KindEKChain {
			continue
		}
		out = append(out, e.Certificates...)
	}
	return out
}
