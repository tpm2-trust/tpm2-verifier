package tpm

import (
	"context"
	"errors"
	"slices"
)

// Fake is an in-memory Backend. It is used in tests and to replay data
// recorded from a real TPM.
type Fake struct {
	Properties map[uint32]uint32
	NV         map[uint32]FakeNV
}

// FakeNV is one NV index of a Fake.
type FakeNV struct {
	Public NVPublic
	Data   []byte
	// ReadErr, if set, is returned by NVRead (e.g. a recorded failure).
	ReadErr error
}

var _ Backend = (*Fake)(nil)

// FixedProperties implements Backend.
func (f *Fake) FixedProperties(context.Context) (map[uint32]uint32, error) {
	return f.Properties, nil
}

// NVIndices implements Backend.
func (f *Fake) NVIndices(context.Context) ([]uint32, error) {
	var out []uint32
	for i := range f.NV {
		out = append(out, i)
	}
	slices.Sort(out)
	return out, nil
}

// NVReadPublic implements Backend.
func (f *Fake) NVReadPublic(_ context.Context, index uint32) (*NVPublic, error) {
	nv, ok := f.NV[index]
	if !ok {
		return nil, &NVError{index, errors.New("index not defined")}
	}
	p := nv.Public
	p.Index = index
	return &p, nil
}

// NVRead implements Backend. It applies the same authorization rules as the
// device backend.
func (f *Fake) NVRead(ctx context.Context, index uint32) ([]byte, error) {
	pub, err := f.NVReadPublic(ctx, index)
	if err != nil {
		return nil, err
	}
	if _, err := readAuths(pub); err != nil {
		return nil, &NVError{index, err}
	}
	nv := f.NV[index]
	if nv.ReadErr != nil {
		return nil, &NVError{index, nv.ReadErr}
	}
	return slices.Clone(nv.Data), nil
}

// Close implements Backend.
func (f *Fake) Close() error { return nil }

// SetCertificate defines index with data like a vendor would provision an EK
// certificate: platform written, owner and auth readable, no DA.
func (f *Fake) SetCertificate(index uint32, data []byte) {
	if f.NV == nil {
		f.NV = map[uint32]FakeNV{}
	}
	f.NV[index] = FakeNV{
		Public: NVPublic{
			Index:      index,
			NameAlg:    0x000B, // SHA-256
			Attributes: NVPPWrite | NVWriteDefine | NVOwnerRead | NVAuthRead | NVPPRead | NVNoDA | NVWritten | NVPlatformCreate,
			Size:       uint16(len(data)),
		},
		Data: slices.Clone(data),
	}
}
