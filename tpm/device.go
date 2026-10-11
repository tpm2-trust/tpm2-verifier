package tpm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Device is the Backend for a real (or software) TPM, using go-tpm.
type Device struct {
	t     transport.TPMCloser
	names map[uint32]tpm2.TPM2BName
	// chunk is the NV read size, from TPM_PT_NV_BUFFER_MAX.
	chunk uint16
}

var _ Backend = (*Device)(nil)

// NewDevice wraps a go-tpm transport.
func NewDevice(t transport.TPMCloser) *Device {
	return &Device{t: t, names: map[uint32]tpm2.TPM2BName{}}
}

// Transport returns the underlying go-tpm transport.
func (d *Device) Transport() transport.TPM { return d.t }

// Close implements Backend.
func (d *Device) Close() error { return d.t.Close() }

const (
	ptFixed     = 0x100
	ptVarFirst  = 0x200
	nvHandleMSB = 0x01000000
)

// FixedProperties implements Backend.
func (d *Device) FixedProperties(ctx context.Context) (map[uint32]uint32, error) {
	out := map[uint32]uint32{}
	next := uint32(ptFixed)
	for next < ptVarFirst {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      next,
			PropertyCount: ptVarFirst - next,
		}.Execute(d.t)
		if err != nil {
			return nil, fmt.Errorf("tpm: GetCapability(properties): %w", err)
		}
		props, err := rsp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return nil, err
		}
		if len(props.TPMProperty) == 0 {
			break
		}
		for _, p := range props.TPMProperty {
			if uint32(p.Property) >= ptVarFirst {
				return out, nil
			}
			out[uint32(p.Property)] = p.Value
			next = uint32(p.Property) + 1
		}
		if !rsp.MoreData {
			break
		}
	}
	return out, nil
}

// NVIndices implements Backend.
func (d *Device) NVIndices(ctx context.Context) ([]uint32, error) {
	var out []uint32
	next := uint32(nvHandleMSB)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      next,
			PropertyCount: 256,
		}.Execute(d.t)
		if err != nil {
			return nil, fmt.Errorf("tpm: GetCapability(handles): %w", err)
		}
		hs, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			return nil, err
		}
		for _, h := range hs.Handle {
			if uint32(h)&0xff000000 != nvHandleMSB {
				return out, nil
			}
			out = append(out, uint32(h))
			next = uint32(h) + 1
		}
		if !rsp.MoreData || len(hs.Handle) == 0 {
			return out, nil
		}
	}
}

// NVReadPublic implements Backend.
func (d *Device) NVReadPublic(ctx context.Context, index uint32) (*NVPublic, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(d.t)
	if err != nil {
		return nil, &NVError{index, err}
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return nil, &NVError{index, err}
	}
	d.names[index] = rsp.NVName
	return &NVPublic{
		Index:      index,
		NameAlg:    uint16(pub.NameAlg),
		Attributes: NVAttributes(binary.BigEndian.Uint32(tpm2.Marshal(pub.Attributes))),
		AuthPolicy: pub.AuthPolicy.Buffer,
		Size:       pub.DataSize,
	}, nil
}

// NVRead implements Backend. See readAuths for the authorization strategy;
// no secrets are ever used.
func (d *Device) NVRead(ctx context.Context, index uint32) ([]byte, error) {
	pub, err := d.NVReadPublic(ctx, index)
	if err != nil {
		return nil, err
	}
	auths, err := readAuths(pub)
	if err != nil {
		return nil, &NVError{index, err}
	}
	if d.chunk == 0 {
		d.chunk = 512
		if props, err := d.FixedProperties(ctx); err == nil {
			if v := props[uint32(tpm2.TPMPTNVBufferMax)]; v > 0 && v < 0xffff {
				d.chunk = uint16(v)
			}
		}
	}
	var lastErr error
	for _, a := range auths {
		data, err := d.read(ctx, index, pub.Size, a)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !errors.Is(err, tpm2.TPMRCBadAuth) && !errors.Is(err, tpm2.TPMRCAuthFail) {
			break
		}
	}
	return nil, &NVError{index, lastErr}
}

func (d *Device) read(ctx context.Context, index uint32, size uint16, a readAuth) ([]byte, error) {
	nv := tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: d.names[index]}
	auth := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	if a == authIndex {
		auth = tpm2.AuthHandle{Handle: nv.Handle, Name: nv.Name, Auth: tpm2.PasswordAuth(nil)}
	}
	out := make([]byte, 0, size)
	for off := uint16(0); off < size; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(d.chunk, size-off)
		rsp, err := tpm2.NVRead{AuthHandle: auth, NVIndex: nv, Size: n, Offset: off}.Execute(d.t)
		if err != nil {
			return nil, err
		}
		if len(rsp.Data.Buffer) == 0 {
			return nil, fmt.Errorf("empty read at offset %d", off)
		}
		out = append(out, rsp.Data.Buffer...)
		off += uint16(len(rsp.Data.Buffer))
	}
	return out, nil
}
