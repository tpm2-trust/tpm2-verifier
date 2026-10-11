package tpm

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Backend is the minimal TPM access this package needs. It is implemented by
// the device backend (go-tpm) and by Fake, which serves recorded data.
type Backend interface {
	// FixedProperties returns the TPM_PT_FIXED properties (0x100-0x1FF).
	FixedProperties(ctx context.Context) (map[uint32]uint32, error)
	// NVIndices lists all defined NV indices.
	NVIndices(ctx context.Context) ([]uint32, error)
	// NVReadPublic returns the public area of an NV index.
	NVReadPublic(ctx context.Context, index uint32) (*NVPublic, error)
	// NVRead returns the full content of an NV index.
	NVRead(ctx context.Context, index uint32) ([]byte, error)
	Close() error
}

// NVAttributes are TPMA_NV bits.
type NVAttributes uint32

// TPMA_NV bits (TPM 2.0 Part 2, 13.4).
const (
	NVPPWrite        NVAttributes = 1 << 0
	NVOwnerWrite     NVAttributes = 1 << 1
	NVAuthWrite      NVAttributes = 1 << 2
	NVPolicyWrite    NVAttributes = 1 << 3
	NVPolicyDelete   NVAttributes = 1 << 10
	NVWriteLocked    NVAttributes = 1 << 11
	NVWriteAll       NVAttributes = 1 << 12
	NVWriteDefine    NVAttributes = 1 << 13
	NVWriteSTClear   NVAttributes = 1 << 14
	NVGlobalLock     NVAttributes = 1 << 15
	NVPPRead         NVAttributes = 1 << 16
	NVOwnerRead      NVAttributes = 1 << 17
	NVAuthRead       NVAttributes = 1 << 18
	NVPolicyRead     NVAttributes = 1 << 19
	NVNoDA           NVAttributes = 1 << 25
	NVOrderly        NVAttributes = 1 << 26
	NVClearSTClear   NVAttributes = 1 << 27
	NVReadLocked     NVAttributes = 1 << 28
	NVWritten        NVAttributes = 1 << 29
	NVPlatformCreate NVAttributes = 1 << 30
	NVReadSTClear    NVAttributes = 1 << 31
)

var attrNames = []struct {
	bit  NVAttributes
	name string
}{
	{NVPPWrite, "ppwrite"}, {NVOwnerWrite, "ownerwrite"}, {NVAuthWrite, "authwrite"}, {NVPolicyWrite, "policywrite"},
	{NVPolicyDelete, "policydelete"}, {NVWriteLocked, "writelocked"}, {NVWriteAll, "writeall"},
	{NVWriteDefine, "writedefine"}, {NVWriteSTClear, "write_stclear"}, {NVGlobalLock, "globallock"},
	{NVPPRead, "ppread"}, {NVOwnerRead, "ownerread"}, {NVAuthRead, "authread"}, {NVPolicyRead, "policyread"},
	{NVNoDA, "no_da"}, {NVOrderly, "orderly"}, {NVClearSTClear, "clear_stclear"}, {NVReadLocked, "readlocked"},
	{NVWritten, "written"}, {NVPlatformCreate, "platformcreate"}, {NVReadSTClear, "read_stclear"},
}

// Has reports whether all bits of b are set.
func (a NVAttributes) Has(b NVAttributes) bool { return a&b == b }

// Type returns the TPM_NT field (0 ordinary, 1 counter, 2 bits, 4 extend, 8 pin fail, 9 pin pass).
func (a NVAttributes) Type() uint8 { return uint8(a>>4) & 0xf }

// String lists the attributes in tpm2-tools notation: "ppwrite|ownerread|...".
func (a NVAttributes) String() string {
	var parts []string
	for _, n := range attrNames {
		if a.Has(n.bit) {
			parts = append(parts, n.name)
		}
	}
	if t := a.Type(); t != 0 {
		parts = append(parts, fmt.Sprintf("nt=%d", t))
	}
	return strings.Join(parts, "|")
}

// NVPublic is the public area of an NV index.
type NVPublic struct {
	Index      uint32       `json:"index"`
	NameAlg    uint16       `json:"name_alg"`
	Attributes NVAttributes `json:"attributes"`
	AuthPolicy []byte       `json:"auth_policy,omitempty"`
	Size       uint16       `json:"size"`
}

// Errors returned by NVRead (wrapped in *NVError).
var (
	ErrNotWritten  = errors.New("index has not been written")
	ErrReadLocked  = errors.New("index is read locked")
	ErrNotReadable = errors.New("index needs platform or policy authorization to read")
	ErrDARisk      = errors.New("index needs its auth value and is subject to dictionary attack protection; not attempted")
)

// NVError is an error reading an NV index.
type NVError struct {
	Index uint32
	Err   error
}

func (e *NVError) Error() string { return fmt.Sprintf("NV %s: %v", HexIndex(e.Index), e.Err) }
func (e *NVError) Unwrap() error { return e.Err }

// readAuth decides how an index can be read without secrets.
//
// Owner authorization with an empty password is used if the index allows
// owner reads; owner authorization failures do not count towards dictionary
// attack lockout. Index authorization is only tried for indices with
// TPMA_NV_NO_DA, so a failed attempt can never contribute to a lockout.
type readAuth int

const (
	authOwner readAuth = iota
	authIndex
)

func readAuths(pub *NVPublic) ([]readAuth, error) {
	a := pub.Attributes
	switch {
	case !a.Has(NVWritten):
		return nil, ErrNotWritten
	case a.Has(NVReadLocked):
		return nil, ErrReadLocked
	}
	var out []readAuth
	if a.Has(NVOwnerRead) {
		out = append(out, authOwner)
	}
	if a.Has(NVAuthRead) && a.Has(NVNoDA) {
		out = append(out, authIndex)
	}
	if len(out) == 0 {
		if a.Has(NVAuthRead) {
			return nil, ErrDARisk
		}
		return nil, ErrNotReadable
	}
	return out, nil
}
