package tpm

import "fmt"

// Kind classifies a TCG NV index.
type Kind string

const (
	KindEKCert       Kind = "ek-certificate"
	KindEKNonce      Kind = "ek-nonce"
	KindEKTemplate   Kind = "ek-template"
	KindEKChain      Kind = "ek-chain"
	KindEKPolicy     Kind = "ek-policy"
	KindPlatformCert Kind = "platform-certificate"
	KindTCGReserved  Kind = "tcg-reserved"
	KindOther        Kind = "other"
)

// TCG NV index ranges.
const (
	TCGRangeFirst      = 0x01C00000
	TCGRangeLast       = 0x01C0FFFF
	ChainRangeFirst    = 0x01C00100
	ChainRangeLast     = 0x01C001FF
	ekPolicyRangeFirst = 0x01C07F01
	ekPolicyRangeLast  = 0x01C07FFF
	platformRangeFirst = 0x01C08000
	platformRangeLast  = 0x01C0FFFF
)

// Label describes what an NV index holds according to the TCG EK Credential
// Profile.
type Label struct {
	Kind Kind `json:"kind"`
	// Key is the EK key type, e.g. "RSA 2048" or "ECC NIST P-256".
	Key string `json:"key,omitempty"`
	// Range is "low", a high range slot like "H-2", or "" if not applicable.
	Range string `json:"range,omitempty"`
}

func (l Label) String() string {
	s := string(l.Kind)
	if l.Key != "" {
		s += " " + l.Key
	}
	if l.Range != "" {
		s += " (" + l.Range + ")"
	}
	return s
}

var labels = map[uint32]Label{
	0x01C00002: {KindEKCert, "RSA 2048", "low"},
	0x01C00003: {KindEKNonce, "RSA 2048", "low"},
	0x01C00004: {KindEKTemplate, "RSA 2048", "low"},
	0x01C0000A: {KindEKCert, "ECC NIST P-256", "low"},
	0x01C0000B: {KindEKNonce, "ECC NIST P-256", "low"},
	0x01C0000C: {KindEKTemplate, "ECC NIST P-256", "low"},
	0x01C00012: {KindEKCert, "RSA 2048", "H-1"},
	0x01C00014: {KindEKCert, "ECC NIST P-256", "H-2"},
	0x01C00016: {KindEKCert, "ECC NIST P-384", "H-3"},
	0x01C00018: {KindEKCert, "ECC NIST P-521", "H-4"},
	0x01C0001A: {KindEKCert, "ECC SM2 P-256", "H-5"},
	0x01C0001C: {KindEKCert, "RSA 3072", "H-6"},
	0x01C0001E: {KindEKCert, "RSA 4096", "H-7"},
}

// Describe returns the TCG meaning of an NV index.
func Describe(index uint32) Label {
	if l, ok := labels[index]; ok {
		return l
	}
	switch {
	case index >= ChainRangeFirst && index <= ChainRangeLast:
		return Label{Kind: KindEKChain}
	case index >= ekPolicyRangeFirst && index <= ekPolicyRangeLast:
		return Label{Kind: KindEKPolicy}
	case index >= platformRangeFirst && index <= platformRangeLast:
		return Label{Kind: KindPlatformCert}
	case index >= TCGRangeFirst && index <= TCGRangeLast:
		return Label{Kind: KindTCGReserved}
	}
	return Label{Kind: KindOther}
}

// IsTCG reports whether index lies in the TCG defined range, whose content is
// public certificates and templates. Only these indices are read by Scan.
func IsTCG(index uint32) bool { return index >= TCGRangeFirst && index <= TCGRangeLast }

// HexIndex formats an NV index like tpm2-tools: 0x01C00002.
func HexIndex(index uint32) string { return fmt.Sprintf("0x%08X", index) }
