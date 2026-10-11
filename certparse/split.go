package certparse

import (
	"encoding/pem"
	"fmt"
)

// SplitError reports a structural problem in a DER blob.
type SplitError struct {
	Offset int
	Reason string
}

func (e *SplitError) Error() string {
	return fmt.Sprintf("certparse: offset %d: %s", e.Offset, e.Reason)
}

// SplitDER splits a blob of concatenated DER encoded SEQUENCEs, as stored by
// TPM vendors in the TCG EK certificate chain NV range (0x01C00100-0x01C001FF),
// into its elements.
//
// Unlike scanning for the bytes 0x30 0x82, the length of each element is read
// from its header, so certificates of any size are found and nothing inside a
// certificate is mistaken for the start of the next one. Trailing padding
// (0x00 or 0xFF, as found in partially used NV indices) is ignored.
func SplitDER(data []byte) ([][]byte, error) {
	var out [][]byte
	for off := 0; off < len(data); {
		if isPadding(data[off:]) {
			break
		}
		n, err := elementLen(data, off)
		if err != nil {
			return out, err
		}
		out = append(out, data[off:off+n])
		off += n
	}
	return out, nil
}

// elementLen returns the total length (header and content) of the DER
// SEQUENCE starting at data[off].
func elementLen(data []byte, off int) (int, error) {
	rest := data[off:]
	if len(rest) < 2 {
		return 0, &SplitError{off, "truncated header"}
	}
	if rest[0] != 0x30 {
		return 0, &SplitError{off, fmt.Sprintf("expected SEQUENCE (0x30), found 0x%02x", rest[0])}
	}
	l := int(rest[1])
	hl := 2
	switch {
	case l == 0x80:
		return 0, &SplitError{off, "indefinite length is not DER"}
	case l > 0x80:
		n := l & 0x7f
		if n > 4 {
			return 0, &SplitError{off, fmt.Sprintf("length of length %d too large", n)}
		}
		if len(rest) < 2+n {
			return 0, &SplitError{off, "truncated length"}
		}
		l = 0
		for _, b := range rest[2 : 2+n] {
			l = l<<8 | int(b)
		}
		hl += n
	}
	if hl+l > len(rest) {
		return 0, &SplitError{off, fmt.Sprintf("element of %d bytes exceeds remaining %d bytes", hl+l, len(rest))}
	}
	return hl + l, nil
}

func isPadding(b []byte) bool {
	for _, c := range b {
		if c != 0x00 && c != 0xff {
			return false
		}
	}
	return true
}

// SplitAny accepts PEM (any number of CERTIFICATE blocks) or concatenated DER
// and returns the DER encoding of every element.
func SplitAny(data []byte) ([][]byte, error) {
	if block, rest := pem.Decode(data); block != nil {
		var out [][]byte
		for block != nil {
			if block.Type == "CERTIFICATE" || block.Type == "X509 CRL" {
				out = append(out, block.Bytes)
			}
			block, rest = pem.Decode(rest)
		}
		return out, nil
	}
	return SplitDER(data)
}
