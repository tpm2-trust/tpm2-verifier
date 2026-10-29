package manifest

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Signer is a key trusted to sign vendor data.
type Signer struct {
	Principal string
	Key       PublicKey
}

// PublicKey is an ssh-ed25519 public key.
type PublicKey ed25519.PublicKey

// Equal reports whether k and o are the same key.
func (k PublicKey) Equal(o PublicKey) bool { return bytes.Equal(k, o) }

// Fingerprint returns the key fingerprint as ssh-keygen -l shows it.
func (k PublicKey) Fingerprint() string {
	sum := sha256.Sum256(sshString(sshString(nil, []byte(keyTypeEd25519)), k))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

const keyTypeEd25519 = "ssh-ed25519"

//go:embed allowed_signers
var allowedSigners []byte

// TrustedSigners returns the signers compiled into the binary
// (manifest/allowed_signers in the source tree).
func TrustedSigners() ([]Signer, error) {
	s, err := ParseAllowedSigners(allowedSigners)
	if err != nil {
		return nil, fmt.Errorf("built-in allowed_signers: %w", err)
	}
	return s, nil
}

// ParseAllowedSigners reads an ssh allowed_signers file
// ("principal [options] ssh-ed25519 <base64> [comment]"). Keys restricted
// with namespaces="..." to other namespaces are skipped.
func ParseAllowedSigners(data []byte) ([]Signer, error) {
	var out []Signer
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		i := slices.IndexFunc(f, func(s string) bool {
			return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
		})
		if i < 1 || i+1 >= len(f) {
			return nil, fmt.Errorf("line %d: expected \"principal [options] ssh-ed25519 <key>\"", n)
		}
		if f[i] != keyTypeEd25519 {
			return nil, fmt.Errorf("line %d: key type %s not supported, use ssh-ed25519", n, f[i])
		}
		blob, err := base64.StdEncoding.DecodeString(f[i+1])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		key, err := parsePublicKey(blob)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if !namespaceAllowed(strings.Join(f[1:i], " ")) {
			continue
		}
		out = append(out, Signer{Principal: f[0], Key: key})
	}
	return out, sc.Err()
}

func namespaceAllowed(options string) bool {
	i := strings.Index(options, "namespaces=")
	if i < 0 {
		return true
	}
	v := options[i+len("namespaces="):]
	if q, ok := strings.CutPrefix(v, `"`); ok {
		v, _, _ = strings.Cut(q, `"`)
	} else {
		v, _, _ = strings.Cut(v, ",")
	}
	for _, ns := range strings.Split(v, ",") {
		if ns == Namespace || ns == "*" {
			return true
		}
	}
	return false
}

// VerifySSHSig verifies an armored SSH signature (PROTOCOL.sshsig, as
// written by ssh-keygen -Y sign) of message in namespace and returns the
// signing key. Only ssh-ed25519 keys are supported.
func VerifySSHSig(message, armored []byte, namespace string) (PublicKey, error) {
	b, _ := pem.Decode(armored)
	if b == nil || b.Type != "SSH SIGNATURE" {
		return nil, errors.New("not an SSH signature")
	}
	r := &reader{b: b.Bytes}
	magic := r.fixed(6)
	version := r.uint32()
	pub, ns, reserved, hashAlg, sig := r.string(), r.string(), r.string(), r.string(), r.string()
	if r.err != nil || len(r.b) != 0 || string(magic) != "SSHSIG" || version != 1 {
		return nil, errors.New("malformed SSH signature")
	}
	if string(ns) != namespace {
		return nil, fmt.Errorf("signature namespace %q, want %q", ns, namespace)
	}
	key, err := parsePublicKey(pub)
	if err != nil {
		return nil, err
	}
	var h []byte
	switch string(hashAlg) {
	case "sha512":
		s := sha512.Sum512(message)
		h = s[:]
	case "sha256":
		s := sha256.Sum256(message)
		h = s[:]
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", hashAlg)
	}
	sr := &reader{b: sig}
	format, raw := sr.string(), sr.string()
	if sr.err != nil || len(sr.b) != 0 || string(format) != keyTypeEd25519 || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("malformed ssh-ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(key), SignedData(namespace, reserved, string(hashAlg), h), raw) {
		return nil, errors.New("signature does not verify (the MANIFEST was changed after signing, or the signature belongs to another file)")
	}
	return key, nil
}

// SignedData returns the data an SSH signature is computed over.
func SignedData(namespace string, reserved []byte, hashAlg string, hash []byte) []byte {
	d := []byte("SSHSIG")
	d = sshString(d, []byte(namespace))
	d = sshString(d, reserved)
	d = sshString(d, []byte(hashAlg))
	return sshString(d, hash)
}

func parsePublicKey(blob []byte) (PublicKey, error) {
	r := &reader{b: blob}
	typ, key := r.string(), r.string()
	if r.err != nil || len(r.b) != 0 {
		return nil, errors.New("malformed public key")
	}
	if string(typ) != keyTypeEd25519 {
		return nil, fmt.Errorf("key type %s not supported, use ssh-ed25519", typ)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("malformed ssh-ed25519 key")
	}
	return PublicKey(key), nil
}

// sshString appends the SSH wire encoding of s (length prefixed).
func sshString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) fixed(n int) []byte {
	if r.err != nil || len(r.b) < n {
		r.err = errors.New("short")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) uint32() uint32 {
	v := r.fixed(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (r *reader) string() []byte {
	n := r.uint32()
	if uint64(n) > uint64(len(r.b)) {
		r.err = errors.New("short")
		return nil
	}
	return r.fixed(int(n))
}
