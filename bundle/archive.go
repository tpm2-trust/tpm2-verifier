package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Limits when reading a bundle.
const (
	maxFileSize  = 16 << 20
	maxTotalSize = 64 << 20
	maxFiles     = 4096
)

const readme = `tpm2-verifier debug bundle
==========================

This archive records what tpm2-verifier reads from a TPM, so that its EK
certificates can be analyzed on another machine:

  manifest.json        tool version, OS, kernel, TPM sysfs and DMI vendor/model
  tpm/properties.json  TPM fixed properties (manufacturer, firmware, ...)
  tpm/info.json        the same, decoded
  tpm/nv.json          all NV indices: attributes, size, read errors
  tpm/nv/*.bin         content of the readable TCG NV indices (EK certificates,
                       certificate chains, EK templates)
  analysis/            the verification result at creation time

PRIVACY: the EK certificate uniquely identifies this TPM, and therefore this
machine. Only share the bundle with people you trust with that information.
No secrets, keys or measurements are included.

Replay it with:  tpm2-verifier info -tpm bundle:<file>
`

// WriteTo writes the bundle as .tar.gz.
func (b *Bundle) WriteTo(w io.Writer) (int64, error) {
	cw := &countingWriter{w: w}
	gz := gzip.NewWriter(cw)
	tw := tar.NewWriter(gz)
	mtime := b.Manifest.Created
	if mtime.IsZero() {
		mtime = time.Now()
	}
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: mtime, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	addJSON := func(name string, v any) error {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return add(name, append(data, '\n'))
	}
	b.sortNV()
	props := map[string]uint32{}
	for k, v := range b.Properties {
		props[fmt.Sprintf("0x%08X", k)] = v
	}
	steps := []func() error{
		func() error { return addJSON("manifest.json", b.Manifest) },
		func() error { return add("README.txt", []byte(readme)) },
		func() error { return addJSON("tpm/properties.json", props) },
		func() error { return addJSON("tpm/info.json", b.Info()) },
		func() error { return addJSON("tpm/nv.json", b.NV) },
	}
	for _, r := range b.NV {
		if r.data != nil {
			steps = append(steps, func() error { return add(r.Data, r.data) })
		}
	}
	names := make([]string, 0, len(b.Extra))
	for n := range b.Extra {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		steps = append(steps, func() error { return add(n, b.Extra[n]) })
	}
	for _, s := range steps {
		if err := s(); err != nil {
			return cw.n, err
		}
	}
	if err := tw.Close(); err != nil {
		return cw.n, err
	}
	err := gz.Close()
	return cw.n, err
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// WriteFile writes the bundle to path.
func (b *Bundle) WriteFile(p string) error {
	var buf bytes.Buffer
	if _, err := b.WriteTo(&buf); err != nil {
		return err
	}
	return os.WriteFile(p, buf.Bytes(), 0o600)
}

// Load reads a bundle file.
func Load(p string) (*Bundle, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read reads a bundle written by WriteTo. Content files are checked against
// the recorded SHA-256.
func Read(r io.Reader) (*Bundle, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		if path.IsAbs(name) || strings.HasPrefix(name, "../") || name == ".." {
			return nil, fmt.Errorf("bundle: invalid path %q", h.Name)
		}
		if h.Size > maxFileSize || total+h.Size > maxTotalSize || len(files) >= maxFiles {
			return nil, errors.New("bundle: too large")
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileSize+1))
		if err != nil {
			return nil, fmt.Errorf("bundle: %s: %w", name, err)
		}
		total += int64(len(data))
		files[name] = data
	}

	b := &Bundle{Extra: map[string][]byte{}}
	if err := unmarshalFile(files, "manifest.json", &b.Manifest); err != nil {
		return nil, err
	}
	if b.Manifest.Format < 1 || b.Manifest.Format > FormatVersion {
		return nil, fmt.Errorf("bundle: unsupported format %d (this tool reads up to %d)", b.Manifest.Format, FormatVersion)
	}
	var props map[string]uint32
	if err := unmarshalFile(files, "tpm/properties.json", &props); err != nil {
		return nil, err
	}
	b.Properties = map[uint32]uint32{}
	for k, v := range props {
		n, err := strconv.ParseUint(k, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("bundle: property %q: %w", k, err)
		}
		b.Properties[uint32(n)] = v
	}
	if err := unmarshalFile(files, "tpm/nv.json", &b.NV); err != nil {
		return nil, err
	}
	used := map[string]bool{"manifest.json": true, "README.txt": true, "tpm/properties.json": true, "tpm/info.json": true, "tpm/nv.json": true}
	for _, r := range b.NV {
		n, err := strconv.ParseUint(r.Index, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("bundle: NV index %q: %w", r.Index, err)
		}
		r.index = uint32(n)
		if r.Data == "" {
			continue
		}
		data, ok := files[r.Data]
		if !ok {
			return nil, fmt.Errorf("bundle: %s missing", r.Data)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != r.SHA256 {
			return nil, fmt.Errorf("bundle: %s: SHA-256 mismatch", r.Data)
		}
		r.data = data
		used[r.Data] = true
	}
	for name, data := range files {
		if !used[name] {
			b.Extra[name] = data
		}
	}
	b.sortNV()
	return b, nil
}

func unmarshalFile(files map[string][]byte, name string, v any) error {
	data, ok := files[name]
	if !ok {
		return fmt.Errorf("bundle: %s missing", name)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("bundle: %s: %w", name, err)
	}
	return nil
}
