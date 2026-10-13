package vendorinfo

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// Limits when reading vendor information, which usually comes from others.
const (
	maxFileSize  = 4 << 20
	maxTotalSize = 32 << 20
	maxFiles     = 1024
)

// Load reads vendor information written by WriteArchive (.tar.gz) or
// WriteDir (a directory).
func Load(p string) (*Info, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return ReadFS(os.DirFS(p))
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read reads a .tar.gz written by WriteArchive.
func Read(r io.Reader) (*Info, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("vendorinfo: %w", err)
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
			return nil, fmt.Errorf("vendorinfo: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if err := add(files, &total, h.Name, h.Size, io.LimitReader(tr, maxFileSize+1)); err != nil {
			return nil, err
		}
	}
	return parse(files)
}

// ReadFS reads vendor information from a directory tree.
func ReadFS(fsys fs.FS) (*Info, error) {
	files := map[string][]byte{}
	var total int64
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		return add(files, &total, p, fi.Size(), io.LimitReader(f, maxFileSize+1))
	})
	if err != nil {
		return nil, err
	}
	return parse(files)
}

func add(files map[string][]byte, total *int64, name string, size int64, r io.Reader) error {
	name = path.Clean(name)
	if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("vendorinfo: invalid path %q", name)
	}
	if size > maxFileSize || *total+size > maxTotalSize || len(files) >= maxFiles {
		return errors.New("vendorinfo: too large")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vendorinfo: %s: %w", name, err)
	}
	if len(data) > maxFileSize {
		return errors.New("vendorinfo: too large")
	}
	*total += int64(len(data))
	files[name] = data
	return nil
}

func parse(files map[string][]byte) (*Info, error) {
	raw, ok := files["info.json"]
	if !ok {
		return nil, errors.New("vendorinfo: info.json missing (not tpm2-ek debug-anon output)")
	}
	var info Info
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("vendorinfo: info.json: %w", err)
	}
	if info.Format < 1 || info.Format > FormatVersion {
		return nil, fmt.Errorf("vendorinfo: unsupported format %d (this tool reads up to %d)", info.Format, FormatVersion)
	}
	if info.TPM == nil {
		return nil, errors.New("vendorinfo: info.json has no TPM information")
	}
	info.files = map[string][]byte{}
	for _, c := range info.Certificates {
		want := "certs/" + strings.ToLower(c.SHA256) + ".der"
		data, ok := files[want]
		if c.File != want || !ok {
			return nil, fmt.Errorf("vendorinfo: certificate %s: file %s missing", c.SHA256, want)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != strings.ToLower(c.SHA256) {
			return nil, fmt.Errorf("vendorinfo: %s: SHA-256 mismatch", want)
		}
		info.files[want] = data
	}
	return &info, nil
}

// Certificate returns the DER of an included public certificate.
func (info *Info) Certificate(sha256 string) []byte {
	return info.files["certs/"+strings.ToLower(sha256)+".der"]
}
