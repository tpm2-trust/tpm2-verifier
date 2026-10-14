// Package manifest protects the vendor data directory: a MANIFEST file at its
// top lists the SHA-256 of every file and a version, and MANIFEST.sig is an
// SSH signature of the MANIFEST (ssh-keygen -Y sign, namespace
// "tpm2-verifier-vendors") by a key compiled into the binary.
//
// The MANIFEST uses the sha256sum format with comment lines, so it can also
// be checked with "sha256sum -c MANIFEST" and the signature with
// "ssh-keygen -Y verify".
package manifest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing/fstest"
	"time"
)

const (
	// File is the name of the manifest at the top of the vendor directory.
	File = "MANIFEST"
	// SigFile is the name of the signature of File.
	SigFile = "MANIFEST.sig"
	// Namespace is the ssh-keygen -n namespace of the signature.
	Namespace = "tpm2-verifier-vendors"
)

// Manifest lists the files of a vendor directory.
type Manifest struct {
	Version string
	Files   []FileHash // sorted by path
}

// FileHash is one file of the manifest; Path is relative, with slashes.
type FileHash struct {
	Path   string
	SHA256 string
}

var versionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)

// Parse reads a manifest.
func Parse(data []byte) (*Manifest, error) {
	m := &Manifest{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "# version:"); ok {
			m.Version = strings.TrimSpace(v)
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, p, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || !isHex(sum) {
			return nil, fmt.Errorf("%s line %d: expected \"<sha256>  <path>\"", File, n)
		}
		if !validPath(p) {
			return nil, fmt.Errorf("%s line %d: invalid path %q", File, n, p)
		}
		if len(m.Files) > 0 && m.Files[len(m.Files)-1].Path >= p {
			return nil, fmt.Errorf("%s line %d: paths not sorted or duplicate", File, n)
		}
		m.Files = append(m.Files, FileHash{Path: p, SHA256: strings.ToLower(sum)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !versionRE.MatchString(m.Version) {
		return nil, fmt.Errorf("%s: missing or invalid \"# version:\" line", File)
	}
	return m, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func validPath(p string) bool {
	return fs.ValidPath(p) && p != "." && p != File && p != SigFile && !strings.ContainsAny(p, "\\\n\r")
}

// Marshal encodes the manifest.
func (m *Manifest) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString("# tpm2-verifier vendor data. Check with: sha256sum -c MANIFEST\n")
	fmt.Fprintf(&b, "# version: %s\n", m.Version)
	for _, f := range m.Files {
		fmt.Fprintf(&b, "%s  %s\n", f.SHA256, f.Path)
	}
	return b.Bytes()
}

// read returns every file of dir except the manifest and its signature,
// keyed by slash separated path. Only regular files and directories are
// allowed.
func read(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%s: not a regular file", rel)
		case rel == File || rel == SigFile:
			return nil
		case !validPath(rel):
			return fmt.Errorf("%s: unsupported file name", rel)
		}
		data, err := os.ReadFile(p)
		files[rel] = data
		return err
	})
	return files, err
}

func hashes(files map[string][]byte) []FileHash {
	var out []FileHash
	for p, data := range files {
		sum := sha256.Sum256(data)
		out = append(out, FileHash{Path: p, SHA256: hex.EncodeToString(sum[:])})
	}
	slices.SortFunc(out, func(a, b FileHash) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// Generate returns the manifest of dir with the given version.
func Generate(dir, version string) (*Manifest, error) {
	files, err := read(dir)
	if err != nil {
		return nil, err
	}
	return &Manifest{Version: version, Files: hashes(files)}, nil
}

// NextVersion returns the version for data changed at now: the UTC date
// (2026.10.14), with a counter if prev is from the same day (2026.10.14.2).
func NextVersion(prev string, now time.Time) string {
	day := now.UTC().Format("2006.01.02")
	if prev == day {
		return day + ".2"
	}
	if n, ok := strings.CutPrefix(prev, day+"."); ok {
		if i, err := strconv.Atoi(n); err == nil {
			return fmt.Sprintf("%s.%d", day, i+1)
		}
	}
	return day
}

// Update computes the manifest of dir. If the files differ from the current
// manifest (or there is none, or version is set), it returns the new
// manifest with version, or the next version, and changed = true; the caller
// writes it and removes the signature, which no longer matches.
func Update(dir, version string, now time.Time) (m *Manifest, changed bool, err error) {
	var cur *Manifest
	if data, err := os.ReadFile(filepath.Join(dir, File)); err == nil {
		if cur, err = Parse(data); err != nil {
			return nil, false, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if version != "" && !versionRE.MatchString(version) {
		return nil, false, fmt.Errorf("invalid version %q", version)
	}
	m, err = Generate(dir, version)
	if err != nil {
		return nil, false, err
	}
	if cur != nil && slices.Equal(cur.Files, m.Files) && (version == "" || version == cur.Version) {
		return cur, false, nil
	}
	if version == "" {
		prev := ""
		if cur != nil {
			prev = cur.Version
		}
		m.Version = NextVersion(prev, now)
	}
	return m, true, nil
}

// Status of the vendor data signature.
type Status string

const (
	// StatusSigned: signed by a trusted key.
	StatusSigned Status = "signed"
	// StatusUntrustedKey: signed, but by a key that is not trusted.
	StatusUntrustedKey Status = "signed by an untrusted key"
	// StatusUnsigned: a manifest without signature.
	StatusUnsigned Status = "unsigned"
	// StatusNoManifest: no manifest; the files are not checked.
	StatusNoManifest Status = "no manifest"
)

// Result describes verified vendor data.
type Result struct {
	Dir     string
	Status  Status
	Version string // empty without manifest
	// Digest is the SHA-256 of the MANIFEST file.
	Digest string
	Files  int
	// Signer is the trusted signer (StatusSigned).
	Signer *Signer
	// KeyFingerprint is the signing key (SHA256:... as ssh-keygen -l shows).
	KeyFingerprint string
	// FS holds the verified content, read once: load from it, not from Dir,
	// so files changed after the check are not used.
	FS fs.FS
}

// Trusted reports whether the data is signed by a trusted key.
func (r *Result) Trusted() bool { return r.Status == StatusSigned }

// Describe returns a one-line summary such as
// "version 2026.10.14, 6 files, signed by maintainer (SHA256:...)".
func (r *Result) Describe() string {
	if r.Status == StatusNoManifest {
		return fmt.Sprintf("%d files, no %s", r.Files, File)
	}
	s := fmt.Sprintf("version %s, %d files, manifest sha256 %s, ", r.Version, r.Files, r.Digest[:16])
	switch r.Status {
	case StatusSigned:
		return s + fmt.Sprintf("signed by %s (%s)", r.Signer.Principal, r.KeyFingerprint)
	case StatusUntrustedKey:
		return s + fmt.Sprintf("signed by an untrusted key (%s)", r.KeyFingerprint)
	}
	return s + "unsigned"
}

// Verify checks dir against its manifest and signature. Files missing from
// the manifest, missing files, changed files and a signature that does not
// verify are errors. A missing manifest or signature, or a signature by a
// key not in signers, is reported in Result.Status; the caller decides
// whether to accept it.
func Verify(dir string, signers []Signer) (*Result, error) {
	files, err := read(dir)
	if err != nil {
		return nil, err
	}
	mfs := fstest.MapFS{}
	for p, data := range files {
		mfs[p] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	r := &Result{Dir: dir, Status: StatusNoManifest, Files: len(files), FS: mfs}
	raw, err := os.ReadFile(filepath.Join(dir, File))
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Stat(filepath.Join(dir, SigFile)); err == nil {
			return nil, fmt.Errorf("%s without %s", SigFile, File)
		}
		return r, nil
	} else if err != nil {
		return nil, err
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	r.Version, r.Digest, r.Status = m.Version, hex.EncodeToString(sum[:]), StatusUnsigned

	var errs []error
	got := hashes(files)
	for _, f := range m.Files {
		i, ok := slices.BinarySearchFunc(got, f.Path, func(h FileHash, p string) int { return strings.Compare(h.Path, p) })
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: listed in %s but missing", f.Path, File))
		case got[i].SHA256 != f.SHA256:
			errs = append(errs, fmt.Errorf("%s: sha256 %s, %s lists %s", f.Path, got[i].SHA256, File, f.SHA256))
		}
	}
	for _, g := range got {
		if !slices.ContainsFunc(m.Files, func(f FileHash) bool { return f.Path == g.Path }) {
			errs = append(errs, fmt.Errorf("%s: not listed in %s", g.Path, File))
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s does not match the files (run tpm2-verifier store manifest after changes): %w", File, errors.Join(errs...))
	}

	sig, err := os.ReadFile(filepath.Join(dir, SigFile))
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	} else if err != nil {
		return nil, err
	}
	key, err := VerifySSHSig(raw, sig, Namespace)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SigFile, err)
	}
	r.KeyFingerprint, r.Status = key.Fingerprint(), StatusUntrustedKey
	for i, s := range signers {
		if s.Key.Equal(key) {
			r.Signer, r.Status = &signers[i], StatusSigned
			break
		}
	}
	return r, nil
}
