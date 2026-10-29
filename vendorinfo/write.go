package vendorinfo

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

const readme = `tpm2-verifier vendor information (tpm2-verifier debug-anon)
=====================================================

What is needed to add this TPM's vendor to the tpm2-verifier vendor store,
without data that identifies the TPM:

  info.json        TPM identity (manufacturer, firmware), NV layout without
                   content, and per EK the chain: public certificates in full,
                   device specific ones only by structure (no serial number,
                   key, signature, key identifiers, fingerprint or dates;
                   device specific name values redacted)
  certs/           public CA certificates (vendor store, AIA downloads)
  vendor/<id>/     draft vendor directory: vendor.yaml, README.md, roots/,
                   intermediates/; usable as overlay: tpm2-verifier info -store vendor

Not included: EK certificates, per-device CA certificates, NV content,
serial numbers, keys.
`

// Files returns every file of the vendor information by relative path.
func (info *Info) Files() (map[string][]byte, error) {
	out := map[string][]byte{"README.txt": []byte(readme)}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	out["info.json"] = append(data, '\n')
	for k, v := range info.files {
		out[k] = v
	}
	return out, nil
}

// WriteArchive writes the vendor information as .tar.gz.
func (info *Info) WriteArchive(w io.Writer) error {
	files, err := info.Files()
	if err != nil {
		return err
	}
	mtime, _ := time.Parse(time.DateOnly, info.Created)
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, name := range sortedKeys(files) {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: mtime, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// WriteDir writes the vendor information into directory dir.
func (info *Info) WriteDir(dir string) error {
	files, err := info.Files()
	if err != nil {
		return err
	}
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
