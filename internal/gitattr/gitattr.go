// Package gitattr is a test helper: it checks that files whose bytes are
// hashed or signed are checked out as they are, with git's text attribute
// unset (.gitattributes), so that no checkout - Windows' core.autocrlf
// above all - converts their line endings.
package gitattr

import (
	"bytes"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"testing"
)

// RequireBinary fails t for every file under each root (a file or a
// directory, relative to the test's working directory) that git would
// convert at checkout. Outside a git work tree, or without git, it skips:
// a build from a source archive has nothing to convert.
func RequireBinary(t testing.TB, roots ...string) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git: the checkout's attributes cannot be asked")
	}
	if out, err := exec.Command(git, "rev-parse", "--is-inside-work-tree").Output(); err != nil || !bytes.Equal(bytes.TrimSpace(out), []byte("true")) {
		t.Skip("not in a git work tree")
	}
	var paths []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				paths = append(paths, filepath.ToSlash(p))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", root, err)
		}
	}
	if len(paths) == 0 {
		t.Fatalf("no files under %v", roots)
	}
	out, err := exec.Command(git, append([]string{"check-attr", "-z", "text", "--"}, paths...)...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("git check-attr: %v: %s", err, ee.Stderr)
		}
		t.Fatalf("git check-attr: %v", err)
	}
	// -z: path NUL attribute NUL value NUL, per path.
	f := bytes.Split(bytes.TrimSuffix(out, []byte{0}), []byte{0})
	if len(f) != 3*len(paths) {
		t.Fatalf("git check-attr: %d fields for %d paths", len(f), len(paths))
	}
	for i := 0; i < len(f); i += 3 {
		if v := string(f[i+2]); v != "unset" {
			t.Errorf("%s: text is %q, not unset: a checkout may convert its line endings and break its hash or signature (.gitattributes: -text)", f[i], v)
		}
	}
}
