//go:build !linux

package bundle

func platformInfo() (string, map[string]string) { return "", nil }
