//go:build !linux && !windows

package tpm

import (
	"fmt"
	"runtime"

	"github.com/google/go-tpm/tpm2/transport"
)

func openDefault() (transport.TPMCloser, error) {
	return nil, fmt.Errorf("tpm: no platform TPM support on %s; use swtpm:...", runtime.GOOS)
}

func openDevice(path string) (transport.TPMCloser, error) { return openDefault() }
