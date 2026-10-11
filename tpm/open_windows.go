package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openDefault opens the TPM through TPM Base Services.
func openDefault() (transport.TPMCloser, error) { return windowstpm.Open() }

func openDevice(path string) (transport.TPMCloser, error) {
	return nil, fmt.Errorf("tpm: device paths are not supported on Windows (%s); use the default or tbs", path)
}
