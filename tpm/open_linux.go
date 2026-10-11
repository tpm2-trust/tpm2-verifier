package tpm

import (
	"errors"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// openDefault prefers the kernel resource manager, which avoids conflicts
// with other TPM users (e.g. tpm2-abrmd, systemd).
func openDefault() (transport.TPMCloser, error) {
	t, err := linuxtpm.Open("/dev/tpmrm0")
	if err == nil {
		return t, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return linuxtpm.Open("/dev/tpm0")
	}
	return nil, err
}

func openDevice(path string) (transport.TPMCloser, error) { return linuxtpm.Open(path) }
