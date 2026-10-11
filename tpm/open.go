package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// Open opens a TPM by spec. The spec uses the TCTI syntax of tpm2-tools:
//
//	""                              TPM2TOOLS_TCTI / TSS2_TCTI if set, else the platform TPM
//	                                (Linux: /dev/tpmrm0, falling back to /dev/tpm0; Windows: TBS)
//	device:/dev/tpmrm0, /dev/tpm0   a TPM character device (Linux)
//	swtpm:host=localhost,port=2321  swtpm socket with --server type=tcp
//	swtpm:path=/run/swtpm.sock      swtpm socket with --server type=unixio
//	tbs                             Windows TPM Base Services
func Open(spec string) (*TPM, error) {
	if spec == "" {
		spec = os.Getenv("TPM2TOOLS_TCTI")
	}
	if spec == "" {
		spec = os.Getenv("TSS2_TCTI")
	}
	t, err := openTransport(spec)
	if err != nil {
		return nil, err
	}
	return New(NewDevice(t)), nil
}

func openTransport(spec string) (transport.TPMCloser, error) {
	name, conf, _ := strings.Cut(spec, ":")
	switch {
	case spec == "":
		return openDefault()
	case strings.HasPrefix(spec, "/"):
		return openDevice(spec)
	case name == "device":
		if conf == "" {
			return openDefault()
		}
		return openDevice(conf)
	case name == "tbs":
		return openDefault()
	case name == "swtpm":
		return openSwtpm(conf)
	}
	return nil, fmt.Errorf("tpm: unsupported TPM spec %q (use device:<path>, swtpm:host=..,port=.., swtpm:path=.. or tbs)", spec)
}

func openSwtpm(conf string) (transport.TPMCloser, error) {
	opts := map[string]string{"host": "localhost", "port": "2321"}
	for _, kv := range strings.Split(conf, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			opts[k] = v
		}
	}
	network, addr := "tcp", net.JoinHostPort(opts["host"], opts["port"])
	if p, ok := opts["path"]; ok {
		network, addr = "unix", p
	}
	conn, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tpm: swtpm: %w", err)
	}
	return &streamTPM{conn: conn}, nil
}

// streamTPM sends raw TPM commands over a stream connection, the protocol of
// swtpm's server socket.
type streamTPM struct {
	mu   sync.Mutex
	conn net.Conn
}

const maxResponse = 64 << 10

func (s *streamTPM) Send(cmd []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if _, err := s.conn.Write(cmd); err != nil {
		return nil, err
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[2:6])
	if size < 10 || size > maxResponse {
		return nil, fmt.Errorf("tpm: invalid response size %d", size)
	}
	rsp := make([]byte, size)
	copy(rsp, hdr)
	if _, err := io.ReadFull(s.conn, rsp[10:]); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (s *streamTPM) Close() error { return s.conn.Close() }

// PermissionHint explains common open errors.
func PermissionHint(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission denied: run as root or add your user to the 'tss' group"
	case errors.Is(err, os.ErrNotExist):
		return "no TPM device found: check that the TPM is enabled in the firmware setup (Intel PTT / AMD fTPM)"
	}
	return ""
}
