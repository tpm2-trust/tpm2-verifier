package bundle

import (
	"os"
	"path/filepath"
	"strings"
)

// platformInfo collects the kernel release, TPM sysfs attributes and DMI
// vendor/model strings. Serial numbers and UUIDs are deliberately omitted.
func platformInfo() (string, map[string]string) {
	out := map[string]string{}
	read := func(key, p string) {
		if b, err := os.ReadFile(p); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				out[key] = v
			}
		}
	}
	link := func(key, p string) {
		if t, err := os.Readlink(p); err == nil {
			out[key] = filepath.Base(t)
		}
	}
	for _, f := range []string{
		"tpm_version_major", "device/description", "device/hid", "device/modalias",
		"device/firmware_node/hid", "device/firmware_node/description", "device/firmware_node/path",
	} {
		read("tpm0/"+f, "/sys/class/tpm/tpm0/"+f)
	}
	link("tpm0/driver", "/sys/class/tpm/tpm0/device/driver")
	for _, f := range []string{
		"sys_vendor", "product_name", "product_version", "product_family",
		"board_vendor", "board_name", "bios_vendor", "bios_version", "bios_date",
	} {
		read("dmi/"+f, "/sys/class/dmi/id/"+f)
	}
	kernel := ""
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(b))
	}
	return kernel, out
}
