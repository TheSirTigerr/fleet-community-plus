package condaccess

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fleetdm/fleet/v4/server/config"
)

// parseCertificateSerial converts the serial representation forwarded by the
// TLS terminator to Fleet's datastore key. Common separators are accepted so
// ALB/Caddy-style header formatting does not change the certificate identity.
func parseCertificateSerial(raw, format string) (uint64, error) {
	serial := strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(raw))
	if serial == "" {
		return 0, fmt.Errorf("certificate serial is empty")
	}

	base := 16
	if format == config.CertSerialFormatDecimal {
		base = 10
	}
	value, err := strconv.ParseUint(serial, base, 64)
	if err != nil {
		return 0, fmt.Errorf("parse certificate serial (%s): %w", format, err)
	}
	return value, nil
}
