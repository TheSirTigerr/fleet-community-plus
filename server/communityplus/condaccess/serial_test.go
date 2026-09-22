package condaccess

import (
	"testing"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/stretchr/testify/require"
)

func TestParseCertificateSerial(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		format string
		want   uint64
	}{
		{name: "hex", raw: "DEADBEEF", format: config.CertSerialFormatHex, want: 0xDEADBEEF},
		{name: "hex separators", raw: "DE:AD:BE:EF", format: config.CertSerialFormatHex, want: 0xDEADBEEF},
		{name: "hex spaces", raw: " DE AD BE EF ", format: config.CertSerialFormatHex, want: 0xDEADBEEF},
		{name: "decimal", raw: "123456", format: config.CertSerialFormatDecimal, want: 123456},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCertificateSerial(tt.raw, tt.format)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseCertificateSerialRejectsInvalidInput(t *testing.T) {
	_, err := parseCertificateSerial("", config.CertSerialFormatHex)
	require.Error(t, err)

	_, err = parseCertificateSerial("not-a-serial", config.CertSerialFormatHex)
	require.Error(t, err)

	_, err = parseCertificateSerial("FFFFFFFFFFFFFFFFF", config.CertSerialFormatHex)
	require.Error(t, err)
}
