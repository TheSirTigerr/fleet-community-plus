package communityplus

import "testing"

func TestSuccessfulWindowsInstallerExitCode(t *testing.T) {
	for _, code := range []int{0, 1641, 3010} {
		if !successfulWindowsInstallerExitCode(code) {
			t.Fatalf("expected exit code %d to be successful", code)
		}
	}
	for _, code := range []int{1, 2, 1603, 1618} {
		if successfulWindowsInstallerExitCode(code) {
			t.Fatalf("expected exit code %d to fail", code)
		}
	}
}
