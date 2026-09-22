package condaccess

import "testing"

func TestConditionalAccessIdPCompatibilityBoundary(t *testing.T) {
	placeholder := struct{}{}
	if err := RegisterIdP(placeholder, placeholder, placeholder, placeholder, placeholder); err != nil {
		t.Fatalf("register IdP compatibility boundary: %v", err)
	}
}
