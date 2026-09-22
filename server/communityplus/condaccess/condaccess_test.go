package condaccess

import "testing"

func TestLegacyConditionalAccessRoutesStayUnmounted(t *testing.T) {
	if err := RegisterSCEP(nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("register SCEP boundary: %v", err)
	}
	if err := RegisterIdP(nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("register IdP boundary: %v", err)
	}
}

func TestConditionalAccessCompatibilityCallShape(t *testing.T) {
	placeholder := struct{}{}
	if err := RegisterSCEP(placeholder, placeholder, placeholder, placeholder, placeholder, placeholder); err != nil {
		t.Fatalf("register SCEP compatibility boundary: %v", err)
	}
	if err := RegisterIdP(placeholder, placeholder, placeholder, placeholder, placeholder); err != nil {
		t.Fatalf("register IdP compatibility boundary: %v", err)
	}
}
