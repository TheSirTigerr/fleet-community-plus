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
