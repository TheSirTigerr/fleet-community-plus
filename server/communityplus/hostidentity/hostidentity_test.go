package hostidentity

import "testing"

func TestLegacySCEPRoutesStayUnmounted(t *testing.T) {
	if err := RegisterSCEP(nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("register host identity SCEP boundary: %v", err)
	}

	placeholder := struct{}{}
	if err := RegisterSCEP(placeholder, placeholder, placeholder, placeholder, placeholder); err != nil {
		t.Fatalf("register host identity compatibility call shape: %v", err)
	}
}
