// Package condaccess provides Community+'s conditional-access registration boundary.
package condaccess

// RegisterSCEP intentionally leaves legacy premium conditional-access SCEP
// routes unmounted until the Community+ implementation is complete.
func RegisterSCEP(_ any, _ any, _ any, _ any, _ any, _ any) error { return nil }

// RegisterIdP intentionally leaves legacy premium IdP routes unmounted until
// the Community+ implementation is complete.
func RegisterIdP(_ any, _ any, _ any, _ any, _ any) error { return nil }
