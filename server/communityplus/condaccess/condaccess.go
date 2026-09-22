// Package condaccess implements Community+ conditional-access integrations.
package condaccess

// RegisterIdP remains the compatibility boundary for the Okta SAML IdP while
// the Community+ implementation is being wired. Unlike the SCEP path, it does
// not mount routes yet.
func RegisterIdP(_ any, _ any, _ any, _ any, _ any) error { return nil }
