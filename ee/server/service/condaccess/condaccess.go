// Package condaccess is a compatibility boundary for the Community+ build.
package condaccess

// RegisterSCEP intentionally registers no legacy premium routes.
func RegisterSCEP(_ any, _ any, _ any, _ any, _ any, _ any) error { return nil }

// RegisterIdP intentionally registers no legacy premium routes.
func RegisterIdP(_ any, _ any, _ any, _ any, _ any) error { return nil }
