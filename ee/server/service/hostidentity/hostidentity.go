// Package hostidentity is a compatibility boundary for the Community+ build.
package hostidentity

// RegisterSCEP intentionally registers no routes. Community+ exposes host
// identity through its own capability gate; the legacy premium gate is closed.
func RegisterSCEP(_ any, _ any, _ any, _ any, _ any) error { return nil }
