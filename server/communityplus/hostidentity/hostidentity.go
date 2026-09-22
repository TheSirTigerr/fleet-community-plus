// Package hostidentity provides Community+'s host-identity registration boundary.
package hostidentity

// RegisterSCEP intentionally leaves the historical premium host-identity SCEP
// routes unmounted. Community+ host identity is authenticated through its own
// capability-gated certificate and HTTP-signature implementation.
func RegisterSCEP(_ any, _ any, _ any, _ any, _ any) error { return nil }
