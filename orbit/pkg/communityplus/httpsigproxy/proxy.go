// Package httpsigproxy is the local signed-proxy boundary for Community+ Orbit.
package httpsigproxy

import (
	"errors"
	"net/url"

	httpsig "github.com/remitly-oss/httpsig-go"
)

var ErrUnavailable = errors.New("Community+ Orbit HTTP-signature proxy is unavailable")

type Proxy struct {
	ParsedURL       *url.URL
	CertificatePath string
}

func NewProxy(_ string, _ string, _ string, _ bool, _ *httpsig.Signer) (*Proxy, error) {
	return nil, ErrUnavailable
}

func (p *Proxy) Serve() error { return ErrUnavailable }

func (p *Proxy) Close() error { return nil }
