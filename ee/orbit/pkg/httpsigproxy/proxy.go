// Package httpsigproxy is a compatibility facade for the Community+ Orbit
// HTTP-signature proxy boundary.
package httpsigproxy

import (
	communityhttpsigproxy "github.com/fleetdm/fleet/v4/orbit/pkg/communityplus/httpsigproxy"
	httpsig "github.com/remitly-oss/httpsig-go"
)

var ErrUnavailable = communityhttpsigproxy.ErrUnavailable

type Proxy = communityhttpsigproxy.Proxy

func NewProxy(rootDir, fleetURL, certPath string, insecure bool, signer *httpsig.Signer) (*Proxy, error) {
	return communityhttpsigproxy.NewProxy(rootDir, fleetURL, certPath, insecure, signer)
}
