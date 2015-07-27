package relay

import (
	"crypto/tls"

	"github.com/erkl/heat"
)

type Proxy struct {
	// If specified, this certificate will be used to sign SSL certificates
	// for all HTTPS domains. If nil, HTTPS tunneling won't be supported.
	Authority *tls.Certificate

	// Function used to serve HTTP requests. Must not be nil.
	RoundTrip func(req *heat.Request) (*heat.Response, error)
}
