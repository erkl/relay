package relay

import (
	"github.com/erkl/heat"
)

type Proxy struct {
	RoundTrip func(req *heat.Request) (*heat.Response, error)
}
