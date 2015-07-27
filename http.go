package relay

import (
	"io"
	"net"
	"net/url"
	"strconv"

	"github.com/erkl/heat"
	"github.com/erkl/xo"
)

func (p *Proxy) serveHTTP(conn net.Conn) error {
	rw := xo.NewReadWriter(
		xo.NewReader(conn, make([]byte, 4096)),
		xo.NewWriter(conn, make([]byte, 4096)),
	)

	for {
		// Read the next request.
		req, body, err := readRequest(rw)
		if err != nil {
			switch err {
			case heat.ErrRequestHeader:
				resp := statusResponse(404, "Malformed HTTP request header.")
				return writeResponse(rw, resp, req.Method)

			case heat.ErrRequestVersion:
				resp := statusResponse(505, "Unsupported HTTP version number.")
				return writeResponse(rw, resp, req.Method)

			// If the connection terminated cleanly, stop.
			case io.EOF:
				return nil

			// Any other error would be from the underlying connection, and
			// should be propagated.
			default:
				return err
			}
		}

		// Support CONNECT tunneling.
		if req.Method == "CONNECT" {
			// TODO: Set up a tunnel.
			return nil
		}

		// Will the client close this connection after receiving a response?
		closing := heat.Closing(req.Major, req.Minor, req.Fields)

		// Fetch the actual response from the upstream server.
		resp, err := p.proxy(req)
		if err != nil {
			resp := statusResponse(500, "Unknown error: %s.", err)
			return writeResponse(rw, resp, req.Method)
		}

		// Are we closing the connection after sending the response?
		if !closing && (body == nil || body.LastError() == io.EOF) {
			resp.Fields.Set("Connection", "keep-alive")
		} else {
			resp.Fields.Set("Connection", "close")
			closing = true
		}

		// Write the response.
		err = writeResponse(rw, resp, req.Method)
		if err != nil {
			return err
		}

		// Stop if the connection isn't keep-alive.
		if closing {
			return nil
		}
	}
}

func (p *Proxy) proxy(req *heat.Request) (*heat.Response, error) {
	// Extract the destination URL.
	u, err := url.ParseRequestURI(req.URI)
	if err != nil {
		return statusResponse(400, "Invalid URI in request."), nil
	}

	// Make sure the request's URI is absolute.
	if !u.IsAbs() {
		return statusResponse(400, "Request URI must be absolute."), nil
	}

	// Clean the request.
	err = scrubRequest(req)
	if err != nil {
		return statusResponse(500, "Could not scrub request."), nil
	}

	// Update the request to reflect the actual destination.
	req.URI = u.RequestURI()
	req.Scheme = u.Scheme
	req.Remote = u.Host

	// Issue the actual request.
	resp, err := p.RoundTrip(req)
	if err != nil {
		return statusResponse(500, "Round-trip to upstream failed: %s.", err), nil
	}

	// Clean the response.
	err = scrubResponse(resp, req.Method)
	if err != nil {
		return statusResponse(500, "Could not scrub response."), nil
	}

	return resp, nil
}

func scrubRequest(req *heat.Request) error {
	// Only ever send HTTP/1.1 requests.
	req.Major = 1
	req.Minor = 1

	// Work out the request body size.
	size, err := heat.RequestBodySize(req)
	if err != nil {
		return err
	}

	scrubHeaderFields(&req.Fields, size)
	return nil
}

func scrubResponse(resp *heat.Response, method string) error {
	// Only ever send HTTP/1.1 responses.
	resp.Major = 1
	resp.Minor = 1

	// Work out the response body size.
	size, err := heat.ResponseBodySize(resp, method)
	if err != nil {
		return err
	}

	scrubHeaderFields(&resp.Fields, size)
	return nil
}

var blacklist = []string{
	// Hop-by-hop headers defined in section 13.5.1 of RFC 2616.
	"Connection",
	"Keep-Alive",
	"Public",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",

	// The "Proxy-Connection" header isn't part of any standard, but
	// nevertheless added by some browsers.
	"Proxy-Connection",

	// Remove "Content-Length" header fields as we'll end up overwriting
	// or removing them anyway.
	"Content-Length",
}

func scrubHeaderFields(fields *heat.Fields, size heat.BodySize) {
	// Prepare a list of "connection-tokens", describing header fields, to be
	// removed as per section 14.10 of RFC 2616.
	tokens := fields.Split("Connection", ',')

	// Remove the header fields we don't want to forward.
	fields.Filter(func(f heat.Field) bool {
		for _, name := range blacklist {
			if f.Is(name) {
				return false
			}
		}

		for _, name := range tokens {
			if f.Is(name) {
				return false
			}
		}

		return true
	})

	// Indicate the transfer-length.
	if size >= 0 {
		fields.Add("Content-Length", strconv.FormatInt(int64(size), 10))
	} else {
		fields.Add("Transfer-Encoding", "chunked")
	}
}
