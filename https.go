package relay

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"

	"github.com/erkl/heat"
	"github.com/erkl/xo"
)

func (p *Proxy) connect(conn net.Conn, rw xo.ReadWriter, req *heat.Request) error {
	// Make sure we have a valid certificate.
	if p.Authority == nil || len(p.Authority.Certificate) == 0 {
		resp := statusResponse(500, "Can't serve CONNECT requests without Proxy.Authority.", req.URI)
		return writeResponse(rw, resp, req.Method)
	}

	// Validate the tunnel address.
	host, port, err := net.SplitHostPort(req.URI)
	if err != nil || port != "443" {
		resp := statusResponse(400, "Invalid CONNECT address: %s.", req.URI)
		return writeResponse(rw, resp, req.Method)
	}

	// Forge a certificate for the remote host.
	cert, err := p.forge(host)
	if err != nil {
		resp := statusResponse(500, "Error when signing SSL certificate: %s.", err)
		return writeResponse(rw, resp, req.Method)
	}

	// Grab the currently buffered data.
	peek, err := rw.Peek(0)
	if err != nil {
		resp := statusResponse(500, "Internal error: %s.", err)
		return writeResponse(rw, resp, req.Method)
	}

	if len(peek) > 0 {
		conn = &prefixed{conn, peek}
	}

	// Indicate that the tunnel is ready.
	if _, err = rw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return err
	}
	if err = rw.Flush(); err != nil {
		return err
	}

	// Carry out the TLS handshake.
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})

	if err = tlsConn.Handshake(); err != nil {
		return err
	}

	return p.serveHTTPS(tlsConn, req.URI)
}

func (p *Proxy) serveHTTPS(conn net.Conn, addr string) error {
	rw := xo.NewReadWriter(
		xo.NewReader(conn, make([]byte, 4096)),
		xo.NewWriter(conn, make([]byte, 4096)),
	)

	for {
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

		// Populate the scheme and remote address.
		req.Scheme = "https"
		req.Remote = addr

		// Will the client close this connection after receiving a response?
		closing := heat.Closing(req.Major, req.Minor, req.Fields)

		// Forward the request to the upstream server.
		resp, err := p.forward(req)
		if err != nil {
			resp = statusResponse(500, "Round-trip to upstream failed: %s.", err)
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

func (p *Proxy) forward(req *heat.Request) (*heat.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}

	// Enable keep-alive connections for outgoing requests.
	isKeepAlive := !heat.Closing(req.Major, req.Minor, req.Fields)
	req.Fields.Set("Connection", "keep-alive")

	// Issue the request.
	resp, err := p.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Does the client expect the connection to be closed?
	if !isKeepAlive {
		resp.Fields.Set("Connection", "close")
	} else {
		resp.Fields.Set("Connection", "keep-alive")
	}

	return resp, nil
}

func (p *Proxy) forge(host string) (*tls.Certificate, error) {
	x509ca, err := x509.ParseCertificate(p.Authority.Certificate[0])
	if err != nil {
		return nil, err
	}

	// By deriving a seed from the hostname we can use consistent serial
	// numbers and encryption keys without having to store any state.
	seed := sha256.Sum256([]byte(host))

	serial := &big.Int{}
	serial.SetBytes(seed[:])

	// Create a certificate template.
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      x509ca.Subject,
		NotBefore:    x509ca.NotBefore,
		NotAfter:     x509ca.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// Generate the certificate.
	rng := &inf{append(([]byte)(nil), seed[:]...)}

	key, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rng, template, x509ca, &key.PublicKey, p.Authority.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, p.Authority.Certificate[0]},
		PrivateKey:  key,
	}, nil
}

// The inf struct generates an infinite stream of "random-looking", but highly
// predictable, data by repeatedly stretching its state SHA-256.
type inf struct {
	state []byte
}

func (i inf) Read(buf []byte) (int, error) {
	h := sha256.New()

	for n := 0; n < len(buf); {
		h.Write(i.state)
		i.state = h.Sum(i.state[:0])
		n += copy(buf[n:], i.state)
		h.Reset()
	}

	return len(buf), nil
}
