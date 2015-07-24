package relay

import (
	"errors"
	"io"

	"github.com/erkl/heat"
	"github.com/erkl/xo"
)

// readRequest reads an HTTP request.
func readRequest(r xo.Reader) (*heat.Request, *bodyReader, error) {
	req, err := heat.ReadRequestHeader(r)
	if err != nil {
		return nil, nil, err
	}

	size, err := heat.RequestBodySize(req)
	if err != nil {
		return nil, nil, err
	}

	var body *bodyReader

	if size != 0 {
		r, _ := heat.OpenBody(r, size)
		body = &bodyReader{r: r}
		req.Body = body
	}

	return req, body, nil
}

// writeResponse writes an HTTP response.
func writeResponse(w xo.Writer, resp *heat.Response, method string) error {
	size, err := heat.ResponseBodySize(resp, method)
	if err != nil {
		return err
	}

	if err = heat.WriteResponseHeader(w, resp); err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}

	if size != 0 {
		if err = heat.WriteBody(w, resp.Body, size); err != nil {
			return err
		}
		if err = w.Flush(); err != nil {
			return err
		}
	}

	return nil
}

var errReadAfterClose = errors.New("relay: read after close")

// The bodyReader type wraps the body of a request or response.
type bodyReader struct {
	r io.Reader
	e error
}

func (br *bodyReader) Read(buf []byte) (int, error) {
	if br.e != nil {
		return 0, br.e
	}

	n, err := br.r.Read(buf)
	if err != nil {
		// Persist errors.
		br.e = err

		// If the call yielded any data, delay the error.
		if n > 0 {
			err = nil
		}
	}

	return n, err
}

func (br *bodyReader) Close() error {
	if br.e != nil {
		br.e = errReadAfterClose
	}
	return nil
}

func (br *bodyReader) LastError() error {
	if br.e == errReadAfterClose {
		return nil
	}
	return br.e
}
