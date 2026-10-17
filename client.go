//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/bindfilter"
)

// helperClient sends bind operations to the helper service's REST API (see
// newHandler), so that the caller needs no elevation.
type helperClient struct{}

// httpClient talks HTTP over the helper service's named pipe. go-winio dials
// at the anonymous impersonation level, so whoever serves the pipe cannot
// act as the client.
var httpClient = &http.Client{Transport: &http.Transport{
	DisableKeepAlives: true, // a CLI run makes one request
	DialContext: func(context.Context, string, string) (net.Conn, error) {
		c, err := winio.DialPipe(pipeName, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot connect to the helper service at %s (see 'wbind helperservice install'): %w", pipeName, cause(err))
		}
		return c, nil
	},
}}

func (helperClient) mount(source, target string, readOnly bool) error {
	return call(http.MethodPost, "/v1/mounts", mountRequest{Source: source, Target: target, ReadOnly: readOnly}, nil)
}

func (helperClient) unmount(target string) error {
	return call(http.MethodDelete, "/v1/mounts?target="+url.QueryEscape(target), nil, nil)
}

func (helperClient) list(target string) ([]bindfilter.BindMapping, error) {
	path := "/v1/mounts"
	if target != "" {
		path += "?target=" + url.QueryEscape(target)
	}
	var resp listResponse
	if err := call(http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	var errs []error
	for _, w := range resp.Warnings {
		errs = append(errs, errors.New(w))
	}
	return resp.Mounts, errors.Join(errs...)
}

// call sends a request with in as JSON body (unless nil) and decodes the
// JSON response into out (unless nil). Error responses become errors.
func call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+serviceName+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return cause(err) // strip *url.Error
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		if json.NewDecoder(resp.Body).Decode(&e) != nil || e.Message == "" {
			return fmt.Errorf("helper service: %s", resp.Status)
		}
		return errors.New(e.Message)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
