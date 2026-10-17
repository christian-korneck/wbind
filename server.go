//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
)

// mountRequest is the body of POST /v1/mounts.
type mountRequest struct {
	Source   string
	Target   string
	ReadOnly bool
}

// listResponse is the body of GET /v1/mounts. Warnings holds the errors of
// the volumes that could not be listed while others could, as in a local
// listing.
type listResponse struct {
	Mounts   []bindfilter.BindMapping
	Warnings []string
}

// newHandler serves the helper service's REST API. Like dockerd's API it
// speaks JSON and reports errors as {"message": "..."}:
//
//	GET    /v1/mounts[?target=PATH]  list all mounts, or the one at PATH, as a listResponse
//	POST   /v1/mounts                create a mount from a mountRequest
//	DELETE /v1/mounts?target=PATH    remove the mount at PATH
func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/mounts", handleList)
	mux.HandleFunc("POST /v1/mounts", handleMount)
	mux.HandleFunc("DELETE /v1/mounts", handleUnmount)
	return mux
}

func handleList(w http.ResponseWriter, r *http.Request) {
	var target string
	if t := r.URL.Query().Get("target"); t != "" {
		var err error
		if target, err = requestPath(t); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	mounts, err := localBinder{}.list(target)
	if err != nil && len(mounts) == 0 {
		writeError(w, status(err), err)
		return
	}
	resp := listResponse{Mounts: mounts, Warnings: []string{}}
	if resp.Mounts == nil {
		resp.Mounts = []bindfilter.BindMapping{}
	}
	if err != nil {
		errs := []error{err}
		if j, ok := err.(interface{ Unwrap() []error }); ok { // from errors.Join
			errs = j.Unwrap()
		}
		for _, e := range errs {
			resp.Warnings = append(resp.Warnings, e.Error())
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleMount(w http.ResponseWriter, r *http.Request) {
	var req mountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	source, err := requestPath(req.Source)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	target, err := requestPath(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// The client checked this too, but the service must not rely on it.
	if err := checkMount(source, target); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := (localBinder{}).mount(source, target, req.ReadOnly); err != nil {
		writeError(w, status(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleUnmount(w http.ResponseWriter, r *http.Request) {
	target, err := requestPath(r.URL.Query().Get("target"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := (localBinder{}).unmount(target); err != nil {
		writeError(w, status(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requestPath canonicalizes a path from a request. It must be absolute: the
// service's working directory means nothing to the client.
func requestPath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q: not an absolute path", p)
	}
	return resolvePath(p)
}

// status returns the HTTP status code for an error of a bind operation.
func status(err error) int {
	switch {
	case errors.Is(err, errNotMounted):
		return http.StatusNotFound
	case errors.Is(err, errAlreadyMounted):
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"message": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
