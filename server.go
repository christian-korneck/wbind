//go:build windows

package main

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
	"golang.org/x/sys/windows"
)

// The headers of the signed whitelist that clients in --whitelist mode send
// with every request, as base64 of the raw files.
const (
	whitelistHeader = "X-Wbind-Whitelist"
	signatureHeader = "X-Wbind-Signature"
)

var errWhitelistRequired = errors.New("the helper service requires a signed whitelist that allows this request (see 'wbind --whitelist')")

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
//
// With a public key, POST needs a whitelist signed with its private key
// that allows it (see api.authorize), and so does DELETE if
// unmountNeedsWhitelist is set.
func newHandler(pub *mldsa.PublicKey, unmountNeedsWhitelist bool) http.Handler {
	a := &api{pub: pub, unmountNeedsWhitelist: unmountNeedsWhitelist}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/mounts", handleList)
	mux.HandleFunc("POST /v1/mounts", a.handleMount)
	mux.HandleFunc("DELETE /v1/mounts", a.handleUnmount)
	return mux
}

type api struct {
	pub                   *mldsa.PublicKey // nil: no whitelist needed
	unmountNeedsWhitelist bool             // with pub; else anyone may unmount anything
	mu                    sync.Mutex       // serializes mountChecked
}

var errMountMoved = errors.New("the bind filter put the mount elsewhere, so it was removed (did TARGET change during the request?)")

// mountChecked mounts like localBinder.mount, then checks where the bind
// filter really put the mount. The bind filter follows a junction at
// target, which the caller can create after the whitelist check (pinDir
// cannot pin a target that does not exist). A mount that ended up
// elsewhere is removed again.
func (a *api) mountChecked(source, target string, readOnly bool) error {
	a.mu.Lock() // so that the new mappings below are this call's
	defer a.mu.Unlock()
	before, err := allMounts()
	if err != nil && len(before) == 0 {
		return err
	}
	if err := (localBinder{}).mount(source, target, readOnly); err != nil {
		return err
	}
	if _, mounted, err := findMount(target); err == nil && mounted {
		return nil
	}

	// Remove the mappings of source that are new.
	after, err := allMounts()
	errs := []error{fmt.Errorf("%s: %w", target, errMountMoved), err}
	for _, m := range after {
		isNew := !slices.ContainsFunc(before, func(b bindfilter.BindMapping) bool { return strings.EqualFold(b.MountPoint, m.MountPoint) })
		if isNew && slices.ContainsFunc(m.Targets, func(s string) bool { return strings.EqualFold(s, source) }) {
			if err := bindfilter.RemoveFileBinding(m.MountPoint); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", m.MountPoint, cause(err)))
			}
		}
	}
	return errors.Join(errs...)
}

type connKey struct{}

// newServer serves h with each request's connection in its context, so
// that the handler can identify the caller (see callerToken).
func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}
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

func (a *api) handleMount(w http.ResponseWriter, r *http.Request) {
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
	if err == nil && a.pub != nil {
		// Checked, pinned, mounted and verified in the same form.
		target, err = canonicalPath(target)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	release, code, err := a.authorize(r, target, func() ([]string, bool, error) { return []string{source}, req.ReadOnly, nil })
	if err != nil {
		writeError(w, code, err)
		return
	}
	defer release()
	// The client checked this too, but the service must not rely on it.
	if err := checkMount(source, target); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	mount := localBinder{}.mount
	if a.pub != nil {
		mount = a.mountChecked
	}
	if err := mount(source, target, req.ReadOnly); err != nil {
		writeError(w, status(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) handleUnmount(w http.ResponseWriter, r *http.Request) {
	target, err := requestPath(r.URL.Query().Get("target"))
	if err == nil && a.unmountNeedsWhitelist {
		target, err = canonicalPath(target)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if a.unmountNeedsWhitelist {
		// The whitelist is checked against the sources and mode the mount
		// really has, not against what the client says.
		release, code, err := a.authorize(r, target, func() ([]string, bool, error) {
			m, mounted, err := findMount(target)
			if err == nil && !mounted {
				err = fmt.Errorf("%s: %w", target, errNotMounted)
			}
			return m.Targets, m.Flags&bindfilter.BINDFLT_FLAG_READ_ONLY_MAPPING != 0, err
		})
		if err != nil {
			writeError(w, code, err)
			return
		}
		defer release()
	}
	if err := (localBinder{}).unmount(target); err != nil {
		writeError(w, status(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorize checks, if the service has a public key, that r carries a
// whitelist signed with its private key and that the whitelist allows the
// caller to bind each of sources at target, read-only or not as sources
// reports. Then it pins target's parent directory (see pinDir) until
// release is called, after the bind operation, so that the paths it
// checked cannot change. On failure it returns the HTTP status code for
// the error.
func (a *api) authorize(r *http.Request, target string, sources func() ([]string, bool, error)) (release func(), code int, err error) {
	if a.pub == nil {
		return func() {}, 0, nil
	}
	if r.Header.Get(whitelistHeader) == "" || r.Header.Get(signatureHeader) == "" {
		return nil, http.StatusForbidden, errWhitelistRequired
	}
	list, err1 := base64.StdEncoding.DecodeString(r.Header.Get(whitelistHeader))
	sig, err2 := base64.StdEncoding.DecodeString(r.Header.Get(signatureHeader))
	if err := errors.Join(err1, err2); err != nil {
		return nil, http.StatusBadRequest, err
	}
	rules, err := verifyWhitelist(a.pub, list, sig)
	switch {
	case errors.Is(err, errSignature):
		return nil, http.StatusForbidden, err
	case err != nil:
		return nil, http.StatusBadRequest, err
	}

	t, err := callerToken(r)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	vs := whitelistVars(t)
	t.Close()

	srcs, readOnly, err := sources()
	if err != nil {
		return nil, status(err), err
	}
	for _, s := range srcs {
		if _, err := allowed(rules, vs, s, target, readOnly); err != nil {
			return nil, http.StatusForbidden, err
		}
	}
	release, err = pinDir(filepath.Dir(target))
	if err != nil {
		return nil, http.StatusConflict, err
	}
	return release, 0, nil
}

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

// callerToken returns the token of the client at the other end of r's
// pipe. Clients in --whitelist mode connect at the identification
// impersonation level, so the token tells who they are, but cannot be used
// to act as them. Older and anonymous clients are rejected.
func callerToken(r *http.Request) (windows.Token, error) {
	c, ok := r.Context().Value(connKey{}).(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("cannot identify the caller: not connected through a pipe")
	}

	// Impersonation applies to the OS thread, which must not run other
	// goroutines meanwhile.
	runtime.LockOSThread()
	if ok, _, err := procImpersonateNamedPipeClient.Call(c.Fd()); ok == 0 {
		runtime.UnlockOSThread()
		return 0, fmt.Errorf("cannot identify the caller: %w", err)
	}
	var t windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// Leave the thread locked: Go then terminates it with this
		// goroutine instead of reusing it with the caller's identity.
		if err == nil {
			t.Close()
		}
		return 0, fmt.Errorf("cannot identify the caller: %w", rerr)
	}
	runtime.UnlockOSThread()
	if err != nil {
		return 0, fmt.Errorf("cannot identify the caller (connect with 'wbind --whitelist'): %w", err)
	}

	u, err := t.GetTokenUser()
	if err == nil && u.User.Sid.IsWellKnown(windows.WinAnonymousSid) {
		err = errors.New("anonymous (connect with 'wbind --whitelist')")
	}
	if err != nil {
		t.Close()
		return 0, fmt.Errorf("cannot identify the caller: %w", err)
	}
	return t, nil
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
