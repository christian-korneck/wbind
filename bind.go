//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/windows"
)

var (
	errAlreadyMounted = errors.New("already mounted")
	errNotMounted     = errors.New("not mounted")
)

// binder is how commands reach the bind filter: directly (localBinder),
// which needs elevation, or through the helper service (helperClient).
type binder interface {
	mount(source, target string, readOnly bool) error
	unmount(target string) error
	// list returns all mounts if target is "", else the one at target.
	list(target string) ([]bindfilter.BindMapping, error)
}

// newBinder returns the binder that cmd's --unprivileged and --whitelist
// flags ask for. The helper client sends wl, if not nil (see
// readWhitelist).
func newBinder(cmd *cli.Command, wl *signedWhitelist) (binder, error) {
	if cmd.Bool("unprivileged") || cmd.Bool("whitelist") {
		return helperClient{whitelist: wl}, nil
	}
	if err := requireElevated(); err != nil {
		return nil, err
	}
	return localBinder{}, nil
}

func mountAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 2 {
		return errors.New("mount: expected SOURCE and TARGET (see 'wbind mount --help')")
	}
	source, err := resolvePath(cmd.Args().Get(0))
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	target, err := resolvePath(cmd.Args().Get(1))
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	if err := checkMount(source, target); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	wl, err := readWhitelist(cmd)
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	b, err := newBinder(cmd, wl)
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	if err := b.mount(source, target, cmd.Bool("ro")); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	return nil
}

func unmountAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 1 {
		return errors.New("unmount: expected TARGET (see 'wbind unmount --help')")
	}
	target, err := resolvePath(cmd.Args().Get(0))
	if err != nil {
		return fmt.Errorf("unmount: %w", err)
	}
	wl, err := readWhitelist(cmd)
	if err != nil {
		return fmt.Errorf("unmount: %w", err)
	}
	b, err := newBinder(cmd, wl)
	if err != nil {
		return fmt.Errorf("unmount: %w", err)
	}
	if err := b.unmount(target); err != nil {
		return fmt.Errorf("unmount: %w", err)
	}
	return nil
}

// checkMount validates the resolved paths of a mount request.
func checkMount(source, target string) error {
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("%s: %w", source, cause(err))
	}
	// TARGET need not exist: the bind filter projects it for the lifetime of
	// the mapping. Its parent must exist, though, because go-winio would
	// otherwise create it on disk, and wbind never writes to disk.
	if _, err := os.Stat(filepath.Dir(target)); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: parent directory does not exist", target)
	}
	if strings.EqualFold(source, target) {
		return fmt.Errorf("%s: SOURCE and TARGET are the same path", target)
	}
	return nil
}

// localBinder calls the bind filter in this process.
type localBinder struct{}

func (localBinder) mount(source, target string, readOnly bool) error {
	if err := bindfilter.ApplyFileBinding(target, source, readOnly); err != nil {
		if _, mounted, lerr := findMount(target); lerr == nil && mounted {
			return fmt.Errorf("%s: %w", target, errAlreadyMounted)
		}
		return fmt.Errorf("%s: %w", target, cause(err))
	}
	return nil
}

func (localBinder) unmount(target string) error {
	if err := bindfilter.RemoveFileBinding(target); err != nil {
		if _, mounted, lerr := findMount(target); lerr == nil && !mounted {
			return fmt.Errorf("%s: %w", target, errNotMounted)
		}
		return fmt.Errorf("%s: %w", target, cause(err))
	}
	return nil
}

func (localBinder) list(target string) ([]bindfilter.BindMapping, error) {
	if target == "" {
		return allMounts()
	}
	m, mounted, err := findMount(target)
	if err != nil {
		return nil, err
	}
	if !mounted {
		return nil, fmt.Errorf("%s: %w", target, errNotMounted)
	}
	return []bindfilter.BindMapping{m}, nil
}

// requireElevated fails unless the process runs with administrator rights.
// The bind filter API refuses everything else, even listing mappings.
func requireElevated() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("requires administrator privileges (run from an elevated shell)")
	}
	return nil
}

// cause strips one level of wrapping, such as go-winio's, which repeats the
// paths in Go-quoted form, so that messages read like
// "mount: C:\mnt\x: Access is denied."
func cause(err error) error {
	if u := errors.Unwrap(err); u != nil {
		return u
	}
	return err
}

// resolvePath makes p absolute and, if it exists (on disk or as a projected
// mount point), resolves symlinks, 8.3 short names and on-disk case, so that
// it matches the final paths that bindfilter.GetBindMappings reports.
func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if final, err := filepath.EvalSymlinks(abs); err == nil {
		return final, nil
	}
	return abs, nil
}

// canonicalPath is resolvePath, but if p does not exist, it resolves p's
// parent, so that only p's last element stays as given. Whitelist checks
// use it: a junction or 8.3 name in the parent of a TARGET must not slip
// past a rule. Everything else uses resolvePath, so that messages show
// paths as the user typed them.
func canonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if final, err := filepath.EvalSymlinks(abs); err == nil {
		return final, nil
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(dir, filepath.Base(abs)), nil
	}
	return abs, nil
}

// pinDir opens dir and its parent directories without sharing delete
// access, so that none of them can be renamed, deleted or replaced by a
// junction until release is called. (Nor can they become junctions in
// place: that needs an empty directory.) dir must be canonical (see
// resolvePath); pinDir fails if it no longer resolves to itself, that is
// if one of its elements changed since it was resolved.
func pinDir(dir string) (release func(), err error) {
	var handles []windows.Handle
	release = func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}
	// From the top down; the volume root cannot be renamed.
	var dirs []string
	for d := dir; len(d) > len(volumeRoot(dir)); d = filepath.Dir(d) {
		dirs = append([]string{d}, dirs...)
	}
	for _, d := range dirs {
		p, err := windows.UTF16PtrFromString(d)
		if err != nil {
			release()
			return nil, err
		}
		// The share mode only binds others if the handle has data access:
		// FILE_READ_ATTRIBUTES alone would not do.
		h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			release()
			return nil, fmt.Errorf("%s: %w", d, err)
		}
		handles = append(handles, h)
	}
	if len(handles) > 0 {
		if final, err := finalPath(handles[len(handles)-1]); err != nil || !strings.EqualFold(final, dir) {
			release()
			return nil, fmt.Errorf("%s: path changed while in use", dir)
		}
	}
	return release, nil
}

// finalPath returns the path of the file open as h, with reparse points
// resolved, as a DOS path.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		// Flags 0: FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			p := windows.UTF16ToString(buf[:n])
			if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
				return `\\` + rest, nil
			}
			return strings.TrimPrefix(p, `\\?\`), nil
		}
		buf = make([]uint16, n)
	}
}
