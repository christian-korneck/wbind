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

// newBinder returns the binder that cmd's --unprivileged flag asks for.
func newBinder(cmd *cli.Command) (binder, error) {
	if cmd.Bool("unprivileged") {
		return helperClient{}, nil
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
	b, err := newBinder(cmd)
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
	b, err := newBinder(cmd)
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
