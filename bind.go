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

func mountAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 2 {
		return errors.New("mount: expected SOURCE and TARGET (see 'wbind mount --help')")
	}

	source, err := resolvePath(cmd.Args().Get(0))
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("mount: %s: %w", source, cause(err))
	}
	// TARGET need not exist: the bind filter projects it for the lifetime of
	// the mapping. Its parent must exist, though, because go-winio would
	// otherwise create it on disk, and wbind never writes to disk.
	target, err := resolvePath(cmd.Args().Get(1))
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	if _, err := os.Stat(filepath.Dir(target)); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("mount: %s: parent directory does not exist", target)
	}
	if strings.EqualFold(source, target) {
		return fmt.Errorf("mount: %s: SOURCE and TARGET are the same path", target)
	}

	if err := requireElevated(); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	if err := bindfilter.ApplyFileBinding(target, source, cmd.Bool("ro")); err != nil {
		if _, mounted, lerr := findMount(target); lerr == nil && mounted {
			return fmt.Errorf("mount: %s: already mounted", target)
		}
		return fmt.Errorf("mount: %s: %w", target, cause(err))
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
	if err := requireElevated(); err != nil {
		return fmt.Errorf("unmount: %w", err)
	}
	if err := bindfilter.RemoveFileBinding(target); err != nil {
		if _, mounted, lerr := findMount(target); lerr == nil && !mounted {
			return fmt.Errorf("unmount: %s: not mounted", target)
		}
		return fmt.Errorf("unmount: %s: %w", target, cause(err))
	}
	return nil
}

// requireElevated fails unless the process runs with administrator rights.
// The bind filter API refuses everything else, even listing mappings.
func requireElevated() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("requires administrator privileges (run from an elevated shell)")
	}
	return nil
}

// cause strips go-winio's wrapping, which repeats the paths in Go-quoted
// form, so that messages read like "mount: C:\mnt\x: Access is denied."
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
