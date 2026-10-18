//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/windows"
)

func listAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() > 1 {
		return errors.New("list: expected at most one TARGET (see 'wbind list --help')")
	}
	var target string
	if cmd.NArg() == 1 {
		var err error
		if target, err = resolvePath(cmd.Args().Get(0)); err != nil {
			return fmt.Errorf("list: %w", err)
		}
	}
	b, err := newBinder(cmd, nil)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	// A full listing prints whatever was found even if some volumes failed;
	// the error still makes the exit status non-zero.
	mounts, err := b.list(target)
	if err == nil || len(mounts) > 0 {
		if perr := printMounts(cmd.Root().Writer, mounts, !cmd.Bool("noheadings")); perr != nil {
			return fmt.Errorf("list: %w", perr)
		}
	}
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	return nil
}

// allMounts returns the bind mounts of all volumes, sorted by mount point.
// Failures of single volumes are joined into the returned error while the
// mounts of the other volumes are still returned.
func allMounts() ([]bindfilter.BindMapping, error) {
	vols, err := volumes()
	if err != nil {
		return nil, err
	}
	var mounts []bindfilter.BindMapping
	var errs []error
	for _, vol := range vols {
		ms, err := mappingsOn(vol)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", vol, err))
			continue
		}
		mounts = append(mounts, ms...)
	}
	slices.SortFunc(mounts, func(a, b bindfilter.BindMapping) int {
		return strings.Compare(strings.ToLower(a.MountPoint), strings.ToLower(b.MountPoint))
	})
	return mounts, errors.Join(errs...)
}

// errFltInstanceNotFound is what BfGetMappings returns for a volume the bind
// filter is not attached to. Such a volume cannot have any mappings.
var errFltInstanceNotFound = syscall.Errno(windows.ERROR_FLT_INSTANCE_NOT_FOUND)

// mappingsOn returns the bind mounts whose mount point lies on the volume
// of path.
func mappingsOn(path string) ([]bindfilter.BindMapping, error) {
	mounts, err := bindfilter.GetBindMappings(path)
	if errors.Is(err, errFltInstanceNotFound) {
		return nil, nil
	}
	return mounts, err
}

// volumes lists the volumes that can hold a mount point as volume GUID
// paths: those reachable through a drive letter or a mounted folder and
// with media present.
func volumes() ([]string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	h, err := windows.FindFirstVolume(&buf[0], uint32(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("enumerating volumes: %w", err)
	}
	defer windows.FindVolumeClose(h)

	var vols []string
	for {
		if vol := windows.UTF16ToString(buf); reachable(vol) {
			vols = append(vols, vol)
		}
		if err := windows.FindNextVolume(h, &buf[0], uint32(len(buf))); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return vols, nil
			}
			return nil, fmt.Errorf("enumerating volumes: %w", err)
		}
	}
}

// reachable reports whether vol is mounted at a drive letter or folder and
// has media present.
func reachable(vol string) bool {
	p, err := windows.UTF16PtrFromString(vol)
	if err != nil {
		return false
	}
	var names [windows.MAX_PATH]uint16
	var n uint32
	err = windows.GetVolumePathNamesForVolumeName(p, &names[0], uint32(len(names)), &n)
	switch {
	case errors.Is(err, windows.ERROR_MORE_DATA):
		// More mount paths than fit the buffer: certainly reachable.
	case err != nil, names[0] == 0:
		return false
	}
	return windows.GetVolumeInformation(p, nil, 0, nil, nil, nil, nil, 0) == nil
}

// findMount looks up the bind mount at target.
func findMount(target string) (m bindfilter.BindMapping, mounted bool, err error) {
	mounts, err := mappingsOn(volumeRoot(target))
	if err != nil {
		return m, false, err
	}
	for _, m := range mounts {
		if strings.EqualFold(m.MountPoint, target) {
			return m, true, nil
		}
	}
	return m, false, nil
}

// volumeRoot returns the root of the volume p lives on (C:\ for C:\a\b).
// It always exists, so it is safe to hand to GetBindMappings even when p
// does not.
func volumeRoot(p string) string {
	return filepath.VolumeName(p) + `\`
}

// printMounts writes mounts as a findmnt-style table.
func printMounts(w io.Writer, mounts []bindfilter.BindMapping, headings bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if headings {
		fmt.Fprintln(tw, "TARGET\tSOURCE\tOPTIONS")
	}
	for _, m := range mounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.MountPoint, strings.Join(m.Targets, ","), options(m.Flags))
	}
	return tw.Flush()
}

// options renders bind filter flags the way findmnt shows mount options.
func options(flags uint32) string {
	if flags&bindfilter.BINDFLT_FLAG_READ_ONLY_MAPPING != 0 {
		return "ro"
	}
	return "rw"
}
