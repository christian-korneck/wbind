//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
)

// These tests create real bind mounts and therefore need an elevated test
// process; otherwise they are skipped, like go-winio's own bindfilter tests.

func skipUnlessElevated(t *testing.T) {
	t.Helper()
	if !elevated() {
		t.Skip("requires an elevated shell")
	}
}

// sourceDir returns a canonical temp directory containing hello.txt.
func sourceDir(t *testing.T) string {
	t.Helper()
	dir := canonical(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// mountPoint returns a canonical path named name inside a fresh temp
// directory. The path itself does not exist; it is unmounted at cleanup.
func mountPoint(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(canonical(t, t.TempDir()), name)
	unmountAtCleanup(t, p)
	return p
}

func unmountAtCleanup(t *testing.T, p string) {
	t.Cleanup(func() { _ = bindfilter.RemoveFileBinding(p) })
}

func canonical(t *testing.T, p string) string {
	t.Helper()
	p, err := resolvePath(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMountRoundTrip(t *testing.T) {
	skipUnlessElevated(t)
	src, dst := sourceDir(t), mountPoint(t, "mnt")
	file := filepath.Join(dst, "hello.txt")

	if _, err := run(t, "mount", src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("file not visible through the mount: %v", err)
	}

	out, err := run(t, "list", "-n", dst)
	if err != nil {
		t.Fatal(err)
	}
	if want := dst + "  " + src + "  rw\n"; out != want {
		t.Errorf("list -n: got %q, want %q", out, want)
	}
	for _, args := range [][]string{{"list"}, {"ls"}} {
		out, err := run(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out, dst) {
			t.Errorf("%v does not list %s:\n%s", args, dst, out)
		}
	}
	if _, err := run(t, "mount", src, dst); err == nil || !strings.Contains(err.Error(), "already mounted") {
		t.Errorf("second mount: %v", err)
	}

	if _, err := run(t, "unmount", dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Error("mount point still exists after unmount")
	}
	if _, err := run(t, "list", dst); err == nil || !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("list after unmount: %v", err)
	}
	if _, err := run(t, "unmount", dst); err == nil || !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("second unmount: %v", err)
	}
}

func TestMountReadOnly(t *testing.T) {
	skipUnlessElevated(t)
	src, dst := sourceDir(t), mountPoint(t, "mnt")

	if _, err := run(t, "mount", "-r", src, dst); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "new.txt"), []byte("x"), 0o644); !errors.Is(err, os.ErrPermission) {
		t.Errorf("write through read-only mount: got %v, want permission error", err)
	}
	out, err := run(t, "list", "-n", dst)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "  ro\n") {
		t.Errorf("list: got %q, want ro", out)
	}
}

func TestMountFile(t *testing.T) {
	skipUnlessElevated(t)
	src := filepath.Join(canonical(t, t.TempDir()), "src.txt")
	if err := os.WriteFile(src, []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := mountPoint(t, "dst.txt")

	if _, err := run(t, "mount", src, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "source" {
		t.Fatalf("read through mount: %q, %v", got, err)
	}
	if err := os.WriteFile(dst, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(src); string(got) != "changed" {
		t.Errorf("write did not reach the source: %q", got)
	}
	out, err := run(t, "list", "-n", dst)
	if err != nil {
		t.Fatal(err)
	}
	if want := dst + "  " + src + "  rw\n"; out != want {
		t.Errorf("list -n: got %q, want %q", out, want)
	}

	if _, err := run(t, "unmount", dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Error("mount point still exists after unmount")
	}
}

func TestMountHidesExistingTarget(t *testing.T) {
	skipUnlessElevated(t)
	src := sourceDir(t)
	dst := canonical(t, t.TempDir())
	unmountAtCleanup(t, dst)
	old := filepath.Join(dst, "old.txt")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, "mount", src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("existing target content still visible while mounted")
	}
	if _, err := os.Stat(filepath.Join(dst, "hello.txt")); err != nil {
		t.Errorf("source content not visible: %v", err)
	}
	if _, err := run(t, "unmount", dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Errorf("existing target content not restored after unmount: %v", err)
	}
}
