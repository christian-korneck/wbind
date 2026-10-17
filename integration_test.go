//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
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

func TestUnprivilegedRoundTrip(t *testing.T) {
	skipUnlessElevated(t)
	startHelper(t, newHandler())
	src, dst := sourceDir(t), mountPoint(t, "mnt")

	if _, err := run(t, "mount", "-u", src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "hello.txt")); err != nil {
		t.Fatalf("file not visible through the mount: %v", err)
	}
	out, err := run(t, "list", "-u", "-n", dst)
	if want := dst + "  " + src + "  rw\n"; err != nil || out != want {
		t.Errorf("list -u -n: got %q, %v, want %q", out, err, want)
	}
	if out, err := run(t, "ls", "-u"); err != nil || !strings.Contains(out, dst) {
		t.Errorf("ls -u does not list %s: %v\n%s", dst, err, out)
	}
	if _, err := run(t, "mount", "-u", src, dst); err == nil || !strings.Contains(err.Error(), "already mounted") {
		t.Errorf("second mount: %v", err)
	}

	if _, err := run(t, "unmount", "-u", dst); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "unmount", "-u", dst); err == nil || !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("second unmount: %v", err)
	}
	if _, err := run(t, "list", "-u", dst); err == nil || !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("list after unmount: %v", err)
	}

	if _, err := run(t, "mount", "-u", "-r", src, dst); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, "list", "-u", "-n", dst); err != nil || !strings.HasSuffix(out, "  ro\n") {
		t.Errorf("list -u -n: got %q, %v, want ro", out, err)
	}
}

// TestHelperService installs this test binary as the real helper service
// (TestMain runs it as the daemon) and uses it through the default pipe.
func TestHelperService(t *testing.T) {
	skipUnlessElevated(t)
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		t.Skip("the helper service is installed already")
	}
	exe, err := installedExe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(exe); err == nil {
		t.Skip(exe + " exists already")
	}
	// An existing group, so that the test creates none.
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	name, domain, _, err := users.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = uninstallService() })
	if _, err := run(t, "helperservice", "install", "--group", domain+`\`+name); err != nil {
		t.Fatal(err)
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Config()
	if err != nil || !strings.HasPrefix(c.BinaryPathName, exe+" ") {
		t.Errorf("service runs %q, %v; want %s", c.BinaryPathName, err, exe)
	}
	if acts, err := s.RecoveryActions(); err != nil || len(acts) != 3 || acts[0].Type != mgr.ServiceRestart {
		t.Errorf("recovery actions: %v, %v; want restarts", acts, err)
	}
	if on, err := s.RecoveryActionsOnNonCrashFailures(); err != nil || !on {
		t.Errorf("recovery on non-crash failures: %v, %v; want true", on, err)
	}
	s.Close()
	if _, err := os.Stat(exe); err != nil {
		t.Errorf("wbind.exe not copied: %v", err)
	}
	if _, err := run(t, "list", "-u"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "helperservice", "uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(exe); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s after uninstall: %v, want it removed", exe, err)
	}
	if _, err := run(t, "list", "-u"); err == nil || !strings.Contains(err.Error(), "cannot connect to the helper service") {
		t.Errorf("list -u after uninstall: %v", err)
	}
}

func TestRemoveExeInUse(t *testing.T) {
	skipUnlessElevated(t)
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(sys, "cmd.exe"))
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "cmd.exe")
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "/c", "ping", "-n", "10", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf("%s.%d.delete", exe, os.Getpid())
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(old)
	})

	if err := removeExe(exe); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(exe); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s after removeExe: %v, want it gone", exe, err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Errorf("renamed exe: %v", err)
	}
}

func TestEnsureGroup(t *testing.T) {
	skipUnlessElevated(t)
	name := fmt.Sprintf("wbind-test-%d", os.Getpid())
	t.Cleanup(func() { _ = exec.Command("net", "localgroup", name, "/delete").Run() })
	au, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatal(err)
	}

	for range 2 { // the second call finds the group
		if err := ensureGroup(name, au); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, typ, err := windows.LookupSID("", name); err != nil || typ != windows.SidTypeAlias {
		t.Errorf("LookupSID(%q): type %d, %v; want a local group", name, typ, err)
	}
	member, _, _, err := au.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("net", "localgroup", name).Output()
	if err != nil || !strings.Contains(string(out), member) {
		t.Errorf("group lacks %s: %v\n%s", member, err, out)
	}
}
