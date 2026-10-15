//go:build windows

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/pkg/bindfilter"
	"golang.org/x/sys/windows"
)

// run executes the CLI in-process and returns what it wrote to stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	app := newApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out
	err := app.Run(context.Background(), append([]string{"wbind"}, args...))
	return out.String(), err
}

func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func TestHelp(t *testing.T) {
	out, err := run(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bind SOURCE (directory or file) at TARGET", "unmount", "list, ls", "docs"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"create", "unmount, umount", ", rm"} {
		if strings.Contains(out, gone) {
			t.Errorf("help still mentions %q:\n%s", gone, out)
		}
	}

	out, err = run(t, "mount", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SOURCE TARGET", "--ro"} {
		if !strings.Contains(out, want) {
			t.Errorf("mount help lacks %q:\n%s", want, out)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"mount"},
		{"mount", "x"},
		{"mount", "a", "b", "c"},
		{"unmount"},
		{"unmount", "a", "b"},
		{"list", "a", "b"},
		{"ls", "a", "b"},
	} {
		_, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "--help") {
			t.Errorf("%v: want usage error, got %v", args, err)
		}
	}
}

func TestMountValidatesPaths(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"mount", missing, dir}, missing},
		{[]string{"mount", dir, dir}, "same path"},
		{[]string{"mount", dir, filepath.Join(missing, "x")}, "parent directory"},
	} {
		_, err := run(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: want error containing %q, got %v", tc.args, tc.want, err)
		}
	}
}

func TestRequiresElevation(t *testing.T) {
	if elevated() {
		t.Skip("running elevated")
	}
	src, dst := t.TempDir(), t.TempDir()
	for _, args := range [][]string{{"mount", src, dst}, {"unmount", dst}, {"list"}, {"list", dst}} {
		_, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "administrator") {
			t.Errorf("%v: want elevation error, got %v", args, err)
		}
	}
}

func TestDocs(t *testing.T) {
	md, err := run(t, "docs")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# NAME", "## mount", "## unmount", "## list, ls", "## docs", "--ro"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
}

func TestDocsUpToDate(t *testing.T) {
	want, err := run(t, "docs")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("cli-reference.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Error("cli-reference.md is stale: run `go generate ./...`")
	}
}

func TestPrintMounts(t *testing.T) {
	mounts := []bindfilter.BindMapping{
		{MountPoint: `C:\mnt\ro`, Targets: []string{`D:\stuff`}, Flags: bindfilter.BINDFLT_FLAG_READ_ONLY_MAPPING | bindfilter.BINDFLT_FLAG_NO_MULTIPLE_TARGETS},
		{MountPoint: `C:\mnt\data`, Targets: []string{`D:\data`}, Flags: bindfilter.BINDFLT_FLAG_NO_MULTIPLE_TARGETS},
	}

	var buf bytes.Buffer
	if err := printMounts(&buf, mounts, true); err != nil {
		t.Fatal(err)
	}
	want := "TARGET       SOURCE    OPTIONS\n" +
		`C:\mnt\ro    D:\stuff  ro` + "\n" +
		`C:\mnt\data  D:\data   rw` + "\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}

	buf.Reset()
	if err := printMounts(&buf, mounts[:1], false); err != nil {
		t.Fatal(err)
	}
	if want := `C:\mnt\ro  D:\stuff  ro` + "\n"; buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestResolvePath(t *testing.T) {
	dir := t.TempDir()
	canon, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ in, want string }{
		{"missing", filepath.Join(cwd, "missing")},
		{dir + `\`, canon},
		{strings.ReplaceAll(dir, `\`, "/"), canon},
		{strings.ToLower(dir), canon},
		{shortPath(t, dir), canon},
	} {
		got, err := resolvePath(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// shortPath returns the 8.3 form of p, or p itself when the volume has no
// short names.
func shortPath(t *testing.T, p string) string {
	t.Helper()
	long, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_PATH)
	if _, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf))); err != nil {
		t.Fatal(err)
	}
	return windows.UTF16ToString(buf)
}

func TestVolumeRoot(t *testing.T) {
	for in, want := range map[string]string{
		`C:\a\b`:             `C:\`,
		`C:\`:                `C:\`,
		`\\?\Volume{x}\a`:    `\\?\Volume{x}\`,
		`\\server\share\dir`: `\\server\share\`,
	} {
		if got := volumeRoot(in); got != want {
			t.Errorf("volumeRoot(%q) = %q, want %q", in, got, want)
		}
	}
}
