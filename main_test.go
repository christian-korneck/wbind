//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/bindfilter"
	"golang.org/x/sys/windows"
)

// TestMain runs the CLI instead of the tests when the SCM starts this test
// binary as the helper service (see TestHelperService).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		main()
		return
	}
	m.Run()
}

// run executes the CLI in-process and returns what it wrote to stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return runStdin(t, "", args...)
}

// runStdin is run with stdin as the CLI's standard input.
func runStdin(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	app := newApp()
	var out bytes.Buffer
	app.Reader = strings.NewReader(stdin)
	app.Writer = &out
	app.ErrWriter = &out
	err := app.Run(context.Background(), append([]string{"wbind"}, args...))
	return out.String(), err
}

func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// usePipe points the helper service client and listen at p for the rest of
// the test.
func usePipe(t *testing.T, p string) {
	old := pipeName
	pipeName = p
	t.Cleanup(func() { pipeName = old })
}

// startHelper serves h in-process on a test pipe and points the client at
// it. The pipe has the default security, which admits the test process.
func startHelper(t *testing.T, h http.Handler) {
	t.Helper()
	usePipe(t, `\\.\pipe\wbind-test-`+t.Name())
	l, err := winio.ListenPipe(pipeName, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(h)
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
}

func TestHelp(t *testing.T) {
	out, err := run(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bind SOURCE (directory or file) at TARGET", "unmount", "list, ls", "helperservice", "sig", "docs", "--whitelist"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"create", "unmount, umount", ", rm", "daemon"} {
		if strings.Contains(out, gone) {
			t.Errorf("help still mentions %q:\n%s", gone, out)
		}
	}

	out, err = run(t, "mount", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SOURCE TARGET", "--ro", "--unprivileged", "--whitelist-file", "--sig-file"} {
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
		{"sig", "keygen", "a"},
		{"sig", "example", "a"},
		{"sig", "sign", "a"},
		{"sig", "test"},
		{"sig", "test", "a"},
		{"sig", "test", "a", "b", "c"},
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
	// Messages show paths as typed, even with 8.3 names in them (if the
	// volume has none, this is the same path again).
	shortMissing := filepath.Join(shortPath(t, dir), "missing")

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"mount", missing, dir}, missing},
		{[]string{"mount", shortMissing, dir}, shortMissing},
		{[]string{"mount", dir, dir}, "same path"},
		{[]string{"mount", dir, filepath.Join(missing, "x")}, "parent directory"},
		{[]string{"mount", "--sig-file", "x", dir, filepath.Join(dir, "mnt")}, "--sig-file needs --whitelist"},
		{[]string{"unmount", "--whitelist-file", "x", dir}, "--whitelist-file needs --whitelist"},
		{[]string{"-w", "mount", "--whitelist-file", missing, dir, filepath.Join(dir, "mnt")}, missing},
		{[]string{"-w", "mount", "--whitelist-file", "-", "--sig-file", "-", dir, filepath.Join(dir, "mnt")}, "only one"},
		{[]string{"helperservice", "install", "--unmount-requires-whitelist"}, "needs --pubkey"},
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
	for _, args := range [][]string{{"mount", src, dst}, {"unmount", dst}, {"list"}, {"list", dst}, {"helperservice", "install"}, {"helperservice", "uninstall"}, {"-u", "helperservice", "install"}} {
		_, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "administrator") {
			t.Errorf("%v: want elevation error, got %v", args, err)
		}
	}
}

func TestUnprivilegedWithoutHelper(t *testing.T) {
	usePipe(t, `\\.\pipe\wbind-test-missing`)
	dir := t.TempDir()
	// -u is global: it works before and after the subcommand.
	for _, args := range [][]string{{"-u", "mount", dir, filepath.Join(dir, "mnt")}, {"unmount", "-u", dir}, {"-u", "ls"}, {"list", "-u"}} {
		_, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "cannot connect to the helper service") {
			t.Errorf("%v: want connection error, got %v", args, err)
		}
	}
}

// TestUnprivilegedListWarnings checks that a partial listing from the helper
// service prints like a local one: the mounts found, then the errors.
func TestUnprivilegedListWarnings(t *testing.T) {
	warnings := []string{`\\?\Volume{a}\: Access is denied.`, `\\?\Volume{b}\: Access is denied.`}
	startHelper(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, listResponse{
			Mounts:   []bindfilter.BindMapping{{MountPoint: `C:\mnt`, Targets: []string{`D:\data`}}},
			Warnings: warnings,
		})
	}))

	out, err := run(t, "list", "-u", "-n")
	if want := `C:\mnt  D:\data  rw` + "\n"; out != want {
		t.Errorf("list -u -n: got %q, want %q", out, want)
	}
	if want := "list: " + strings.Join(warnings, "\n"); err == nil || err.Error() != want {
		t.Errorf("list -u -n: got error %v, want %q", err, want)
	}
}

func TestHandlerRejectsBadRequests(t *testing.T) {
	dir := t.TempDir()
	body := func(source, target string) string {
		b, err := json.Marshal(mountRequest{Source: source, Target: target})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	for _, tc := range []struct{ method, url, body string }{
		{"POST", "/v1/mounts", "{"},
		{"POST", "/v1/mounts", body("rel", dir)},
		{"POST", "/v1/mounts", body(dir, "rel")},
		{"POST", "/v1/mounts", body(filepath.Join(dir, "missing"), filepath.Join(dir, "mnt"))},
		{"POST", "/v1/mounts", body(dir, dir)},
		{"DELETE", "/v1/mounts", ""},
		{"DELETE", "/v1/mounts?target=rel", ""},
		{"GET", "/v1/mounts?target=rel", ""},
	} {
		rec := httptest.NewRecorder()
		newHandler(nil, false).ServeHTTP(rec, httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body)))
		var e struct {
			Message string `json:"message"`
		}
		if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Message == "" {
			t.Errorf("%s %s %s: got %d %q, want 400 with a message", tc.method, tc.url, tc.body, rec.Code, rec.Body)
		}
	}
}

// TestWhitelistDenied checks that a helper service with a public key
// rejects requests without a valid whitelist that allows them. The
// requests fail before any bind filter call, so no elevation is needed.
func TestWhitelistDenied(t *testing.T) {
	src := canonical(t, t.TempDir())
	dst := filepath.Join(canonical(t, t.TempDir()), "mnt")
	pub, wl, sig := signWhitelist(t, escapeMeta(src)+" | C:/elsewhere/*\n")
	_, _, otherSig := signWhitelist(t, escapeMeta(src)+" | C:/elsewhere/*\n")
	startHelper(t, newHandler(pub, true))

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-u", "mount", src, dst}, "signed whitelist"},
		{[]string{"-u", "unmount", dst}, "signed whitelist"},
		{[]string{"-w", "mount", "--whitelist-file", wl, "--sig-file", otherSig, src, dst}, "signature does not match"},
		{[]string{"-w", "unmount", "--whitelist-file", wl, "--sig-file", otherSig, dst}, "signature does not match"},
		{[]string{"-w", "mount", "--whitelist-file", wl, "--sig-file", sig, src, dst}, "not allowed by the whitelist"},
	} {
		if _, err := run(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want an error containing %q", tc.args, err, tc.want)
		}
	}

	// A valid whitelist over an anonymous connection: the caller is unknown.
	body, err := json.Marshal(mountRequest{Source: src, Target: dst})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+serviceName+"/v1/mounts", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(whitelistHeader, base64.StdEncoding.EncodeToString(readFile(t, wl)))
	req.Header.Set(signatureHeader, base64.StdEncoding.EncodeToString(readFile(t, sig)))
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e struct{ Message string }
	if json.NewDecoder(resp.Body).Decode(&e); resp.StatusCode != http.StatusForbidden || !strings.Contains(e.Message, "cannot identify the caller") {
		t.Errorf("anonymous: got %d %q, want 403 and an identification error", resp.StatusCode, e.Message)
	}
}

func TestDocs(t *testing.T) {
	md, err := run(t, "docs")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# NAME", "## mount", "## unmount", "## list, ls", "## sig", "## docs", "--ro"} {
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
		{filepath.Join(shortPath(t, dir), "missing"), filepath.Join(shortPath(t, dir), "missing")},
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

func TestCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	canon, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ in, want string }{
		{shortPath(t, dir), canon},
		{filepath.Join(strings.ToLower(dir), "missing"), filepath.Join(canon, "missing")},
		{filepath.Join(shortPath(t, dir), "missing"), filepath.Join(canon, "missing")},
	} {
		got, err := canonicalPath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("canonicalPath(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
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
