//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestParseWhitelist(t *testing.T) {
	text := "\xEF\xBB\xBF# comment\r\n\r\n  %USERPROFILE%/src/**  |  %UserProfile%/mnt/*  \r\n" +
		"   # indented comment\nD:/a b/c|C:/x\\%y\n" +
		"C:/r | C:/s | RO\nC:/t|C:/u|rw\n"
	rules, err := parseWhitelist([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	want := []rule{
		{Line: 3, Source: "%USERPROFILE%/src/**", Target: "%UserProfile%/mnt/*"},
		{Line: 5, Source: "D:/a b/c", Target: `C:/x\%y`},
		{Line: 6, Source: "C:/r", Target: "C:/s", ReadOnly: true},
		{Line: 7, Source: "C:/t", Target: "C:/u"},
	}
	if !slices.Equal(rules, want) {
		t.Errorf("got %+v, want %+v", rules, want)
	}

	for _, bad := range []string{
		"",
		"# only a comment",
		"C:/a",
		"C:/a | C:/b | C:/c",
		"C:/a | C:/b | rx",
		"C:/a | C:/b | ro | rw",
		"C:/a | C:/b |",
		" | C:/b",
		"C:/a | ",
		"%NOSUCHVAR%/a | C:/b",
		"C:/a | %USERPROFILE/b",
		"C:/[a | C:/b",
		"\xff | C:/b",
	} {
		if _, err := parseWhitelist([]byte(bad)); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestParseWhitelistDots(t *testing.T) {
	for _, bad := range []string{
		"C:/a/../b | C:/x",
		"C:/a | %USERPROFILE%/..",
		"C:/./a | C:/b",
		"C:/a/. | C:/b",
		`C:/a/\.\./b | C:/x`,
		"C:/{..,b}/c | C:/x",
		"C:/{a/..,b} | C:/x",
		"C:/{a,{b,..}}/c | C:/x",
		"C:/{a,b}/{c,d}/.. | C:/x",
	} {
		if _, err := parseWhitelist([]byte(bad)); err == nil || !strings.Contains(err.Error(), `".." are not allowed`) {
			t.Errorf("%q: got %v, want a dots error", bad, err)
		}
	}
	for _, good := range []string{
		"C:/a..b | C:/x",
		"C:/.git/** | C:/x",
		"C:/... | C:/x",
		"C:/a.{txt,md} | C:/x",
		"C:/{.git,src}/** | C:/x",
		"//server/share/x | C:/x",
		"C:/[.]x | C:/y",
		"C:/x[/].. | C:/y", // a / in a class is no separator
		`C:/a\/.. | C:/y`,  // nor is an escaped /
	} {
		if _, err := parseWhitelist([]byte(good)); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}

	// Each group multiplies the alternatives.
	_, err := parseWhitelist([]byte("C:/" + strings.Repeat("{a,b,c}", 7) + " | C:/x"))
	if err == nil || !strings.Contains(err.Error(), "alternatives") {
		t.Errorf("3^7 alternatives: got %v, want an error", err)
	}
}

func TestParseWhitelistUTF16(t *testing.T) {
	u := utf16.Encode([]rune("C:/ä | C:/b\r\n"))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	rules, err := parseWhitelist(b)
	if err != nil || len(rules) != 1 || rules[0].Source != "C:/ä" {
		t.Errorf("got %+v, %v", rules, err)
	}
}

func TestSignedMessage(t *testing.T) {
	msg := func(text string) []byte {
		t.Helper()
		rules, err := parseWhitelist([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return signedMessage(rules)
	}
	want := msg("C:/a | C:/b\nD:/c | D:/d\n")
	if string(want) != "C:/a|C:/b\nD:/c|D:/d\n" {
		t.Errorf("got %q", want)
	}
	for _, same := range []string{
		"# new comment\r\nC:/a|C:/b\r\n\r\n   D:/c   |   D:/d",
		"\xEF\xBB\xBFC:/a | C:/b\nD:/c | D:/d",
		"C:/a | C:/b | rw\nD:/c | D:/d | RW",
	} {
		if !bytes.Equal(msg(same), want) {
			t.Errorf("%q: message changed", same)
		}
	}
	for _, different := range []string{
		"C:/a | C:/b\nD:/c | D:/e",
		"D:/c | D:/d\nC:/a | C:/b",
		"C:/a | C:/b",
		"c:/a | C:/b\nD:/c | D:/d",
		"C:/a | C:/b\nD:/c | D:/d | ro",
	} {
		if bytes.Equal(msg(different), want) {
			t.Errorf("%q: message unchanged", different)
		}
	}
	if got := msg("C:/a | C:/b | RO"); string(got) != "C:/a|C:/b|ro\n" {
		t.Errorf("read-only rule: got %q", got)
	}
}

func TestExpand(t *testing.T) {
	vs := vars{}
	vs.set("USERPROFILE", `C:\Users\a[1]{b,c}`, nil)
	vs.set("USERNAME", "", windows.ERROR_NONE_MAPPED)

	for _, tc := range []struct{ in, want string }{
		{"%USERPROFILE%/x", `C:/Users/a\[1\]\{b\,c\}/x`},
		{"%userprofile%/x", `C:/Users/a\[1\]\{b\,c\}/x`},
		{`C:/100\%/x`, `C:/100\%/x`},
		{`C:/a\*b`, `C:/a\*b`},
	} {
		got, err := expand(tc.in, vs)
		if err != nil || got != tc.want {
			t.Errorf("expand(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{"%USERNAME%/x", "%NOPE%/x", "C:/%USERPROFILE"} {
		if got, err := expand(in, vs); err == nil {
			t.Errorf("expand(%q) = %q; want an error", in, got)
		}
	}
}

func TestAllowed(t *testing.T) {
	rules, err := parseWhitelist([]byte(`
%USERPROFILE%/src/** | %USERPROFILE%/mnt/*
//server/share/**    | %APPDATA%/cache
%USERNAME%/x         | C:/y
D:/media/**          | C:/media/* | ro
`))
	if err != nil {
		t.Fatal(err)
	}
	vs := vars{}
	vs.set("USERPROFILE", `C:\Users\b[o]b`, nil)
	vs.set("APPDATA", `C:\Users\b[o]b\AppData\Roaming`, nil)
	vs.set("USERNAME", "", windows.ERROR_NONE_MAPPED)

	for _, tc := range []struct {
		source, target string
		readOnly       bool
		line           int // 0: not allowed
	}{
		{`C:\Users\b[o]b\src\a\b`, `C:\Users\b[o]b\mnt\x`, false, 2},
		{`C:\Users\b[o]b\src\a\b`, `C:\Users\b[o]b\mnt\x`, true, 2},
		{`c:\users\B[O]B\SRC`, `C:\USERS\b[o]b\mnt\x`, false, 2},
		{`\\server\share\dir`, `C:\Users\b[o]b\AppData\Roaming\cache`, false, 3},
		{`C:\Users\alice\src\a`, `C:\Users\b[o]b\mnt\x`, false, 0},
		{`C:\Users\b[o]b\src\a`, `C:\Users\alice\mnt\x`, false, 0},
		{`C:\Users\b[o]b\src\a`, `C:\Users\b[o]b\mnt\x\y`, false, 0},
		{`C:\Users\bob\src\a`, `C:\Users\bob\mnt\x`, false, 0},
		{`C:\Users\b[o]b\other`, `C:\Users\b[o]b\mnt\x`, false, 0},
		{`D:\media\films`, `C:\media\films`, true, 5},
		{`D:\media\films`, `C:\media\films`, false, 0},
	} {
		r, err := allowed(rules, vs, tc.source, tc.target, tc.readOnly)
		switch {
		case tc.line == 0 && err == nil:
			t.Errorf("%s -> %s (ro %v): allowed by line %d, want denied", tc.source, tc.target, tc.readOnly, r.Line)
		case tc.line != 0 && (err != nil || r.Line != tc.line):
			t.Errorf("%s -> %s (ro %v): got line %d, %v; want line %d", tc.source, tc.target, tc.readOnly, r.Line, err, tc.line)
		}
	}

	_, err = allowed(rules, vs, `D:\media\films`, `C:\media\films`, false)
	if !errors.Is(err, errNotAllowed) || !strings.Contains(err.Error(), "--ro") {
		t.Errorf("read-write under a read-only rule: got %v, want a denial that suggests --ro", err)
	}
	_, err = allowed(rules, vs, `C:\a`, `C:\b`, false)
	if !errors.Is(err, errNotAllowed) || strings.Contains(err.Error(), "--ro") || !strings.Contains(err.Error(), "line 4: %USERNAME%") {
		t.Errorf("got %v, want a denial that mentions the skipped rule", err)
	}
}

func TestWhitelistVars(t *testing.T) {
	tok := windows.GetCurrentProcessToken()
	vs := whitelistVars(tok)
	for _, name := range varNames {
		if v := vs[name]; v.err != nil || v.value == "" {
			t.Errorf("%%%s%%: %q, %v", name, v.value, v.err)
		}
	}

	path := func(p string) string {
		t.Helper()
		p, err := canonicalPath(p)
		if err != nil {
			t.Fatal(err)
		}
		return escapeMeta(p)
	}
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := tok.GetUserProfileDirectory()
	if err != nil {
		t.Fatal(err)
	}
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"PROGRAMFILES": path(pf),
		"USERPROFILE":  path(profile),
		"APPDATA":      path(filepath.Join(profile, "AppData", "Roaming")),
		"LOCALAPPDATA": path(filepath.Join(profile, "AppData", "Local")),
		"USERNAME":     escapeMeta(name),
		"USERDOMAIN":   escapeMeta(domain),
		"SYSTEMDRIVE":  escapeMeta(os.Getenv("SystemDrive")),
	} {
		if got := vs[name].value; !strings.EqualFold(got, want) {
			t.Errorf("%%%s%% = %q, want %q", name, got, want)
		}
	}
}

func TestPinDir(t *testing.T) {
	dir := canonical(t, t.TempDir())
	a := filepath.Join(dir, "a")
	b := filepath.Join(a, "b")
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}

	release, err := pinDir(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a, b} {
		if err := os.Rename(p, p+"2"); err == nil {
			t.Errorf("renamed %s while pinned", p)
		}
	}
	release()
	if err := os.Rename(a, a+"2"); err != nil {
		t.Fatalf("rename after release: %v", err)
	}

	// pinDir refuses a path that resolves elsewhere, as after a swap.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", a, a+"2").CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v\n%s", err, out)
	}
	if _, err := pinDir(b); err == nil || !strings.Contains(err.Error(), "path changed") {
		t.Errorf("pinDir through a junction: got %v, want a changed path", err)
	}
}
