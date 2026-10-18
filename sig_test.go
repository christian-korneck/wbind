//go:build windows

package main

import (
	"crypto/mldsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/sys/windows"
)

// signWhitelist writes text and its signature to files and returns them
// with the public key that verifies them.
func signWhitelist(t *testing.T, text string) (pub *mldsa.PublicKey, list, sig string) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	rules, err := parseWhitelist([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	s, err := key.SignDeterministic(signedMessage(rules), &mldsa.Options{Context: sigContext})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	list, sig = filepath.Join(dir, "wl.txt"), filepath.Join(dir, "sig.txt")
	writeFile(t, list, text)
	writeFile(t, sig, encodeSig(s))
	return key.PublicKey(), list, sig
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "key.txt"), filepath.Join(dir, "pub.txt")
	wl, sig := filepath.Join(dir, "wl.txt"), filepath.Join(dir, "sig.txt")
	writeFile(t, wl, "# tools\nD:/tools/** | %PROGRAMFILES%/App/plugins\n")

	if _, err := run(t, "sig", "keygen", "--private", priv, "--public", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "sig", "keygen", "--private", priv, "--public", filepath.Join(dir, "other.txt")); err == nil {
		t.Error("keygen overwrote a key")
	}
	if _, err := run(t, "sig", "sign", "--key", priv, "--whitelist-file", wl, "--output", sig); err != nil {
		t.Fatal(err)
	}
	key, err := loadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWhitelist(key, readFile(t, wl), readFile(t, sig)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// stdin and stdout
	out, err := runStdin(t, string(readFile(t, wl)), "sig", "sign", "--key", priv, "--whitelist-file", "-", "--output", "-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWhitelist(key, readFile(t, wl), []byte(out)); err != nil {
		t.Errorf("verify the signature from stdout: %v", err)
	}
	if _, err := runStdin(t, "", "sig", "sign", "--key", "-", "--whitelist-file", "-"); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Errorf("two inputs from stdin: %v", err)
	}

	if _, err := verifyWhitelist(key, []byte("# changed comment\r\nD:/tools/**|%PROGRAMFILES%/App/plugins"), readFile(t, sig)); err != nil {
		t.Errorf("a formatting change broke the signature: %v", err)
	}
	if _, err := verifyWhitelist(key, []byte("D:/tools/** | %PROGRAMFILES%/**"), readFile(t, sig)); !errors.Is(err, errSignature) {
		t.Errorf("changed rule: got %v, want %v", err, errSignature)
	}
	other, _, _ := signWhitelist(t, "C:/a | C:/b")
	if _, err := verifyWhitelist(other, readFile(t, wl), readFile(t, sig)); !errors.Is(err, errSignature) {
		t.Errorf("other key: got %v, want %v", err, errSignature)
	}
	if _, err := verifyWhitelist(key, readFile(t, wl), readFile(t, sig)[:100]); err == nil {
		t.Error("truncated signature verified")
	}
}

func TestSigExample(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := run(t, "sig", "example"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, defaultWhitelistFile, "C:/a | C:/b\n")
	if _, err := run(t, "sig", "example"); err == nil {
		t.Error("second run: want an error")
	}
	if got := string(readFile(t, defaultWhitelistFile)); got != "C:/a | C:/b\n" {
		t.Errorf("second run overwrote the file: %q", got)
	}
	if _, err := run(t, "sig", "example", "--force"); err != nil {
		t.Fatal(err)
	}
	if got := string(readFile(t, defaultWhitelistFile)); got != exampleWhitelist {
		t.Error("--force did not overwrite the file")
	}
	if _, err := run(t, "sig", "example", "--output", "other.txt"); err != nil {
		t.Fatal(err)
	}
	if got := string(readFile(t, "other.txt")); got != exampleWhitelist {
		t.Error("--output did not write the example")
	}

	// As written, nothing is allowed.
	if _, err := parseWhitelist([]byte(exampleWhitelist)); err == nil || !strings.Contains(err.Error(), "no rules") {
		t.Errorf("example as written: got %v, want no rules", err)
	}
	for _, name := range varNames {
		if !strings.Contains(exampleWhitelist, "%"+name+"%") {
			t.Errorf("the example does not use %%%s%%", name)
		}
	}
	for _, mode := range []string{"| ro\n", "| rw\n"} {
		if !strings.Contains(exampleWhitelist, mode) {
			t.Errorf("the example has no rule ending in %q", mode)
		}
	}

	// Uncommented, every rule parses.
	var uncommented []string
	for line := range strings.Lines(exampleWhitelist) {
		if len(line) > 1 && line[0] == '#' && line[1] != '#' && !unicode.IsSpace(rune(line[1])) {
			line = line[1:]
		}
		uncommented = append(uncommented, line)
	}
	rules, err := parseWhitelist([]byte(strings.Join(uncommented, "")))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 20 {
		t.Errorf("only %d rules", len(rules))
	}
	anything := rules[len(rules)-1]
	if anything.Source != "**" || anything.Target != "**" {
		t.Fatalf("last rule is %s, want ** | **", anything)
	}
	for _, pair := range [][2]string{{`C:\a`, `D:\b`}, {`\\server\share\x`, `C:\y`}, {`D:\[x]\100%`, `C:\Program Files\App`}} {
		if _, err := allowed([]rule{anything}, vars{}, pair[0], pair[1], false); err != nil {
			t.Errorf("** | **: %v", err)
		}
	}
}

func TestWhitelistExampleUpToDate(t *testing.T) {
	got := strings.ReplaceAll(string(readFile(t, "wbind.whitelist.example.txt")), "\r\n", "\n")
	if got != exampleWhitelist {
		t.Error("wbind.whitelist.example.txt is stale: run `go generate ./...`")
	}
}

func TestSigTest(t *testing.T) {
	profile, err := windows.GetCurrentProcessToken().GetUserProfileDirectory()
	if err != nil {
		t.Fatal(err)
	}
	src := canonical(t, t.TempDir())
	wl := filepath.Join(t.TempDir(), "wl.txt")
	writeFile(t, wl, "C:/nowhere | C:/nowhere\n"+escapeMeta(src)+"/** | %USERPROFILE%/mnt/*\n"+escapeMeta(src)+"/** | %USERPROFILE%/ro/* | ro\n")

	out, err := run(t, "sig", "test", "--whitelist-file", wl, filepath.Join(src, "a"), filepath.Join(profile, "mnt", "x"))
	if want := "allowed by line 2: "; err != nil || !strings.HasPrefix(out, want) {
		t.Errorf("got %q, %v; want %q...", out, err, want)
	}
	_, err = run(t, "sig", "test", "--whitelist-file", wl, filepath.Join(src, "a"), filepath.Join(profile, "other", "x"))
	if err == nil || !strings.Contains(err.Error(), "not allowed by the whitelist") {
		t.Errorf("got %v, want a denial", err)
	}

	out, err = run(t, "sig", "test", "--ro", "--whitelist-file", wl, filepath.Join(src, "a"), filepath.Join(profile, "ro", "x"))
	if want := "allowed by line 3: "; err != nil || !strings.HasPrefix(out, want) || !strings.HasSuffix(out, " | ro\n") {
		t.Errorf("--ro: got %q, %v; want %q... | ro", out, err, want)
	}
	_, err = run(t, "sig", "test", "--whitelist-file", wl, filepath.Join(src, "a"), filepath.Join(profile, "ro", "x"))
	if err == nil || !strings.Contains(err.Error(), "--ro") {
		t.Errorf("read-write under a read-only rule: got %v, want a denial that suggests --ro", err)
	}
}
