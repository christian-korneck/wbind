//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
	"golang.org/x/sys/windows"
)

var errNotAllowed = errors.New("not allowed by the whitelist")

// rule is one line of a whitelist: SOURCE may be mounted at TARGET if they
// match Source and Target, which are doublestar patterns with %VARIABLES%
// (see expand). With ReadOnly, only read-only mounts are allowed.
type rule struct {
	Line           int
	Source, Target string
	ReadOnly       bool
}

func (r rule) String() string {
	if r.ReadOnly {
		return r.Source + " | " + r.Target + " | ro"
	}
	return r.Source + " | " + r.Target
}

// parseWhitelist parses a whitelist: one "SOURCE | TARGET [| ro|rw]" rule
// per line, rw if the mode is left out. Blank lines and lines starting
// with # are ignored. Windows paths cannot contain |, so it cannot clash
// with a path. Every pattern is validated, so that a broken list fails here
// and not when it is matched.
func parseWhitelist(raw []byte) ([]rule, error) {
	text, err := decodeText(raw)
	if err != nil {
		return nil, err
	}
	var rules []rule
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		for j := range fields {
			fields[j] = strings.TrimSpace(fields[j])
		}
		r := rule{Line: i + 1}
		switch {
		case len(fields) == 3 && strings.EqualFold(fields[2], "ro"):
			r.ReadOnly = true
		case len(fields) == 3 && strings.EqualFold(fields[2], "rw"), len(fields) == 2:
		default:
			return nil, fmt.Errorf("line %d: expected SOURCE | TARGET [| ro|rw]", i+1)
		}
		r.Source, r.Target = fields[0], fields[1]
		if r.Source == "" || r.Target == "" {
			return nil, fmt.Errorf("line %d: expected SOURCE | TARGET [| ro|rw]", i+1)
		}
		for _, p := range []string{r.Source, r.Target} {
			if err := validatePattern(p); err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, errors.New("no rules")
	}
	return rules, nil
}

// signedMessage is what a whitelist signature covers: the rules in a
// canonical form, "SOURCE|TARGET" plus "|ro" for read-only rules. Comments,
// whitespace around the separators, an explicit rw, line endings and the
// text encoding are not part of it, so changing them keeps the signature
// valid, while any change to a rule breaks it. Neither pattern can contain
// | or a line break, so the form is unambiguous.
func signedMessage(rules []rule) []byte {
	var b bytes.Buffer
	for _, r := range rules {
		b.WriteString(r.Source + "|" + r.Target)
		if r.ReadOnly {
			b.WriteString("|ro")
		}
		b.WriteString("\n")
	}
	return b.Bytes()
}

// decodeText decodes a text file: UTF-8 with or without BOM, or UTF-16
// with BOM, which PowerShell 5.1's Out-File and > write.
func decodeText(b []byte) (string, error) {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		b = b[3:]
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return decodeUTF16(b[2:], binary.LittleEndian)
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		return decodeUTF16(b[2:], binary.BigEndian)
	}
	if !utf8.Valid(b) {
		return "", errors.New("not UTF-8 or UTF-16 text")
	}
	return string(b), nil
}

func decodeUTF16(b []byte, order binary.ByteOrder) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("truncated UTF-16 text")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = order.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u)), nil
}

// vars maps the names of whitelist variables (upper case) to their values,
// escaped for doublestar. A variable whose value cannot be determined holds
// the error instead, which fails only the rules that use it.
type vars map[string]varValue

type varValue struct {
	value string
	err   error
}

// Whitelist variables. They look like environment variables, but are not
// taken from any environment: the system ones are looked up through the
// APIs that report the actual install locations, the user ones from the
// account of the caller (see userVars).
var (
	systemDirs = map[string]*windows.KNOWNFOLDERID{
		"PROGRAMFILES":            windows.FOLDERID_ProgramFiles,
		"PROGRAMFILES(X86)":       windows.FOLDERID_ProgramFilesX86,
		"COMMONPROGRAMFILES":      windows.FOLDERID_ProgramFilesCommon,
		"COMMONPROGRAMFILES(X86)": windows.FOLDERID_ProgramFilesCommonX86,
		"PROGRAMDATA":             windows.FOLDERID_ProgramData,
		"ALLUSERSPROFILE":         windows.FOLDERID_ProgramData,
		"PUBLIC":                  windows.FOLDERID_Public,
	}
	varNames = append(slices.Collect(maps.Keys(systemDirs)), "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR",
		"USERPROFILE", "APPDATA", "LOCALAPPDATA", "USERNAME", "USERDOMAIN")
)

// whitelistVars returns the values of all whitelist variables for the user
// of token t.
func whitelistVars(t windows.Token) vars {
	vs := vars{}
	root, err := windows.GetSystemWindowsDirectory()
	vs.setPath("SYSTEMROOT", root, err)
	vs.setPath("WINDIR", root, err)
	vs.set("SYSTEMDRIVE", filepath.VolumeName(root), err)
	for name, id := range systemDirs {
		dir, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT)
		vs.setPath(name, dir, err)
	}
	userVars(vs, t)
	return vs
}

// userVars adds the variables of the user of token t. The profile directory
// comes from HKLM's ProfileList, which only administrators can change.
// %APPDATA% and %LOCALAPPDATA% are deliberately the default folders in the
// profile: the user's shell folder settings, which redirect them, live in
// the user's own registry hive, so the user could point them anywhere.
func userVars(vs vars, t windows.Token) {
	var name, domain string
	u, err := t.GetTokenUser()
	if err == nil {
		name, domain, _, err = u.User.Sid.LookupAccount("")
	}
	vs.set("USERNAME", name, err)
	vs.set("USERDOMAIN", domain, err)

	profile, err := t.GetUserProfileDirectory()
	vs.setPath("USERPROFILE", profile, err)
	vs.setPath("APPDATA", filepath.Join(profile, "AppData", "Roaming"), err)
	vs.setPath("LOCALAPPDATA", filepath.Join(profile, "AppData", "Local"), err)
}

func (vs vars) set(name, value string, err error) {
	if err != nil {
		vs[name] = varValue{err: err}
		return
	}
	vs[name] = varValue{value: escapeMeta(value)}
}

// setPath sets a path variable to the canonical form of p, which is what
// request paths are compared in (see canonicalPath).
func (vs vars) setPath(name, p string, err error) {
	if err == nil {
		p, err = canonicalPath(p)
	}
	vs.set(name, p, err)
}

// escapeMeta turns p, a Windows path or account name, into a doublestar
// pattern that matches just p: with / as separator and the metacharacters
// escaped. Escaping , matters inside {alternatives}.
func escapeMeta(p string) string {
	var b strings.Builder
	for _, c := range filepath.ToSlash(p) {
		if strings.ContainsRune(`\*?[]{},`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// expand replaces the %VARIABLES% in pattern (case-insensitive names) by
// their values. Backslash escapes, as in doublestar, so \% is a literal %.
func expand(pattern string, vs vars) (string, error) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '\\':
			b.WriteByte(c)
			if i+1 < len(pattern) {
				i++
				b.WriteByte(pattern[i])
			}
		case '%':
			end := strings.IndexByte(pattern[i+1:], '%')
			if end < 0 {
				return "", fmt.Errorf("%s: unclosed %%VARIABLE%% (write \\%% for a literal %%)", pattern)
			}
			name := strings.ToUpper(pattern[i+1 : i+1+end])
			v, ok := vs[name]
			switch {
			case !ok:
				return "", fmt.Errorf("%s: unknown variable %%%s%%", pattern, name)
			case v.err != nil:
				return "", fmt.Errorf("%%%s%%: %w", name, v.err)
			}
			b.WriteString(v.value)
			i += end + 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// validatePattern checks that p uses only known variables and is a valid
// doublestar pattern.
func validatePattern(p string) error {
	placeholders := vars{}
	for _, name := range varNames {
		placeholders[name] = varValue{value: "x"}
	}
	expanded, err := expand(p, placeholders)
	if err != nil {
		return err
	}
	if !doublestar.ValidatePattern(expanded) {
		return fmt.Errorf("%s: invalid pattern", p)
	}
	return checkDots(p)
}

// maxAlternatives limits the {a,b} alternatives of a pattern that
// checkDots expands, so that a crafted list cannot blow up parsing.
const maxAlternatives = 1000

// checkDots fails if an alternative of pattern p has a path element that
// is "." or "..", escapes removed. Paths are normalized before they are
// matched, so such a rule could never match anything. Variables need no
// expansion here: their values are whole canonical paths or account names,
// which cannot consist of periods only.
func checkDots(p string) error {
	alts, err := expandBraces(p)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	for _, alt := range alts {
		start := 0
		for _, i := range append(syntaxPositions(alt), len(alt)) {
			if i < len(alt) && alt[i] != '/' {
				continue
			}
			if e := unescape(alt[start:i]); e == "." || e == ".." {
				return fmt.Errorf(`%s: "." and ".." are not allowed in rules (paths are matched normalized)`, p)
			}
			start = i + 1
		}
	}
	return nil
}

// expandBraces returns the patterns that p's {a,b} groups, which may nest,
// stand for.
func expandBraces(p string) ([]string, error) {
	open, end, depth := -1, -1, 0
	var commas []int
	for _, i := range syntaxPositions(p) {
		switch p[i] {
		case '{':
			if depth == 0 {
				open = i
			}
			depth++
		case ',':
			if depth == 1 {
				commas = append(commas, i)
			}
		case '}':
			if depth--; depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 { // no group; an unbalanced one fails doublestar's validation
		return []string{p}, nil
	}

	bounds := append(append([]int{open}, commas...), end)
	var out []string
	for k := range len(bounds) - 1 {
		// The rest of p goes along, so that nested and later groups expand too.
		rest, err := expandBraces(p[bounds[k]+1:bounds[k+1]] + p[end+1:])
		if err != nil {
			return nil, err
		}
		for _, r := range rest {
			out = append(out, p[:open]+r)
		}
		if len(out) > maxAlternatives {
			return nil, fmt.Errorf("more than %d {a,b} alternatives", maxAlternatives)
		}
	}
	return out, nil
}

// syntaxPositions returns the indexes of the bytes of glob pattern p that
// can be syntax: those not escaped with \ and not inside a [...] class.
func syntaxPositions(p string) []int {
	var pos []int
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '[':
			for i++; i < len(p) && p[i] != ']'; i++ {
				if p[i] == '\\' {
					i++
				}
			}
		default:
			pos = append(pos, i)
		}
	}
	return pos
}

// unescape removes the \ escapes from p.
func unescape(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+1 < len(p) {
			i++
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// allowed returns the first rule that allows mounting source at target,
// both canonical paths, read-only or not. A read-only rule allows only
// read-only mounts, the others allow both. Matching is case-insensitive,
// like Windows paths: doublestar has no such option for Match, so both
// sides are lowercased, which leaves the metacharacters alone.
func allowed(rules []rule, vs vars, source, target string, readOnly bool) (rule, error) {
	src, tgt := matchPath(source), matchPath(target)
	var skipped []string
	onlyRO := false // the paths match a read-only rule
	for _, r := range rules {
		ok, err := r.matches(vs, src, tgt)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("line %d: %v", r.Line, err))
			continue
		}
		if ok && r.ReadOnly && !readOnly {
			onlyRO = true
			continue
		}
		if ok {
			return r, nil
		}
	}
	err := fmt.Errorf("%s: source %s: %w", target, source, errNotAllowed)
	if onlyRO {
		err = fmt.Errorf("%w: only read-only mounts (--ro) are allowed", err)
	}
	if len(skipped) > 0 {
		err = fmt.Errorf("%w (skipped %s)", err, strings.Join(skipped, "; "))
	}
	return rule{}, err
}

func (r rule) matches(vs vars, source, target string) (bool, error) {
	for _, m := range [...]struct{ pattern, path string }{{r.Source, source}, {r.Target, target}} {
		p, err := expand(m.pattern, vs)
		if err != nil {
			return false, err
		}
		if ok, err := doublestar.Match(strings.ToLower(p), m.path); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// matchPath turns a canonical path into the form that patterns match.
func matchPath(p string) string {
	return strings.ToLower(filepath.ToSlash(p))
}
