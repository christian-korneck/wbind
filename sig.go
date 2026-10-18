//go:build windows

package main

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
	"golang.org/x/sys/windows"
)

const (
	defaultWhitelistFile  = "wbind.whitelist.txt"
	defaultSigFile        = "wbind.sig.txt"
	defaultPrivateKeyFile = "wbind.privkey.txt"
	defaultPublicKeyFile  = "wbind.pubkey.txt"

	// sigContext separates whitelist signatures from other uses of a key.
	sigContext = "wbind-whitelist-v1"
)

var errSignature = errors.New("whitelist: signature does not match the helper service's public key")

// signedWhitelist is the raw content of a whitelist file and of its
// signature file, as sent to the helper service.
type signedWhitelist struct {
	list, sig []byte
}

// readWhitelist reads the files of --whitelist-file and --sig-file in
// --whitelist mode, and returns nil otherwise. It checks that the list
// parses, so that mistakes show up with the file name.
func readWhitelist(cmd *cli.Command) (*signedWhitelist, error) {
	if !cmd.Bool("whitelist") {
		for _, f := range []string{"whitelist-file", "sig-file"} {
			if cmd.IsSet(f) {
				return nil, fmt.Errorf("--%s needs --whitelist", f)
			}
		}
		return nil, nil
	}
	listFile, sigFile := cmd.String("whitelist-file"), cmd.String("sig-file")
	if listFile == "-" && sigFile == "-" {
		return nil, errors.New("only one of --whitelist-file and --sig-file can read stdin")
	}
	list, err := readInput(cmd, listFile)
	if err != nil {
		return nil, err
	}
	if _, err := parseWhitelist(list); err != nil {
		return nil, fmt.Errorf("%s: %w", listFile, err)
	}
	sig, err := readInput(cmd, sigFile)
	if err != nil {
		return nil, err
	}
	return &signedWhitelist{list: list, sig: sig}, nil
}

// verifyWhitelist checks sig against list and returns list's rules.
func verifyWhitelist(pub *mldsa.PublicKey, list, sig []byte) ([]rule, error) {
	rules, err := parseWhitelist(list)
	if err != nil {
		return nil, fmt.Errorf("whitelist: %w", err)
	}
	s, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	if mldsa.Verify(pub, signedMessage(rules), s, &mldsa.Options{Context: sigContext}) != nil {
		return nil, errSignature
	}
	return rules, nil
}

// readInput reads file, or stdin if file is "-".
func readInput(cmd *cli.Command, file string) ([]byte, error) {
	if file == "-" {
		r := cmd.Root().Reader
		if r == nil {
			r = os.Stdin
		}
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, cause(err))
	}
	return b, nil
}

func keygenAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 0 {
		return errors.New("sig keygen: expected no arguments (see 'wbind sig keygen --help')")
	}
	if err := keygen(cmd.String("private"), cmd.String("public")); err != nil {
		return fmt.Errorf("sig keygen: %w", err)
	}
	return nil
}

// keygen writes a new ML-DSA-65 key pair as PEM: the private key as PKCS #8,
// the public key as PKIX. It never overwrites a file.
func keygen(privFile, pubFile string) error {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return err
	}
	for _, f := range []string{privFile, pubFile} {
		if _, err := os.Lstat(f); err == nil {
			return fmt.Errorf("%s: %w", f, os.ErrExist)
		}
	}
	if err := writeNew(privFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})); err != nil {
		return err
	}
	if err := writeNew(pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})); err != nil {
		os.Remove(privFile)
		return err
	}
	return nil
}

// writeNew writes b to file, which must not exist.
func writeNew(file string, b []byte) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%s: %w", file, cause(err))
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", file, cause(err))
	}
	return f.Close()
}

func exampleAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 0 {
		return errors.New("sig example: expected no arguments (see 'wbind sig example --help')")
	}
	out := cmd.String("output")
	if !cmd.Bool("force") {
		if err := writeNew(out, []byte(exampleWhitelist)); err != nil {
			return fmt.Errorf("sig example: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(out, []byte(exampleWhitelist), 0o666); err != nil {
		return fmt.Errorf("sig example: %s: %w", out, cause(err))
	}
	return nil
}

func signAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 0 {
		return errors.New("sig sign: expected no arguments (see 'wbind sig sign --help')")
	}
	keyFile, listFile := cmd.String("key"), cmd.String("whitelist-file")
	if keyFile == "-" && listFile == "-" {
		return errors.New("sig sign: only one of --key and --whitelist-file can read stdin")
	}
	b, err := readInput(cmd, keyFile)
	if err != nil {
		return fmt.Errorf("sig sign: %w", err)
	}
	key, err := parsePrivateKey(b)
	if err != nil {
		return fmt.Errorf("sig sign: %s: %w", keyFile, err)
	}
	list, err := readInput(cmd, listFile)
	if err != nil {
		return fmt.Errorf("sig sign: %w", err)
	}
	rules, err := parseWhitelist(list)
	if err != nil {
		return fmt.Errorf("sig sign: %s: %w", listFile, err)
	}
	sig, err := key.Sign(nil, signedMessage(rules), &mldsa.Options{Context: sigContext})
	if err != nil {
		return fmt.Errorf("sig sign: %w", err)
	}

	text := encodeSig(sig)
	if out := cmd.String("output"); out != "-" {
		if err := os.WriteFile(out, []byte(text), 0o666); err != nil {
			return fmt.Errorf("sig sign: %s: %w", out, cause(err))
		}
		return nil
	}
	_, err = fmt.Fprint(cmd.Root().Writer, text)
	return err
}

func sigTestAction(_ context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 2 {
		return errors.New("sig test: expected SOURCE and TARGET (see 'wbind sig test --help')")
	}
	// The same paths that the service checks.
	source, err := canonicalPath(cmd.Args().Get(0))
	if err != nil {
		return fmt.Errorf("sig test: %w", err)
	}
	target, err := canonicalPath(cmd.Args().Get(1))
	if err != nil {
		return fmt.Errorf("sig test: %w", err)
	}
	listFile := cmd.String("whitelist-file")
	list, err := readInput(cmd, listFile)
	if err != nil {
		return fmt.Errorf("sig test: %w", err)
	}
	rules, err := parseWhitelist(list)
	if err != nil {
		return fmt.Errorf("sig test: %s: %w", listFile, err)
	}

	r, err := allowed(rules, whitelistVars(windows.GetCurrentProcessToken()), source, target, cmd.Bool("ro"))
	if err != nil {
		return fmt.Errorf("sig test: %w", err)
	}
	_, err = fmt.Fprintf(cmd.Root().Writer, "allowed by line %d: %s\n", r.Line, r)
	return err
}

// loadPublicKey reads a public key file written by keygen.
func loadPublicKey(file string) (*mldsa.PublicKey, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, cause(err))
	}
	pub, err := parsePublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return pub, nil
}

func parsePublicKey(b []byte) (*mldsa.PublicKey, error) {
	der, err := pemBlock(b, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ML-DSA public key (%T)", k)
	}
	return pub, nil
}

func parsePrivateKey(b []byte) (*mldsa.PrivateKey, error) {
	der, err := pemBlock(b, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ML-DSA private key (%T)", k)
	}
	return key, nil
}

func pemBlock(b []byte, typ string) ([]byte, error) {
	text, err := decodeText(b)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("not a PEM %s", typ)
	}
	return block.Bytes, nil
}

// encodeSig returns the content of a signature file: base64 on one line.
func encodeSig(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig) + "\n"
}

// parseSignature decodes the base64 of a signature file. Whitespace,
// including line breaks, is ignored.
func parseSignature(b []byte) ([]byte, error) {
	text, err := decodeText(b)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		return nil, errors.New("signature: not base64")
	}
	return sig, nil
}
