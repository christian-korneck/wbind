//go:build windows

// Command wbind creates, removes and lists bind mounts on Windows. It is a
// thin CLI over the Windows bind filter (bindflt), using go-winio's
// bindfilter package.
package main

//go:generate go run . docs --output cli-reference.md
//go:generate go run . sig example --force --output wbind.whitelist.example.txt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	docs "github.com/urfave/cli-docs/v3"
	"github.com/urfave/cli/v3"
)

func main() {
	if err := newApp().Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "wbind:", err)
		os.Exit(1)
	}
}

// newApp builds the command tree. Tests use it to run the CLI in-process.
func newApp() *cli.Command {
	return &cli.Command{
		Name:            "wbind",
		Usage:           "bind mounts on MS Windows",
		Version:         buildVersion(),
		HideHelpCommand: true,
		// Root flags apply to all subcommands; those without use for it ignore it.
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "unprivileged", Aliases: []string{"u"}, Usage: "use the " + serviceName + " helper service, so that mount, unmount and list need no elevation"},
			&cli.BoolFlag{Name: "whitelist", Aliases: []string{"w"}, Usage: "send a signed whitelist (see --whitelist-file and --sig-file of mount and unmount) to a helper service installed with --pubkey; implies --unprivileged"},
		},
		Commands: []*cli.Command{
			{
				Name:      "mount",
				Usage:     "bind SOURCE (directory or file) at TARGET",
				ArgsUsage: "SOURCE TARGET",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "ro", Aliases: []string{"r"}, Usage: "mount read-only"},
					whitelistFileFlag("with --whitelist, "),
					sigFileFlag(),
				},
				Action: mountAction,
			},
			{
				Name:      "unmount",
				Usage:     "remove the bind mount at TARGET",
				ArgsUsage: "TARGET",
				Flags: []cli.Flag{
					whitelistFileFlag("with --whitelist, "),
					sigFileFlag(),
				},
				Action: unmountAction,
			},
			{
				Name:      "list",
				Aliases:   []string{"ls"},
				Usage:     "list all bind mounts, or only the one at TARGET",
				ArgsUsage: "[TARGET]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "noheadings", Aliases: []string{"n"}, Usage: "do not print a header line"},
				},
				Action: listAction,
			},
			{
				Name:            "helperservice",
				Usage:           "manage the " + serviceName + " helper service, which serves --unprivileged requests",
				HideHelpCommand: true,
				Commands: []*cli.Command{
					{
						Name:  "install",
						Usage: "copy wbind.exe to the system directory, then install and start the helper service from there",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "group", Usage: "let members of `GROUP` use the service; it is created if missing (default: " + defaultGroup + ", created with Authenticated Users as member)"},
							&cli.StringFlag{Name: "pubkey", Usage: "copy the public key `FILE` (see 'wbind sig keygen') next to wbind.exe and accept only mounts allowed by a whitelist signed with its private key"},
							&cli.BoolFlag{Name: "unmount-requires-whitelist", Usage: "with --pubkey, accept only unmounts allowed by the whitelist too (by default, anyone may unmount anything)"},
						},
						Action: installAction,
					},
					{
						Name:   "uninstall",
						Usage:  "stop and remove the helper service",
						Action: uninstallAction,
					},
				},
			},
			{
				Name:            "sig",
				Usage:           "generate keys, and sign and test whitelists for a helper service installed with --pubkey",
				HideHelpCommand: true,
				Commands: []*cli.Command{
					{
						Name:  "keygen",
						Usage: "create a new ML-DSA key pair",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "private", Value: defaultPrivateKeyFile, Usage: "write the private key to `FILE`, which must not exist"},
							&cli.StringFlag{Name: "public", Value: defaultPublicKeyFile, Usage: "write the public key to `FILE`, which must not exist"},
						},
						Action: keygenAction,
					},
					{
						Name:  "example",
						Usage: "write an example whitelist that shows all features, with all rules commented out",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "output", Value: defaultWhitelistFile, Usage: "write to `FILE`, which must not exist"},
							&cli.BoolFlag{Name: "force", Usage: "overwrite the --output file if it exists"},
						},
						Action: exampleAction,
					},
					{
						Name:  "sign",
						Usage: "sign a whitelist with a private key",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "key", Value: defaultPrivateKeyFile, Usage: "read the private key from `FILE` (- for stdin)"},
							whitelistFileFlag(""),
							&cli.StringFlag{Name: "output", Value: defaultSigFile, Usage: "write the signature to `FILE` (- for stdout)"},
						},
						Action: signAction,
					},
					{
						Name:      "test",
						Usage:     "check whether a whitelist allows the current user to bind SOURCE at TARGET (does not check a signature)",
						ArgsUsage: "SOURCE TARGET",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "ro", Aliases: []string{"r"}, Usage: "check a read-only mount"},
							whitelistFileFlag(""),
						},
						Action: sigTestAction,
					},
				},
			},
			{
				Name:   "daemon",
				Usage:  "run the helper service",
				Hidden: true,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "group", Usage: "let members of `GROUP` connect"},
					&cli.StringFlag{Name: "pubkey", Usage: "accept only mounts allowed by a whitelist signed for the public key `FILE`"},
					&cli.BoolFlag{Name: "unmount-requires-whitelist", Usage: "with --pubkey, accept only unmounts allowed by the whitelist too"},
				},
				Action: daemonAction,
			},
			{
				Name:  "docs",
				Usage: "show auto-generated cli reference docs",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Usage: "write to `FILE` instead of stdout"},
				},
				Action: docsAction,
			},
		},
	}
}

func whitelistFileFlag(prefix string) cli.Flag {
	return &cli.StringFlag{Name: "whitelist-file", Value: defaultWhitelistFile, Usage: prefix + "read the whitelist from `FILE` (- for stdin)"}
}

func sigFileFlag() cli.Flag {
	return &cli.StringFlag{Name: "sig-file", Value: defaultSigFile, Usage: "with --whitelist, read the whitelist's signature from `FILE` (- for stdin)"}
}

// docsAction renders the command tree as Markdown with cli-docs.
// `go generate` uses it to refresh cli-reference.md.
func docsAction(_ context.Context, cmd *cli.Command) error {
	text, err := docs.ToMarkdown(cmd.Root())
	if err != nil {
		return fmt.Errorf("docs: %w", err)
	}

	out := cmd.String("output")
	if out == "" {
		_, err = fmt.Fprint(cmd.Root().Writer, text)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o777); err != nil {
		return fmt.Errorf("docs: %w", err)
	}
	return os.WriteFile(out, []byte(text), 0o666)
}

// version is set by goreleaser through -X main.version. buildVersion falls
// back to the module version of `go install` builds, then to "(devel)".
var version string

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
