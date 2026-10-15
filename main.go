//go:build windows

// Command wbind creates, removes and lists bind mounts on Windows. It is a
// thin CLI over the Windows bind filter (bindflt), using go-winio's
// bindfilter package.
package main

//go:generate go run . docs --output cli-reference.md

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
		Commands: []*cli.Command{
			{
				Name:      "mount",
				Usage:     "bind SOURCE (directory or file) at TARGET",
				ArgsUsage: "SOURCE TARGET",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "ro", Aliases: []string{"r"}, Usage: "mount read-only"},
				},
				Action: mountAction,
			},
			{
				Name:      "unmount",
				Usage:     "remove the bind mount at TARGET",
				ArgsUsage: "TARGET",
				Action:    unmountAction,
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
