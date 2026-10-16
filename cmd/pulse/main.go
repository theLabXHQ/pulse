// Command pulse is a fast HTTP prober for reconnaissance pipelines.
package main

import (
	"os"

	"github.com/theLabXHQ/pulse/internal/cli"
	"github.com/theLabXHQ/pulse/internal/input"
)

func main() {
	isTTY := func(f *os.File) bool {
		fi, err := f.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
	os.Exit(cli.Main(os.Args[1:], cli.Env{
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		StdinPiped: input.StdinIsPiped(),
		StdoutTTY:  isTTY(os.Stdout),
		StderrTTY:  isTTY(os.Stderr),
	}))
}
