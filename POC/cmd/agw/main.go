package main

import (
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.Execute(); err != nil {
		// Cobra will already have printed the error if SilenceErrors=false; we set it true,
		// so print here to keep a single, consistent error path.
		_, _ = io.WriteString(stderr, err.Error()+"\n")
		return 1
	}
	return 0
}

