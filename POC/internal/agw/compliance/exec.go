package compliance

import (
	"bytes"
	"context"
	"os/exec"
)

type commandRunner func(ctx context.Context, cwd, name string, args ...string) (stdout, stderr string, err error)

var runExternalCommand commandRunner = defaultRunExternalCommand

func defaultRunExternalCommand(ctx context.Context, cwd, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
