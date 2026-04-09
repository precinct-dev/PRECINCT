// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const precinctComposeFile = "deploy/compose/docker-compose.yml"

const (
	composeServiceExecMaxAttempts = 5
	composeServiceExecRetryDelay  = 300 * time.Millisecond
)

func composeProjectRoot() string {
	if root := strings.TrimSpace(os.Getenv("PRECINCT_PROJECT_ROOT")); root != "" {
		return root
	}
	if wd, err := os.Getwd(); err == nil {
		if root, findErr := findPrecinctProjectRoot(wd); findErr == nil {
			return root
		}
		return wd
	}
	return "."
}

func findPrecinctProjectRoot(startDir string) (string, error) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, precinctComposeFile)
		if _, err := os.Stat(candidate); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find %s starting from %s", precinctComposeFile, startDir)
		}
		dir = parent
	}
}

func composeArgs(extra ...string) []string {
	root := composeProjectRoot()
	args := []string{"compose"}

	if strings.EqualFold(strings.TrimSpace(os.Getenv("DEMO_SERVICE_MODE")), "real") {
		envFile := filepath.Join(root, ".env")
		if _, err := os.Stat(envFile); err == nil {
			args = append(args, "--env-file", envFile)
		}
		args = append(args,
			"-f", filepath.Join(root, "deploy", "compose", "docker-compose.yml"),
			"-f", filepath.Join(root, "deploy", "compose", "docker-compose.real.yml"),
		)
	} else {
		args = append(args,
			"-f", filepath.Join(root, "deploy", "compose", "docker-compose.yml"),
			"-f", filepath.Join(root, "deploy", "compose", "docker-compose.mock.yml"),
			"--profile", "mock",
		)
	}

	return append(args, extra...)
}

func RunComposeServiceCommand(ctx context.Context, service string, args ...string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", fmt.Errorf("compose service is empty")
	}

	var lastErr error
	for attempt := 1; attempt <= composeServiceExecMaxAttempts; attempt++ {
		out, err := runComposeServiceCommandOnce(ctx, service, args...)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !isRetryableComposeServiceError(err) || attempt == composeServiceExecMaxAttempts {
			break
		}
		if err := sleepWithContext(ctx, composeServiceExecRetryDelay*time.Duration(attempt)); err != nil {
			return "", lastErr
		}
	}

	return "", lastErr
}

func copyComposeServiceFile(ctx context.Context, service, srcPath string) ([]byte, error) {
	service = strings.TrimSpace(service)
	srcPath = strings.TrimSpace(srcPath)
	if service == "" {
		return nil, fmt.Errorf("compose service is empty")
	}
	if srcPath == "" {
		return nil, fmt.Errorf("compose source path is empty")
	}

	var lastErr error
	for attempt := 1; attempt <= composeServiceExecMaxAttempts; attempt++ {
		content, err := copyComposeServiceFileOnce(ctx, service, srcPath)
		if err == nil {
			return content, nil
		}
		lastErr = err
		if !isRetryableComposeServiceError(err) || attempt == composeServiceExecMaxAttempts {
			break
		}
		if err := sleepWithContext(ctx, composeServiceExecRetryDelay*time.Duration(attempt)); err != nil {
			return nil, lastErr
		}
	}

	return nil, lastErr
}

func runComposeServiceCommandOnce(ctx context.Context, service string, args ...string) (string, error) {
	containerID, err := resolveComposeServiceContainerID(ctx, service)
	if err != nil {
		return "", err
	}

	out, execErr := runDockerCommand(ctx, append([]string{"exec", "-i", containerID}, args...)...)
	if execErr != nil {
		return "", fmt.Errorf("docker exec -i %s %s: %w (output=%q)", containerID, strings.Join(args, " "), execErr, out)
	}
	return out, nil
}

func copyComposeServiceFileOnce(ctx context.Context, service, srcPath string) ([]byte, error) {
	containerID, err := resolveComposeServiceContainerID(ctx, service)
	if err != nil {
		return nil, err
	}

	tempDir, err := os.MkdirTemp("", "precinct-compose-copy-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dstPath := filepath.Join(tempDir, filepath.Base(srcPath))
	out, copyErr := runDockerCommand(ctx, "cp", fmt.Sprintf("%s:%s", containerID, srcPath), dstPath)
	if copyErr != nil {
		return nil, fmt.Errorf("docker cp %s:%s %s: %w (output=%q)", containerID, srcPath, dstPath, copyErr, out)
	}

	content, err := os.ReadFile(dstPath)
	if err != nil {
		return nil, fmt.Errorf("read copied file %s: %w", dstPath, err)
	}
	return content, nil
}

func resolveComposeServiceContainerID(ctx context.Context, service string) (string, error) {
	cmdArgs := composeArgs("ps", "-q", service)
	out, err := runDockerCommand(ctx, cmdArgs...)
	if err != nil {
		return "", fmt.Errorf("docker %s: %w (output=%q)", strings.Join(cmdArgs, " "), err, out)
	}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("compose service %q has no running container", service)
}

func runDockerCommand(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = composeProjectRoot()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func isRetryableComposeServiceError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such container") ||
		strings.Contains(msg, "has no running container") ||
		strings.Contains(msg, "is restarting") ||
		strings.Contains(msg, "container is restarting") ||
		strings.Contains(msg, "container is not running") ||
		strings.Contains(msg, "cannot exec in a stopped state") ||
		strings.Contains(msg, "signal: killed")
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
