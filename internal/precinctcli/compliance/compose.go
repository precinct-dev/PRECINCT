package compliance

import (
	"os"
	"path/filepath"
	"strings"
)

func composeArgs(projectRoot string, extra ...string) []string {
	root := strings.TrimSpace(projectRoot)
	if root == "" {
		if wd, err := os.Getwd(); err == nil {
			if detected, findErr := FindProjectRoot(wd); findErr == nil {
				root = detected
			} else {
				root = wd
			}
		} else {
			root = "."
		}
	}

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
