// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"fmt"
	"os"
	"path/filepath"
)

const taxonomyRelPath = "tools/compliance/control_taxonomy.yaml"

// FindProjectRoot walks upward from startDir until it finds the control taxonomy.
func FindProjectRoot(startDir string) (string, error) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, taxonomyRelPath)
		if _, err := os.Stat(candidate); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find %s starting from %s", taxonomyRelPath, startDir)
		}
		dir = parent
	}
}
