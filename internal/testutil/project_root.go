// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Package testutil provides test helpers for the project.
//
// The primary helper is ProjectRoot(), which returns the absolute path to the
// project root directory (where go.mod lives). This eliminates fragile
// relative paths like "../../config/opa" in test files, which break when
// tests are run from different working directories.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	projectRootOnce sync.Once
	projectRootPath string
)

// ProjectRoot returns the absolute path to the project root directory
// (the directory containing go.mod). It uses runtime.Caller to locate
// the source file and walks up until it finds go.mod.
//
// The result is cached after the first call for performance.
//
// Panics if the project root cannot be found (should never happen in
// a properly structured Go project).
func ProjectRoot() string {
	projectRootOnce.Do(func() {
		// Get the absolute path of this source file
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("testutil.ProjectRoot: runtime.Caller failed")
		}

		// Walk up from this file's directory to find go.mod
		dir := filepath.Dir(thisFile)
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				projectRootPath = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				// Reached filesystem root without finding go.mod
				panic("testutil.ProjectRoot: could not find go.mod in any parent directory of " + thisFile)
			}
			dir = parent
		}
	})
	return projectRootPath
}

// OPAPolicyDir returns the absolute path to config/opa/ within the project.
func OPAPolicyDir() string {
	return filepath.Join(ProjectRoot(), "config", "opa")
}

// OPAPolicyPath returns the absolute path to config/opa/mcp_policy.rego.
func OPAPolicyPath() string {
	return filepath.Join(ProjectRoot(), "config", "opa", "mcp_policy.rego")
}

// ToolRegistryConfigPath returns the absolute path to config/tool-registry.yaml.
func ToolRegistryConfigPath() string {
	return filepath.Join(ProjectRoot(), "config", "tool-registry.yaml")
}

// UICapabilityGrantsPath returns the absolute path to config/opa/ui_capability_grants.yaml.
func UICapabilityGrantsPath() string {
	return filepath.Join(ProjectRoot(), "config", "opa", "ui_capability_grants.yaml")
}
