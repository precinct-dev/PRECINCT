// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io"
	"log/slog"
	"os"
)

// InitLogger configures the global slog default logger.
// When jsonOutput is true, logs are emitted as structured JSON to stdout.
// When false, logs use the human-readable text format to stderr.
//
// Call this once at process startup (e.g., in main or NewGateway)
// before any slog calls are made.
func InitLogger(jsonOutput bool) {
	initLoggerWithWriter(jsonOutput, nil)
}

// initLoggerWithWriter is the internal implementation used by tests.
// It accepts an explicit writer so tests can capture log output.
func initLoggerWithWriter(jsonOutput bool, w io.Writer) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	var handler slog.Handler
	if jsonOutput {
		if w == nil {
			w = os.Stdout
		}
		handler = slog.NewJSONHandler(w, opts)
	} else {
		if w == nil {
			w = os.Stderr
		}
		handler = slog.NewTextHandler(w, opts)
	}
	slog.SetDefault(slog.New(handler))
}
