// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// newX509Source creates a new workloadapi.X509Source connected to the SPIRE
// Agent at the given socket path. It validates that the socket file exists
// before attempting to connect, providing a fast and clear failure message.
//
// The returned source must be closed by the caller when no longer needed
// (typically during graceful shutdown via setX509Closer).
func newX509Source(ctx context.Context, socketPath string) (*workloadapi.X509Source, error) {
	// Fail fast: check that the socket file exists before trying to connect.
	cleanPath := socketPath
	// Strip unix:// prefix for filesystem check if present.
	if len(cleanPath) > 7 && cleanPath[:7] == "unix://" {
		cleanPath = cleanPath[7:]
	}
	if _, err := os.Stat(cleanPath); err != nil {
		return nil, fmt.Errorf("socket not found: %w", err)
	}

	addr := formatSpireAddr(socketPath)
	src, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(addr)),
	)
	if err != nil {
		return nil, err
	}
	return src, nil
}
