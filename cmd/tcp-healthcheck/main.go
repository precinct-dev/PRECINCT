// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// cmd/tcp-healthcheck performs a local listener health check without creating
// a network connection. It inspects /proc/net/tcp and /proc/net/tcp6 for a
// LISTEN socket on the configured port, which avoids TLS handshake EOF noise
// in servers that require mTLS (for example SPIKE Keeper).
//
// Environment variables:
//   - HEALTHCHECK_ADDR: TCP address to check (default: localhost:8443)
//
// Exit codes: 0 = healthy (port listening), 1 = unhealthy.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	addr := os.Getenv("HEALTHCHECK_ADDR")
	if addr == "" {
		addr = "localhost:8443"
	}

	port, err := parsePort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcp-healthcheck: parse %s: %v\n", addr, err)
		os.Exit(1)
	}

	listening, err := hasListeningPort("/proc/net/tcp", port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcp-healthcheck: inspect /proc/net/tcp: %v\n", err)
		os.Exit(1)
	}
	if !listening {
		listening, err = hasListeningPort("/proc/net/tcp6", port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp-healthcheck: inspect /proc/net/tcp6: %v\n", err)
			os.Exit(1)
		}
	}
	if !listening {
		fmt.Fprintf(os.Stderr, "tcp-healthcheck: port %d is not listening\n", port)
		os.Exit(1)
	}
}

func parsePort(addr string) (int, error) {
	idx := strings.LastIndex(addr, ":")
	if idx == -1 || idx == len(addr)-1 {
		return 0, fmt.Errorf("missing port")
	}
	return strconv.Atoi(addr[idx+1:])
}

func hasListeningPort(path string, port int) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	wantPort := strings.ToUpper(fmt.Sprintf("%04X", port))
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "sl" {
			continue
		}
		local := fields[1]
		state := fields[3]
		parts := strings.Split(local, ":")
		if len(parts) != 2 {
			continue
		}
		if parts[1] == wantPort && state == "0A" {
			return true, nil
		}
	}

	return false, nil
}
