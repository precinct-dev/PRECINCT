// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// ws-e2e-client is a minimal CLI tool for E2E testing WebSocket endpoints.
// It connects, authenticates, sends a single method frame, prints the response
// JSON to stdout, and exits 0 on success (ok==true) or 1 on failure.
//
// Usage:
//
//	ws-e2e-client -url wss://localhost:8443/openclaw/ws -method message.send -params '{"platform":"whatsapp",...}'
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	url := flag.String("url", "wss://localhost:8443/openclaw/ws", "WebSocket URL")
	method := flag.String("method", "", "WS method to invoke")
	params := flag.String("params", "{}", "JSON params for the method")
	role := flag.String("role", "operator", "Role for connect frame")
	scopes := flag.String("scopes", "", "Comma-separated scopes")
	spiffeID := flag.String("spiffe-id", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev", "SPIFFE identity header for gateway auth")
	sessionID := flag.String("session-id", "openclaw-ws-e2e", "Session identifier header")
	flag.Parse()

	if *method == "" {
		fmt.Fprintln(os.Stderr, "error: -method is required")
		os.Exit(1)
	}

	headers := http.Header{}
	if strings.TrimSpace(*spiffeID) != "" {
		headers.Set("X-SPIFFE-ID", strings.TrimSpace(*spiffeID))
	}
	if strings.TrimSpace(*sessionID) != "" {
		headers.Set("X-Session-ID", strings.TrimSpace(*sessionID))
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // E2E client for local testing only
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.Dial(*url, headers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: dial %s: %v\n", *url, err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	// Parse scopes.
	var scopeList []string
	if *scopes != "" {
		scopeList = strings.Split(*scopes, ",")
	}

	// Send connect frame.
	connectFrame := map[string]any{
		"type": "req", "id": "e2e-connect", "method": "connect",
		"params": map[string]any{
			"role":   *role,
			"scopes": scopeList,
		},
	}
	if err := conn.WriteJSON(connectFrame); err != nil {
		fmt.Fprintf(os.Stderr, "error: write connect: %v\n", err)
		os.Exit(1)
	}
	var connectResp map[string]any
	if err := conn.ReadJSON(&connectResp); err != nil {
		fmt.Fprintf(os.Stderr, "error: read connect response: %v\n", err)
		os.Exit(1)
	}
	if ok, _ := connectResp["ok"].(bool); !ok {
		resp, _ := json.Marshal(connectResp)
		fmt.Fprintf(os.Stderr, "error: connect failed: %s\n", string(resp))
		os.Exit(1)
	}

	// Parse params.
	var paramMap map[string]any
	if err := json.Unmarshal([]byte(*params), &paramMap); err != nil {
		fmt.Fprintf(os.Stderr, "error: parse params: %v\n", err)
		os.Exit(1)
	}

	// Send method frame.
	methodFrame := map[string]any{
		"type": "req", "id": "e2e-1", "method": *method,
		"params": paramMap,
	}
	if err := conn.WriteJSON(methodFrame); err != nil {
		fmt.Fprintf(os.Stderr, "error: write method frame: %v\n", err)
		os.Exit(1)
	}
	var methodResp map[string]any
	if err := conn.ReadJSON(&methodResp); err != nil {
		fmt.Fprintf(os.Stderr, "error: read method response: %v\n", err)
		os.Exit(1)
	}

	// Print response as JSON to stdout.
	out, _ := json.MarshalIndent(methodResp, "", "  ")
	fmt.Println(string(out))

	// Exit based on ok field.
	if ok, _ := methodResp["ok"].(bool); !ok {
		os.Exit(1)
	}
}
