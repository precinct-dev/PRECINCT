// Auto-detection logic for MCP transport type.
//
// DetectTransport tries Streamable HTTP first (the current MCP spec transport),
// and falls back to Legacy SSE (the deprecated pre-2025-03-26 transport) if the
// server does not support Streamable HTTP.
//
// This enables the gateway to work with both modern and legacy MCP servers
// without manual configuration.
//
// RFA-0dz: Legacy SSE transport + auto-detection.
package mcpclient

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

// DetectTransport probes the MCP server at baseURL and returns the appropriate
// Transport implementation.
//
// Detection order:
//  1. Try Streamable HTTP: POST an initialize request. If the server responds
//     with 200 and a valid JSON-RPC response, use StreamableHTTPTransport.
//  2. Try Legacy SSE: GET /sse. If the server responds with 200 and sends an
//     "endpoint" event, use LegacySSETransport. Log a deprecation warning.
//  3. If neither works, return an error.
//
// The returned Transport is fully initialized and ready for Send() calls.
func DetectTransport(ctx context.Context, baseURL string, httpClient *http.Client) (Transport, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Attempt 1: Streamable HTTP
	transport, err := tryStreamableHTTP(ctx, baseURL, httpClient)
	if err == nil {
		return transport, nil
	}

	// Attempt 2: Legacy SSE
	sseTransport, sseErr := tryLegacySSE(ctx, baseURL, httpClient)
	if sseErr == nil {
		log.Printf("WARNING: MCP server at %s uses deprecated SSE transport. "+
			"Consider upgrading to Streamable HTTP (MCP spec 2025-03-26+).", baseURL)
		return sseTransport, nil
	}

	return nil, fmt.Errorf("failed to detect MCP transport at %s: "+
		"streamable HTTP error: %v; legacy SSE error: %v", baseURL, err, sseErr)
}

// tryStreamableHTTP attempts to connect using the Streamable HTTP transport.
// Returns the initialized transport on success, or an error on failure.
func tryStreamableHTTP(ctx context.Context, baseURL string, httpClient *http.Client) (*StreamableHTTPTransport, error) {
	t := NewStreamableHTTPTransport(baseURL, httpClient)
	if err := t.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("streamable HTTP initialize failed: %w", err)
	}
	return t, nil
}

// tryLegacySSE attempts to connect using the legacy SSE transport.
// Returns the connected transport on success, or an error on failure.
func tryLegacySSE(ctx context.Context, baseURL string, httpClient *http.Client) (*LegacySSETransport, error) {
	t := NewLegacySSETransport(baseURL, httpClient)
	if err := t.Connect(ctx); err != nil {
		return nil, fmt.Errorf("legacy SSE connect failed: %w", err)
	}
	return t, nil
}
