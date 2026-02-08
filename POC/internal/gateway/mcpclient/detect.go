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
// RFA-xhr: DetectTransportWithConfig adds per-probe and overall timeouts.
package mcpclient

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

// DetectTransport probes the MCP server at baseURL and returns the appropriate
// Transport implementation. This is the original interface without timeout
// configuration (uses the caller's context for all timeouts).
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

// DetectTransportWithConfig probes the MCP server with per-probe and overall
// timeouts. Each probe (Streamable HTTP, Legacy SSE) gets its own timeout
// context derived from ProbeTimeout. The overall detection is bounded by
// OverallTimeout.
//
// RFA-xhr: Production-grade detection that prevents indefinite hanging on
// unresponsive servers.
func DetectTransportWithConfig(ctx context.Context, baseURL string, httpClient *http.Client, cfg DetectConfig) (Transport, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Apply overall timeout to the detection process.
	// If detection succeeds with Legacy SSE, we must NOT cancel the context
	// because the SSE stream's HTTP request is tied to it. The cancelSSE flag
	// controls whether defer should actually cancel.
	overallCtx, overallCancel := context.WithTimeout(ctx, cfg.OverallTimeout)
	cancelOnExit := true
	defer func() {
		if cancelOnExit {
			overallCancel()
		}
	}()

	// Attempt 1: Streamable HTTP with per-probe timeout
	probeCtx, probeCancel := context.WithTimeout(overallCtx, cfg.ProbeTimeout)
	transport, err := tryStreamableHTTP(probeCtx, baseURL, httpClient)
	probeCancel()
	if err == nil {
		return transport, nil
	}

	// Check if overall context expired
	if overallCtx.Err() != nil {
		return nil, fmt.Errorf("transport detection timed out for %s: %w", baseURL, overallCtx.Err())
	}

	// Attempt 2: Legacy SSE with per-probe timeout.
	// We pass overallCtx (not a probe-scoped timeout context) because the
	// SSE stream is a long-lived HTTP connection. ConnectWithTimeout enforces
	// the handshake timeout internally without cancelling the stream context.
	// Wrapping with an extra timeout context would cancel the SSE response body
	// when the probe context is cleaned up, killing the stream.
	sseTransport, sseErr := tryLegacySSEWithTimeout(overallCtx, baseURL, httpClient, cfg.ProbeTimeout)
	if sseErr == nil {
		// Do NOT cancel overallCtx -- the SSE stream's HTTP request is tied
		// to it, and cancelling would close the response body.
		cancelOnExit = false
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

// tryLegacySSEWithTimeout attempts to connect using the legacy SSE transport
// with an explicit handshake timeout. Used by DetectTransportWithConfig.
func tryLegacySSEWithTimeout(ctx context.Context, baseURL string, httpClient *http.Client, handshakeTimeout time.Duration) (*LegacySSETransport, error) {
	t := NewLegacySSETransport(baseURL, httpClient)
	if err := t.ConnectWithTimeout(ctx, handshakeTimeout); err != nil {
		return nil, fmt.Errorf("legacy SSE connect failed: %w", err)
	}
	return t, nil
}
