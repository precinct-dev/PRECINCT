//go:build integration

package mcpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// spireSocket returns the SPIRE agent socket path from the environment.
// The test fails immediately if not set -- no skip, no conditional gating.
func spireSocket(t *testing.T) string {
	t.Helper()
	sock := os.Getenv("SPIRE_AGENT_SOCKET")
	if sock == "" {
		t.Fatal("SPIRE_AGENT_SOCKET not set; cannot run integration tests without a live SPIRE agent")
	}
	// Verify the socket file exists on disk.
	cleanPath := sock
	if len(cleanPath) > 7 && cleanPath[:7] == "unix://" {
		cleanPath = cleanPath[7:]
	}
	if _, err := os.Stat(cleanPath); err != nil {
		t.Fatalf("SPIRE agent socket not accessible at %s: %v", cleanPath, err)
	}
	return sock
}

// waitForAddr polls s.Addr() until the server is listening or the deadline
// passes. Returns the address string or fails the test.
func waitForAddr(t *testing.T, s *Server, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if a := s.Addr(); a != nil {
			return a.String()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not start within deadline")
	panic("unreachable") // t.Fatal calls runtime.Goexit; this satisfies the compiler
}

// newX509Client creates an HTTP client that uses a SPIRE-issued SVID for
// mTLS. The caller must close the X509Source when done.
func newX509Client(t *testing.T, ctx context.Context, socketPath string) (*http.Client, *workloadapi.X509Source) {
	t.Helper()
	addr := formatSpireAddr(socketPath)
	src, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(addr)),
	)
	if err != nil {
		t.Fatalf("failed to create X509Source for client: %v", err)
	}

	tlsCfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeAny())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		Timeout: 10 * time.Second,
	}
	return client, src
}

// jsonRPCRequest builds a JSON-RPC 2.0 request body as an io.Reader.
func jsonRPCRequest(t *testing.T, id any, method string, params any) io.Reader {
	t.Helper()
	m := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if id != nil {
		m["id"] = id
	}
	if params != nil {
		m["params"] = params
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return bytes.NewReader(b)
}

// mcpInitialize performs the MCP initialize + notifications/initialized
// handshake over the given client and returns the session ID.
func mcpInitialize(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()

	// Step 1: initialize
	body := jsonRPCRequest(t, 1, "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "integration-test",
			"version": "1.0.0",
		},
	})
	req, err := http.NewRequest(http.MethodPost, baseURL+"/", body)
	if err != nil {
		t.Fatalf("new init request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("initialize request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize returned %d, want 200", resp.StatusCode)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize: missing Mcp-Session-Id header")
	}

	// Step 2: notifications/initialized
	body2 := jsonRPCRequest(t, nil, "notifications/initialized", nil)
	req2, err := http.NewRequest(http.MethodPost, baseURL+"/", body2)
	if err != nil {
		t.Fatalf("new notification request: %v", err)
	}
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Mcp-Session-Id", sessionID)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("notifications/initialized request failed: %v", err)
	}
	resp2.Body.Close()

	return sessionID
}

// ---------------------------------------------------------------------------
// AC 10: Server obtains SVID and accepts mTLS connection; client with valid
// SVID from the same trust domain can connect and call tools/list.
// ---------------------------------------------------------------------------

func TestIntegration_SPIRE_ServerObtainsSVID_ClientCallsToolsList(t *testing.T) {
	socketPath := spireSocket(t)

	// Create an mcpserver with WithSPIRE pointing to the real SPIRE agent.
	s := New("spire-integ-test",
		WithSPIRE(socketPath),
		WithPort(0),
		WithShutdownTimeout(5*time.Second),
		WithoutRateLimiting(),
		WithoutCaching(),
		WithoutOTel(),
		WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	)

	// Register a test tool so tools/list has something to return.
	s.Tool("echo", "echoes input", Schema{Type: "object"}, func(_ context.Context, args map[string]any) (any, error) {
		return args, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunContext(ctx)
	}()

	// Wait for the TLS listener to come up.
	addr := waitForAddr(t, s, 30*time.Second)
	baseURL := fmt.Sprintf("https://%s", addr)

	t.Logf("mcpserver listening with mTLS at %s", baseURL)

	// Create an mTLS client with a valid SVID from the same trust domain.
	client, clientSrc := newX509Client(t, ctx, socketPath)
	defer clientSrc.Close()

	// Perform MCP handshake: initialize + notifications/initialized.
	sessionID := mcpInitialize(t, client, baseURL)
	t.Logf("MCP session established: %s", sessionID)

	// Call tools/list and verify the response contains the registered tool.
	body := jsonRPCRequest(t, 2, "tools/list", nil)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/", body)
	if err != nil {
		t.Fatalf("new tools/list request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("tools/list request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list returned %d, want 200", resp.StatusCode)
	}

	// Parse the response to verify the tool is listed.
	var rpcResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode tools/list response: %v", err)
	}

	found := false
	for _, tool := range rpcResp.Result.Tools {
		if tool.Name == "echo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("tools/list did not contain 'echo'; got %+v", rpcResp.Result.Tools)
	}

	// Shutdown gracefully.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("RunContext returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunContext did not shut down within 10s")
	}
}

// ---------------------------------------------------------------------------
// AC 11: Client without valid cert is rejected at TLS handshake.
// ---------------------------------------------------------------------------

func TestIntegration_SPIRE_ClientWithoutCert_Rejected(t *testing.T) {
	socketPath := spireSocket(t)

	// Create an mcpserver with WithSPIRE (real mTLS).
	s := New("spire-reject-test",
		WithSPIRE(socketPath),
		WithPort(0),
		WithShutdownTimeout(5*time.Second),
		WithoutRateLimiting(),
		WithoutCaching(),
		WithoutOTel(),
		WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunContext(ctx)
	}()

	addr := waitForAddr(t, s, 30*time.Second)
	baseURL := fmt.Sprintf("https://%s", addr)

	t.Logf("mcpserver listening with mTLS at %s", baseURL)

	// Create an HTTP client with NO client certificate.
	// InsecureSkipVerify is used because the server cert is a SPIRE-issued
	// SVID that is not in the system trust store. We only care about
	// verifying that the server REJECTS the connection due to missing
	// client cert (mTLS requirement).
	noClientCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // intentional for test
			},
		},
		Timeout: 5 * time.Second,
	}

	// Attempt to connect -- the TLS handshake should fail because the
	// server requires a client certificate (RequireAndVerifyClientCert).
	req, err := http.NewRequest(http.MethodGet, baseURL+"/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := noClientCertClient.Do(req)
	if err != nil {
		// Expected: TLS handshake failure. The exact error varies by
		// platform but should contain "tls" or "certificate" keywords.
		t.Logf("connection correctly rejected with error: %v", err)
	} else {
		// If somehow the connection succeeded, that is a security failure.
		resp.Body.Close()
		t.Fatalf("expected TLS handshake rejection, but got HTTP %d; mTLS is not enforced", resp.StatusCode)
	}

	// Shutdown gracefully.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("RunContext returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunContext did not shut down within 10s")
	}
}
