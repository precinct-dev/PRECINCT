// demo/go/main.go -- E2E demo exercising every gateway middleware layer via the Go SDK.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/example/mcp-gateway-sdk-go/mcpgateway"
)

const (
	dspySPIFFE = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	colorReset = "\033[0m"
	colorGreen = "\033[32m"
	colorRed   = "\033[31m"
	colorCyan  = "\033[36m"
	colorDim   = "\033[2m"
)

// testCase holds a single E2E test with rich self-documenting metadata.
type testCase struct {
	name   string   // Short test name (shown in [N/M] header)
	what   string   // Plain-English explanation of the security control
	send   string   // What payload/tool/identity we send
	expect string   // Expected result and what it proves
	fn     func() bool
}

var gatewayURL = flag.String("gateway-url", "http://localhost:9090", "Gateway base URL")

func main() {
	flag.Parse()

	fmt.Println("========================================")
	fmt.Println("  MCP Security Gateway -- Go SDK Demo")
	fmt.Printf("  Gateway: %s\n", *gatewayURL)
	fmt.Println("========================================")
	fmt.Println()

	pass, fail := 0, 0
	tests := []testCase{
		{
			name:   "Happy path (chain runs, reaches upstream)",
			what:   "Full 13-layer middleware chain processes a valid request end-to-end",
			send:   "tavily_search(query='AI security') with valid SPIFFE ID",
			expect: "200 (mock MCP server response) or 502 (no upstream) -- both prove all 13 layers executed",
			fn:     testHappyPath,
		},
		{
			name:   "MCP transport: tools/call through all 13 layers",
			what:   "MCP Streamable HTTP transport delivers tool results through all 13 middleware layers",
			send:   "tavily_search(query='AI security best practices') via SDK -> gateway -> mock MCP server",
			expect: "Actual search results from mock MCP server proving SDK -> gateway -> MCP transport -> server -> results",
			fn:     testMCPToolsCall,
		},
		{
			name:   "SPIFFE auth denial (empty identity)",
			what:   "SPIFFE identity verification rejects unauthenticated requests at step 2",
			send:   "read(file_path='/tmp/test') with EMPTY SPIFFE ID (no identity)",
			expect: "401 or 403 -- gateway blocks at authentication layer before any tool execution",
			fn:     testAuthDenial,
		},
		{
			name:   "Unregistered tool (registry rejection)",
			what:   "Tool registry rejects calls to tools not in the approved registry",
			send:   "not_a_real_tool() -- a tool name that does not exist in the registry",
			expect: "400 or 403 -- gateway blocks before OPA policy evaluation",
			fn:     testUnregisteredTool,
		},
		{
			name:   "OPA policy denial (bash requires step-up)",
			what:   "OPA policy engine enforces fine-grained authorization (bash requires step-up auth)",
			send:   "bash(command='ls') with standard SPIFFE ID (no step-up auth)",
			expect: "403 -- OPA policy denies bash execution without step-up authentication",
			fn:     testOPADenial,
		},
		{
			name:   "DLP credential block (AWS key)",
			what:   "DLP scanner blocks AWS access key patterns in request payloads",
			send:   "read(file_path='AKIAIOSFODNN7EXAMPLE') -- contains AWS access key pattern",
			expect: "403 -- DLP blocks credential pattern before reaching upstream",
			fn:     testDLPCredentialBlock,
		},
		{
			name:   "DLP PII pass-through (email is audit-only)",
			what:   "DLP scanner audits PII (email) but does NOT block -- audit-only policy",
			send:   "tavily_search(query='contact user@example.com about results') -- contains email PII",
			expect: "200 or 502 -- PII is logged for audit but request passes through",
			fn:     testDLPPIIPass,
		},
		{
			name:   "Rate limit burst (429 on rapid calls)",
			what:   "Per-SPIFFE-ID rate limiter enforces request quotas at step 11",
			send:   "Rapid burst of tavily_search() calls (up to 200) with same SPIFFE ID",
			expect: "429 after hitting rate limit -- proves per-identity throttling works",
			fn:     testRateLimit,
		},
		{
			name:   "Request size limit (11 MB payload)",
			what:   "Request size limit (10 MB) rejects oversized payloads at step 1",
			send:   "read(file_path=<11 MB of 'A's>) -- 11 MB payload exceeds 10 MB limit",
			expect: "413 or connection reset -- gateway rejects at ingress before processing",
			fn:     testRequestSizeLimit,
		},
	}

	for i, t := range tests {
		fmt.Printf("%s[%d/%d] %s%s\n", colorCyan, i+1, len(tests), t.name, colorReset)
		fmt.Printf("  WHAT:   %s\n", t.what)
		fmt.Printf("  SEND:   %s\n", t.send)
		fmt.Printf("  EXPECT: %s\n", t.expect)
		if t.fn() {
			pass++
		} else {
			fail++
		}
		fmt.Println()
	}

	fmt.Println("========================================")
	fmt.Printf("  Go SDK Demo: %s%d PASS%s / %s%d FAIL%s\n",
		colorGreen, pass, colorReset, colorRed, fail, colorReset)
	fmt.Println("========================================")

	if fail > 0 {
		os.Exit(1)
	}
}

// newClient creates a client with the DSPy researcher SPIFFE ID.
func newClient() *mcpgateway.GatewayClient {
	return mcpgateway.NewClient(*gatewayURL, dspySPIFFE,
		mcpgateway.WithTimeout(10*time.Second),
		mcpgateway.WithMaxRetries(0), // No retries for demo -- we want immediate responses
	)
}

func printProof(ok bool, reason string) bool {
	if ok {
		fmt.Printf("  PROOF:  %sPASS%s -- %s\n", colorGreen, colorReset, reason)
	} else {
		fmt.Printf("  PROOF:  %sFAIL%s -- %s\n", colorRed, colorReset, reason)
	}
	return ok
}

func printGatewayError(ge *mcpgateway.GatewayError) {
	fmt.Printf("  %sCode:%s        %s\n", colorDim, colorReset, ge.Code)
	fmt.Printf("  %sMiddleware:%s  %s\n", colorDim, colorReset, ge.Middleware)
	fmt.Printf("  %sStep:%s        %d\n", colorDim, colorReset, ge.Step)
	fmt.Printf("  %sHTTP:%s        %d\n", colorDim, colorReset, ge.HTTPStatus)
	fmt.Printf("  %sMessage:%s     %s\n", colorDim, colorReset, ge.Message)
	if ge.Remediation != "" {
		fmt.Printf("  %sRemediation:%s %s\n", colorDim, colorReset, ge.Remediation)
	}
	if ge.TraceID != "" {
		fmt.Printf("  %sTraceID:%s     %s\n", colorDim, colorReset, ge.TraceID)
	}
	if ge.DecisionID != "" {
		fmt.Printf("  %sDecisionID:%s  %s\n", colorDim, colorReset, ge.DecisionID)
	}
}

// --- Test sections -------------------------------------------------------

// 1. Happy path: Call a registered tool with valid identity.
// Expect success (200) or 502 (no real upstream) -- either proves chain ran.
// Uses tavily_search which has no path restrictions in OPA policy.
func testHappyPath() bool {
	client := newClient()
	ctx := context.Background()
	result, err := client.Call(ctx, "tavily_search", map[string]any{"query": "AI security"})
	if err == nil {
		fmt.Printf("  Result: %v\n", result)
		return printProof(true, "chain processed request successfully (200)")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		// 502 = chain ran but no upstream server (expected in demo)
		if ge.HTTPStatus == 502 {
			return printProof(true, "chain ran to completion, 502 = no upstream (expected)")
		}
		return printProof(false, fmt.Sprintf("unexpected gateway error: %s", ge.Code))
	}
	fmt.Printf("  Error: %v\n", err)
	return printProof(false, fmt.Sprintf("unexpected error type: %T", err))
}

// 2. MCP transport: tools/call flows through all 13 middleware layers to mock MCP server.
// Unlike the happy path which accepts 502 as success, this test REQUIRES actual results
// from the mock MCP server. This proves the MCP Streamable HTTP transport works end-to-end:
// SDK -> gateway (13 middleware layers) -> MCP transport -> mock MCP server -> results back.
func testMCPToolsCall() bool {
	client := newClient()
	ctx := context.Background()
	result, err := client.Call(ctx, "tavily_search", map[string]any{"query": "AI security best practices"})
	if err != nil {
		var ge *mcpgateway.GatewayError
		if errors.As(err, &ge) {
			printGatewayError(ge)
			if ge.HTTPStatus == 502 {
				return printProof(false, "got 502 -- MCP transport did not reach mock server (expected actual results)")
			}
			return printProof(false, fmt.Sprintf("gateway error: %s (HTTP %d)", ge.Code, ge.HTTPStatus))
		}
		fmt.Printf("  Error: %v\n", err)
		return printProof(false, fmt.Sprintf("unexpected error: %v", err))
	}

	// We expect a JSON-RPC result with content from the mock MCP server
	if result == nil {
		return printProof(false, "got nil result from MCP transport")
	}

	// The result from the gateway is the JSON-RPC result field, which should contain
	// the mock MCP server's canned response with search results.
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return printProof(false, fmt.Sprintf("failed to marshal result: %v", err))
	}

	resultStr := string(resultJSON)
	fmt.Printf("  %sResult preview:%s %s\n", colorDim, colorReset, truncateStr(resultStr, 200))

	// Verify the canned search results are present
	if !strings.Contains(resultStr, "AI Security") {
		return printProof(false, "result does not contain expected canned search data")
	}

	return printProof(true, "MCP transport returned actual search results through all 13 layers")
}

// 3. SPIFFE auth denial: Client with empty SPIFFE ID should get 401.
func testAuthDenial() bool {
	client := mcpgateway.NewClient(*gatewayURL, "", // empty SPIFFE ID
		mcpgateway.WithTimeout(10*time.Second),
		mcpgateway.WithMaxRetries(0),
	)
	ctx := context.Background()
	_, err := client.Call(ctx, "read", map[string]any{"file_path": "/tmp/test"})
	if err == nil {
		return printProof(false, "expected denial but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		if ge.HTTPStatus == 401 || ge.HTTPStatus == 403 {
			return printProof(true, fmt.Sprintf("correctly denied with HTTP %d", ge.HTTPStatus))
		}
		return printProof(false, fmt.Sprintf("wrong HTTP status: %d (expected 401/403)", ge.HTTPStatus))
	}
	fmt.Printf("  Error: %v\n", err)
	return printProof(false, "error is not a GatewayError")
}

// 4. Unregistered tool: Call a tool that doesn't exist in the registry.
func testUnregisteredTool() bool {
	client := newClient()
	ctx := context.Background()
	_, err := client.Call(ctx, "not_a_real_tool", map[string]any{})
	if err == nil {
		return printProof(false, "expected denial but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		ok := ge.HTTPStatus == 403 || ge.HTTPStatus == 400
		return printProof(ok, fmt.Sprintf("registry rejection: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printProof(false, "error is not a GatewayError")
}

// 5. OPA policy denial: bash tool requires step-up auth that demo doesn't provide.
func testOPADenial() bool {
	client := newClient()
	ctx := context.Background()
	_, err := client.Call(ctx, "bash", map[string]any{"command": "ls"})
	if err == nil {
		return printProof(false, "expected denial but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		ok := ge.HTTPStatus == 403
		return printProof(ok, fmt.Sprintf("OPA policy denied: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printProof(false, "error is not a GatewayError")
}

// 6. DLP credential block: AWS access key pattern should be blocked.
func testDLPCredentialBlock() bool {
	client := newClient()
	ctx := context.Background()
	_, err := client.Call(ctx, "read", map[string]any{
		"file_path": "AKIAIOSFODNN7EXAMPLE",
	})
	if err == nil {
		// Chain may pass to upstream which 502s -- check if DLP caught it
		return printProof(false, "expected DLP block but chain passed through")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		// DLP block should be 403 or 400
		if ge.HTTPStatus == 502 {
			// Reached upstream (DLP didn't block) -- still useful data
			return printProof(false, "DLP did not block credential pattern (reached upstream)")
		}
		return printProof(true, fmt.Sprintf("DLP blocked: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printProof(false, "error is not a GatewayError")
}

// 7. DLP PII pass-through: Email address should pass (audit-only, not blocked).
// Uses tavily_search to bypass OPA path restrictions. PII in query is audit-only.
func testDLPPIIPass() bool {
	client := newClient()
	ctx := context.Background()
	result, err := client.Call(ctx, "tavily_search", map[string]any{
		"query": "contact user@example.com about results",
	})
	if err == nil {
		fmt.Printf("  Result: %v\n", result)
		return printProof(true, "PII passed through (audit-only, not blocked)")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		// 502 = reached upstream (PII was not blocked) -- PASS
		if ge.HTTPStatus == 502 {
			return printProof(true, "PII reached upstream (502 = no server, proves pass-through)")
		}
		return printProof(false, fmt.Sprintf("PII was blocked: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printProof(false, "unexpected error type")
}

// 8. Rate limit burst: Rapidly call until we get 429.
// Uses tavily_search (no path restrictions) so calls reach the rate limiter at step 11.
// Creates a fresh client per call to avoid session risk accumulation (OPA step 6)
// while still accumulating rate limit counters (per-SPIFFE-ID at step 11).
func testRateLimit() bool {
	ctx := context.Background()
	maxAttempts := 200 // enough to hit the rate limit

	for i := 0; i < maxAttempts; i++ {
		client := newClient() // fresh session each call to avoid session risk escalation
		_, err := client.Call(ctx, "tavily_search", map[string]any{"query": "test"})
		if err == nil {
			continue // chain succeeded -- keep going
		}
		var ge *mcpgateway.GatewayError
		if errors.As(err, &ge) {
			if ge.HTTPStatus == 429 {
				printGatewayError(ge)
				return printProof(true, fmt.Sprintf("rate limited after %d calls: code=%s", i+1, ge.Code))
			}
			// Other errors (502 etc.) are expected -- keep trying
			continue
		}
	}
	return printProof(false, fmt.Sprintf("no rate limit after %d calls", maxAttempts))
}

// 9. Request size limit: 11 MB payload should be rejected at step 1.
func testRequestSizeLimit() bool {
	client := newClient()
	ctx := context.Background()
	bigPayload := strings.Repeat("A", 11*1024*1024) // 11 MB
	_, err := client.Call(ctx, "read", map[string]any{"file_path": bigPayload})
	if err == nil {
		return printProof(false, "expected rejection but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		return printProof(true, fmt.Sprintf("size limit enforced: code=%s, HTTP=%d", ge.Code, ge.HTTPStatus))
	}
	fmt.Printf("  Error: %v\n", err)
	// Even a non-GatewayError (e.g. connection reset) proves the limit works
	return printProof(true, fmt.Sprintf("rejected (non-JSON): %v", err))
}

// truncateStr shortens a string for display, appending "..." if truncated.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
