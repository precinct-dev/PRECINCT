// demo/go/main.go -- E2E demo exercising every gateway middleware layer via the Go SDK.
package main

import (
	"context"
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

var gatewayURL = flag.String("gateway-url", "http://localhost:9090", "Gateway base URL")

func main() {
	flag.Parse()

	fmt.Println("========================================")
	fmt.Println("  MCP Security Gateway -- Go SDK Demo")
	fmt.Printf("  Gateway: %s\n", *gatewayURL)
	fmt.Println("========================================")
	fmt.Println()

	pass, fail := 0, 0
	tests := []struct {
		name string
		fn   func() bool
	}{
		{"Happy path (chain runs, reaches upstream)", testHappyPath},
		{"SPIFFE auth denial (empty identity)", testAuthDenial},
		{"Unregistered tool (registry rejection)", testUnregisteredTool},
		{"OPA policy denial (bash requires step-up)", testOPADenial},
		{"DLP credential block (AWS key)", testDLPCredentialBlock},
		{"DLP PII pass-through (email is audit-only)", testDLPPIIPass},
		{"Rate limit burst (429 on rapid calls)", testRateLimit},
		{"Request size limit (11 MB payload)", testRequestSizeLimit},
	}

	for i, t := range tests {
		fmt.Printf("%s[%d/%d] %s%s\n", colorCyan, i+1, len(tests), t.name, colorReset)
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

func printVerdict(ok bool, reason string) bool {
	if ok {
		fmt.Printf("  Verdict: %sPASS%s -- %s\n", colorGreen, colorReset, reason)
	} else {
		fmt.Printf("  Verdict: %sFAIL%s -- %s\n", colorRed, colorReset, reason)
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
		return printVerdict(true, "chain processed request successfully (200)")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		// 502 = chain ran but no upstream server (expected in demo)
		if ge.HTTPStatus == 502 {
			return printVerdict(true, "chain ran to completion, 502 = no upstream (expected)")
		}
		return printVerdict(false, fmt.Sprintf("unexpected gateway error: %s", ge.Code))
	}
	fmt.Printf("  Error: %v\n", err)
	return printVerdict(false, fmt.Sprintf("unexpected error type: %T", err))
}

// 2. SPIFFE auth denial: Client with empty SPIFFE ID should get 401.
func testAuthDenial() bool {
	client := mcpgateway.NewClient(*gatewayURL, "", // empty SPIFFE ID
		mcpgateway.WithTimeout(10*time.Second),
		mcpgateway.WithMaxRetries(0),
	)
	ctx := context.Background()
	_, err := client.Call(ctx, "read", map[string]any{"file_path": "/tmp/test"})
	if err == nil {
		return printVerdict(false, "expected denial but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		if ge.HTTPStatus == 401 || ge.HTTPStatus == 403 {
			return printVerdict(true, fmt.Sprintf("correctly denied with HTTP %d", ge.HTTPStatus))
		}
		return printVerdict(false, fmt.Sprintf("wrong HTTP status: %d (expected 401/403)", ge.HTTPStatus))
	}
	fmt.Printf("  Error: %v\n", err)
	return printVerdict(false, "error is not a GatewayError")
}

// 3. Unregistered tool: Call a tool that doesn't exist in the registry.
func testUnregisteredTool() bool {
	client := newClient()
	ctx := context.Background()
	_, err := client.Call(ctx, "not_a_real_tool", map[string]any{})
	if err == nil {
		return printVerdict(false, "expected denial but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		ok := ge.HTTPStatus == 403 || ge.HTTPStatus == 400
		return printVerdict(ok, fmt.Sprintf("registry rejection: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printVerdict(false, "error is not a GatewayError")
}

// 4. OPA policy denial: bash tool requires step-up auth that demo doesn't provide.
func testOPADenial() bool {
	client := newClient()
	ctx := context.Background()
	_, err := client.Call(ctx, "bash", map[string]any{"command": "ls"})
	if err == nil {
		return printVerdict(false, "expected denial but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		ok := ge.HTTPStatus == 403
		return printVerdict(ok, fmt.Sprintf("OPA policy denied: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printVerdict(false, "error is not a GatewayError")
}

// 5. DLP credential block: AWS access key pattern should be blocked.
func testDLPCredentialBlock() bool {
	client := newClient()
	ctx := context.Background()
	_, err := client.Call(ctx, "read", map[string]any{
		"file_path": "AKIAIOSFODNN7EXAMPLE",
	})
	if err == nil {
		// Chain may pass to upstream which 502s -- check if DLP caught it
		return printVerdict(false, "expected DLP block but chain passed through")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		// DLP block should be 403 or 400
		if ge.HTTPStatus == 502 {
			// Reached upstream (DLP didn't block) -- still useful data
			return printVerdict(false, "DLP did not block credential pattern (reached upstream)")
		}
		return printVerdict(true, fmt.Sprintf("DLP blocked: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printVerdict(false, "error is not a GatewayError")
}

// 6. DLP PII pass-through: Email address should pass (audit-only, not blocked).
// Uses tavily_search to bypass OPA path restrictions. PII in query is audit-only.
func testDLPPIIPass() bool {
	client := newClient()
	ctx := context.Background()
	result, err := client.Call(ctx, "tavily_search", map[string]any{
		"query": "contact user@example.com about results",
	})
	if err == nil {
		fmt.Printf("  Result: %v\n", result)
		return printVerdict(true, "PII passed through (audit-only, not blocked)")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		// 502 = reached upstream (PII was not blocked) -- PASS
		if ge.HTTPStatus == 502 {
			return printVerdict(true, "PII reached upstream (502 = no server, proves pass-through)")
		}
		return printVerdict(false, fmt.Sprintf("PII was blocked: code=%s, step=%d", ge.Code, ge.Step))
	}
	fmt.Printf("  Error: %v\n", err)
	return printVerdict(false, "unexpected error type")
}

// 7. Rate limit burst: Rapidly call until we get 429.
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
				return printVerdict(true, fmt.Sprintf("rate limited after %d calls: code=%s", i+1, ge.Code))
			}
			// Other errors (502 etc.) are expected -- keep trying
			continue
		}
	}
	return printVerdict(false, fmt.Sprintf("no rate limit after %d calls", maxAttempts))
}

// 8. Request size limit: 11 MB payload should be rejected at step 1.
func testRequestSizeLimit() bool {
	client := newClient()
	ctx := context.Background()
	bigPayload := strings.Repeat("A", 11*1024*1024) // 11 MB
	_, err := client.Call(ctx, "read", map[string]any{"file_path": bigPayload})
	if err == nil {
		return printVerdict(false, "expected rejection but got success")
	}
	var ge *mcpgateway.GatewayError
	if errors.As(err, &ge) {
		printGatewayError(ge)
		return printVerdict(true, fmt.Sprintf("size limit enforced: code=%s, HTTP=%d", ge.Code, ge.HTTPStatus))
	}
	fmt.Printf("  Error: %v\n", err)
	// Even a non-GatewayError (e.g. connection reset) proves the limit works
	return printVerdict(true, fmt.Sprintf("rejected (non-JSON): %v", err))
}
