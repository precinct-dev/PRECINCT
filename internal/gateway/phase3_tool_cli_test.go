// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// ---------------------------------------------------------------------------
// Unit tests: CLI protocol adapter via evaluate() directly
// ---------------------------------------------------------------------------

func TestCLIProtocolAllowedCommand(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "ls", nil)
	res := engine.evaluate(req)
	if res.Decision != DecisionStepUp {
		// tool.highrisk.cli requires step-up; if CLI checks pass, we reach step-up
		t.Fatalf("expected step_up decision for allowed command, got decision=%s reason=%s status=%d", res.Decision, res.Reason, res.HTTPStatus)
	}
	if res.Reason != ReasonToolStepUpRequired {
		t.Fatalf("expected reason=%s, got %s", ReasonToolStepUpRequired, res.Reason)
	}
}

func TestCLIProtocolAllowedCommandNoStepUp(t *testing.T) {
	// Create an engine with a CLI rule that does NOT require step-up
	engine := &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.safe": {
				CapabilityID: "tool.cli.safe",
				Protocol:     "cli",
				Adapters:     map[string]struct{}{"cli": {}},
				AllowTools:   map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{
					"ls":   {},
					"echo": {},
					"cat":  {},
				},
				MaxArgs:         6,
				DeniedArgTokens: []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
				Actions: []toolActionRule{
					{
						Action:    "tool.execute",
						Resources: map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{
							"bash": {},
						},
					},
				},
			},
		},
	}

	req := cliToolPlaneRequest("tool.cli.safe", "bash", "ls", []string{"-la"})
	res := engine.evaluate(req)
	if res.Decision != DecisionAllow || res.Reason != ReasonToolAllow || res.HTTPStatus != http.StatusOK {
		t.Fatalf("expected allow/TOOL_ALLOW/200, got decision=%s reason=%s status=%d metadata=%v",
			res.Decision, res.Reason, res.HTTPStatus, res.Metadata)
	}
}

func TestCLIProtocolDisallowedCommand(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "rm", nil)
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLICommandDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_COMMAND_DENIED/403, got reason=%s status=%d metadata=%v",
			res.Reason, res.HTTPStatus, res.Metadata)
	}
}

func TestCLIProtocolDeniedNestedShellInterpreterCommand(t *testing.T) {
	engine := &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.interpreter": {
				CapabilityID:    "tool.cli.interpreter",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"bash": {}, "sh": {}, "ls": {}},
				MaxArgs:         6,
				DeniedArgTokens: []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{name: "bash -c", command: "bash", args: []string{"-c", "touch /tmp/pwned"}},
		{name: "sh -c", command: "sh", args: []string{"-c", "touch /tmp/pwned"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := cliToolPlaneRequest("tool.cli.interpreter", "bash", tt.command, tt.args)
			res := engine.evaluate(req)
			if res.Reason != ReasonToolCLICommandDenied || res.HTTPStatus != http.StatusForbidden {
				t.Fatalf("expected TOOL_CLI_COMMAND_DENIED/403 for %s, got reason=%s status=%d metadata=%v",
					tt.name, res.Reason, res.HTTPStatus, res.Metadata)
			}
		})
	}
}

func TestCLIProtocolArgsExceedMaxArgs(t *testing.T) {
	engine := &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.limited": {
				CapabilityID:    "tool.cli.limited",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"ls": {}},
				MaxArgs:         3,
				DeniedArgTokens: []string{";"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	req := cliToolPlaneRequest("tool.cli.limited", "bash", "ls", []string{"-l", "-a", "-h", "-R"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED/403, got reason=%s status=%d metadata=%v",
			res.Reason, res.HTTPStatus, res.Metadata)
	}
}

func TestCLIProtocolDeniedArgTokenSemicolon(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "ls", []string{"-la", "; rm -rf /"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED/403 for semicolon injection, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLIProtocolDeniedArgTokenDoubleAmpersand(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "ls", []string{"&& malicious"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED/403 for && injection, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLIProtocolDeniedArgTokenPipe(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "ls", []string{"| cat /etc/passwd"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED/403 for pipe injection, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLIProtocolDeniedArgTokenSubshell(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "echo", []string{"$(whoami)"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED/403 for $( injection, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLIProtocolDeniedArgTokenBacktick(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "echo", []string{"`id`"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED/403 for backtick injection, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLIProtocolCommandWithSpace(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "ls -la", nil)
	res := engine.evaluate(req)
	if res.Reason != ReasonToolSchemaInvalid {
		t.Fatalf("expected TOOL_SCHEMA_INVALID for command with space, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLIProtocolMissingCommand(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := cliToolPlaneRequest("tool.highrisk.cli", "bash", "", nil)
	res := engine.evaluate(req)
	if res.Reason != ReasonToolSchemaInvalid {
		t.Fatalf("expected TOOL_SCHEMA_INVALID for missing command, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestMCPProtocolRegressionSafe(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	req := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "cli-test-mcp-regression",
			SessionID:     "cli-test-session",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneTool,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "cli-test-mcp-regression",
				SessionID:     "cli-test-session",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
			},
			Action:   "tool.execute",
			Resource: "tool/read",
			Attributes: map[string]any{
				"capability_id": "tool.default.mcp",
				"tool_name":     "read",
				"protocol":      "mcp",
			},
		},
	}

	res := engine.evaluate(req)
	if res.Decision != DecisionAllow || res.Reason != ReasonToolAllow || res.HTTPStatus != http.StatusOK {
		t.Fatalf("MCP regression: expected allow/TOOL_ALLOW/200, got decision=%s reason=%s status=%d",
			res.Decision, res.Reason, res.HTTPStatus)
	}
}

func TestCLIDefaultDeniedTokensApplied(t *testing.T) {
	// Rule with empty DeniedArgTokens should still use defaults
	engine := &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.nodenied": {
				CapabilityID:    "tool.cli.nodenied",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"ls": {}},
				MaxArgs:         10,
				DeniedArgTokens: nil, // empty = use defaults
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	req := cliToolPlaneRequest("tool.cli.nodenied", "bash", "ls", []string{"; whoami"})
	res := engine.evaluate(req)
	if res.Reason != ReasonToolCLIArgsDenied || res.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected default denied tokens to catch semicolon, got reason=%s status=%d",
			res.Reason, res.HTTPStatus)
	}
}

func TestCLICustomDeniedTokensOverrideDefaults(t *testing.T) {
	// Rule with custom DeniedArgTokens that does NOT include ";"
	engine := &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.custom": {
				CapabilityID:    "tool.cli.custom",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"ls": {}},
				MaxArgs:         10,
				DeniedArgTokens: []string{"FORBIDDEN"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	// Semicolon should now be allowed since custom tokens don't include it
	req := cliToolPlaneRequest("tool.cli.custom", "bash", "ls", []string{";"})
	res := engine.evaluate(req)
	if res.Reason == ReasonToolCLIArgsDenied {
		t.Fatalf("custom DeniedArgTokens should NOT block semicolon, got reason=%s", res.Reason)
	}

	// FORBIDDEN token should be denied
	req2 := cliToolPlaneRequest("tool.cli.custom", "bash", "ls", []string{"FORBIDDEN_value"})
	res2 := engine.evaluate(req2)
	if res2.Reason != ReasonToolCLIArgsDenied {
		t.Fatalf("custom DeniedArgTokens should block FORBIDDEN, got reason=%s", res2.Reason)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: hasDeniedCLIArgToken helper
// ---------------------------------------------------------------------------

func TestHasDeniedCLIArgTokenEmptyArgs(t *testing.T) {
	if hasDeniedCLIArgToken(nil, nil) {
		t.Fatal("expected false for nil args")
	}
	if hasDeniedCLIArgToken([]string{}, nil) {
		t.Fatal("expected false for empty args")
	}
}

func TestHasDeniedCLIArgTokenCleanArgs(t *testing.T) {
	args := []string{"-la", "/tmp", "--color=auto"}
	if hasDeniedCLIArgToken(args, nil) {
		t.Fatal("expected false for clean args with default denied tokens")
	}
}

func TestHasDeniedCLIArgTokenDetectsInjection(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		token string
	}{
		{"semicolon", []string{"foo;bar"}, ";"},
		{"double-and", []string{"a && b"}, "&&"},
		{"double-pipe", []string{"a || b"}, "||"},
		{"pipe", []string{"a | b"}, "|"},
		{"subshell", []string{"$(cmd)"}, "$("},
		{"backtick", []string{"`cmd`"}, "`"},
		{"redirect-out", []string{"> file"}, ">"},
		{"redirect-in", []string{"< file"}, "<"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !hasDeniedCLIArgToken(tt.args, nil) {
				t.Fatalf("expected true for args containing %q with default denied tokens", tt.token)
			}
		})
	}
}

func TestIsDeniedCLIInterpreterCommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{command: "bash", want: true},
		{command: "sh", want: true},
		{command: "zsh", want: true},
		{command: "ls", want: false},
		{command: "grep", want: false},
	}

	for _, tt := range tests {
		if got := isDeniedCLIInterpreterCommand(tt.command); got != tt.want {
			t.Fatalf("isDeniedCLIInterpreterCommand(%q) = %v, want %v", tt.command, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Unit tests: parseStringSlice helper
// ---------------------------------------------------------------------------

func TestParseStringSliceNil(t *testing.T) {
	result := parseStringSlice(nil)
	if result != nil {
		t.Fatalf("expected nil for nil input, got %v", result)
	}
}

func TestParseStringSliceStringSlice(t *testing.T) {
	result := parseStringSlice([]string{"-la", "  /tmp  ", ""})
	if len(result) != 2 || result[0] != "-la" || result[1] != "/tmp" {
		t.Fatalf("expected [-la /tmp], got %v", result)
	}
}

func TestParseStringSliceAnySlice(t *testing.T) {
	result := parseStringSlice([]any{"-la", 42, ""})
	if len(result) != 2 || result[0] != "-la" || result[1] != "42" {
		t.Fatalf("expected [-la 42], got %v", result)
	}
}

func TestParseStringSliceSingleString(t *testing.T) {
	result := parseStringSlice("hello")
	if len(result) != 1 || result[0] != "hello" {
		t.Fatalf("expected [hello], got %v", result)
	}
}

func TestParseStringSliceEmptyString(t *testing.T) {
	result := parseStringSlice("  ")
	if result != nil {
		t.Fatalf("expected nil for whitespace string, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: YAML parsing with CLI fields
// ---------------------------------------------------------------------------

func TestCapabilityRegistryV2YAMLParsing(t *testing.T) {
	yamlContent := `
version: "2.0"
capabilities:
  - id: "tool.cli.yaml-test"
    kind: "tool"
    protocol: "cli"
    allowlist:
      - "bash"
    adapters:
      - "cli"
    allowed_commands:
      - "ls"
      - "echo"
    max_args: 5
    denied_arg_tokens:
      - ";"
      - "&&"
    action_policies:
      - action: "tool.execute"
        resources:
          - "tool/exec"
        allowed_tools:
          - "bash"
`

	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "registry.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	engine := newToolPlanePolicyEngine(yamlPath)
	rule, ok := engine.rules["tool.cli.yaml-test"]
	if !ok {
		t.Fatalf("expected rule 'tool.cli.yaml-test' to be loaded, available rules: %v", sortedRuleKeys(engine.rules))
	}

	if _, ok := rule.AllowedCommands["ls"]; !ok {
		t.Fatalf("expected 'ls' in AllowedCommands, got %v", rule.AllowedCommands)
	}
	if _, ok := rule.AllowedCommands["echo"]; !ok {
		t.Fatalf("expected 'echo' in AllowedCommands, got %v", rule.AllowedCommands)
	}
	if rule.MaxArgs != 5 {
		t.Fatalf("expected MaxArgs=5, got %d", rule.MaxArgs)
	}
	if len(rule.DeniedArgTokens) != 2 || rule.DeniedArgTokens[0] != ";" || rule.DeniedArgTokens[1] != "&&" {
		t.Fatalf("expected DeniedArgTokens=[; &&], got %v", rule.DeniedArgTokens)
	}

	// Verify the rule works: allowed command
	req := cliToolPlaneRequest("tool.cli.yaml-test", "bash", "ls", []string{"-la"})
	res := engine.evaluate(req)
	if res.Decision != DecisionAllow || res.Reason != ReasonToolAllow {
		t.Fatalf("expected allow for ls, got decision=%s reason=%s", res.Decision, res.Reason)
	}

	// Verify the rule works: disallowed command
	req2 := cliToolPlaneRequest("tool.cli.yaml-test", "bash", "rm", nil)
	res2 := engine.evaluate(req2)
	if res2.Reason != ReasonToolCLICommandDenied {
		t.Fatalf("expected TOOL_CLI_COMMAND_DENIED for rm, got reason=%s", res2.Reason)
	}

	// Verify the rule works: denied token
	req3 := cliToolPlaneRequest("tool.cli.yaml-test", "bash", "ls", []string{"; rm"})
	res3 := engine.evaluate(req3)
	if res3.Reason != ReasonToolCLIArgsDenied {
		t.Fatalf("expected TOOL_CLI_ARGS_DENIED for semicolon, got reason=%s", res3.Reason)
	}
}

// ---------------------------------------------------------------------------
// Integration tests: full handleToolExecute HTTP flow (no mocks)
// ---------------------------------------------------------------------------

func TestCLIIntegrationAllowedCommandHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())

	// Override tool policy with a CLI-safe rule (no step-up)
	gw.toolPolicy = &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.integration": {
				CapabilityID:    "tool.cli.integration",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"ls": {}, "echo": {}, "cat": {}},
				MaxArgs:         6,
				DeniedArgTokens: []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	h := gw.Handler()
	payload := cliHTTPPayload("tool.cli.integration", "bash", "ls", []any{"-la"})

	code, body := postGatewayJSON(t, h, http.MethodPost, "/v1/tool/execute", payload)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for allowed CLI command, got %d body=%v", code, body)
	}
	if got, _ := body["reason_code"].(string); got != string(ReasonToolAllow) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonToolAllow, body["reason_code"])
	}
}

func TestCLIIntegrationDeniedCommandHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())

	// Override tool policy with a CLI rule that only allows ls
	gw.toolPolicy = &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.integration": {
				CapabilityID:    "tool.cli.integration",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"ls": {}},
				MaxArgs:         6,
				DeniedArgTokens: []string{";"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	h := gw.Handler()
	payload := cliHTTPPayload("tool.cli.integration", "bash", "rm", []any{"-rf", "/"})

	code, body := postGatewayJSON(t, h, http.MethodPost, "/v1/tool/execute", payload)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for denied CLI command, got %d body=%v", code, body)
	}
	if got, _ := body["reason_code"].(string); got != string(ReasonToolCLICommandDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonToolCLICommandDenied, body["reason_code"])
	}
}

func TestCLIIntegrationDeniedArgTokenHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())

	// Override tool policy with a CLI rule
	gw.toolPolicy = &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.integration": {
				CapabilityID:    "tool.cli.integration",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"ls": {}},
				MaxArgs:         10,
				DeniedArgTokens: []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	h := gw.Handler()
	payload := cliHTTPPayload("tool.cli.integration", "bash", "ls", []any{"-la", "; rm -rf /"})

	code, body := postGatewayJSON(t, h, http.MethodPost, "/v1/tool/execute", payload)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for denied arg token, got %d body=%v", code, body)
	}
	if got, _ := body["reason_code"].(string); got != string(ReasonToolCLIArgsDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonToolCLIArgsDenied, body["reason_code"])
	}
}

func TestCLIIntegrationDeniedNestedShellInterpreterHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())

	gw.toolPolicy = &toolPlanePolicyEngine{
		rules: map[string]toolCapabilityRule{
			"tool.cli.integration": {
				CapabilityID:    "tool.cli.integration",
				Protocol:        "cli",
				Adapters:        map[string]struct{}{"cli": {}},
				AllowTools:      map[string]struct{}{"bash": {}},
				AllowedCommands: map[string]struct{}{"bash": {}, "sh": {}, "ls": {}},
				MaxArgs:         10,
				DeniedArgTokens: []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
				Actions: []toolActionRule{
					{
						Action:       "tool.execute",
						Resources:    map[string]struct{}{"tool/exec": {}},
						AllowedTools: map[string]struct{}{"bash": {}},
					},
				},
			},
		},
	}

	h := gw.Handler()
	payload := cliHTTPPayload("tool.cli.integration", "bash", "bash", []any{"-c", "touch /tmp/pwned"})

	code, body := postGatewayJSON(t, h, http.MethodPost, "/v1/tool/execute", payload)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for nested shell interpreter command, got %d body=%v", code, body)
	}
	if got, _ := body["reason_code"].(string); got != string(ReasonToolCLICommandDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonToolCLICommandDenied, body["reason_code"])
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// cliToolPlaneRequest creates a PlaneRequestV2 for a CLI tool invocation.
func cliToolPlaneRequest(capabilityID, toolName, command string, args []string) PlaneRequestV2 {
	attrs := map[string]any{
		"capability_id": capabilityID,
		"tool_name":     toolName,
		"adapter":       "cli",
		"command":       command,
	}
	if args != nil {
		strArgs := make([]any, len(args))
		for i, a := range args {
			strArgs[i] = a
		}
		attrs["args"] = strArgs
	}
	return PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "cli-test-run",
			SessionID:     "cli-test-session",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneTool,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "cli-test-run",
				SessionID:     "cli-test-session",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
			},
			Action:     "tool.execute",
			Resource:   "tool/exec",
			Attributes: attrs,
		},
	}
}

// cliHTTPPayload creates an HTTP request payload for integration tests.
func cliHTTPPayload(capabilityID, toolName, command string, args []any) map[string]any {
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "cli-integration-session"
	attrs := map[string]any{
		"capability_id": capabilityID,
		"tool_name":     toolName,
		"adapter":       "cli",
		"command":       command,
	}
	if args != nil {
		attrs["args"] = args
	}
	return map[string]any{
		"envelope": map[string]any{
			"run_id":          "cli-integration-run",
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "tool",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "cli-integration-run",
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "tool",
			},
			"action":     "tool.execute",
			"resource":   "tool/exec",
			"attributes": attrs,
		},
	}
}
