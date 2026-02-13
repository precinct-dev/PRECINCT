package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	ocadapter "github.com/example/agentic-security-poc/internal/integrations/openclaw"
)

func TestOpenClawWalkingSkeleton_MediatedAllowAndDeterministicDeny(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/openclaw/dev"
	sessionID := fmt.Sprintf("openclaw-it-session-%d", time.Now().UnixNano())
	nowUTC := time.Now().UTC().Format(time.RFC3339)

	assertDecision := func(label string, code int, body map[string]any, wantCode int, wantReason string) {
		t.Helper()
		if code != wantCode {
			t.Fatalf("%s: expected status %d, got %d body=%v", label, wantCode, code, body)
		}
		if reason := stringField(body["reason_code"]); reason != wantReason {
			t.Fatalf("%s: expected reason %q, got %q body=%v", label, wantReason, reason, body)
		}
		if stringField(body["decision_id"]) == "" || stringField(body["trace_id"]) == "" {
			t.Fatalf("%s: missing decision or trace id body=%v", label, body)
		}
	}

	registerCode, registerResp := ruleOpsPost(t, baseURL+"/v1/connectors/register", map[string]any{
		"connector_id": "openclaw-webhook",
		"manifest": map[string]any{
			"connector_id":     "openclaw-webhook",
			"connector_type":   "webhook",
			"source_principal": spiffeID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     "bootstrap-signature",
			},
		},
	})
	if registerCode != 200 {
		t.Fatalf("connector register expected 200, got %d body=%v", registerCode, registerResp)
	}
	connectorSig := nestedRuleOpsField(registerResp, "record", "expected_signature")
	if connectorSig == "" {
		t.Fatalf("connector register missing expected_signature body=%v", registerResp)
	}
	registerCode, registerResp = ruleOpsPost(t, baseURL+"/v1/connectors/register", map[string]any{
		"connector_id": "openclaw-webhook",
		"manifest": map[string]any{
			"connector_id":     "openclaw-webhook",
			"connector_type":   "webhook",
			"source_principal": spiffeID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     connectorSig,
			},
		},
	})
	if registerCode != 200 {
		t.Fatalf("connector re-register expected 200, got %d body=%v", registerCode, registerResp)
	}
	for _, op := range []string{"validate", "approve", "activate"} {
		code, body := ruleOpsPost(t, baseURL+"/v1/connectors/"+op, map[string]any{"connector_id": "openclaw-webhook"})
		if code != 200 {
			t.Fatalf("connector %s expected 200, got %d body=%v", op, code, body)
		}
	}

	ingressAllowRunID := "openclaw-it-ingress-allow"
	code, body := ruleOpsPostAs(t, baseURL+"/v1/ingress/submit", ocadapter.BuildIngressSubmitRequest(ocadapter.IngressSubmitParams{
		EnvelopeParams: ocadapter.EnvelopeParams{
			RunID:     ingressAllowRunID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "ingress",
		},
		ConnectorID:        "openclaw-webhook",
		ConnectorSignature: connectorSig,
		SourceID:           "openclaw-webhook",
		SourcePrincipal:    spiffeID,
		EventID:            "evt-openclaw-ingress-allow",
		EventTimestamp:     nowUTC,
	}), spiffeID)
	assertDecision("ingress allow", code, body, 200, "INGRESS_ALLOW")

	contextAllowRunID := "openclaw-it-context-allow"
	code, body = ruleOpsPostAs(t, baseURL+"/v1/context/admit", ocadapter.BuildContextMemoryRequest(ocadapter.ContextAdmitParams{
		EnvelopeParams: ocadapter.EnvelopeParams{
			RunID:     contextAllowRunID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "context",
		},
		Attributes: map[string]any{
			"scan_passed":               true,
			"prompt_check_passed":       true,
			"prompt_injection_detected": false,
			"memory_scope":              "session",
		},
	}), spiffeID)
	assertDecision("context allow", code, body, 200, "CONTEXT_ALLOW")

	modelAllowRunID := "openclaw-it-model-allow"
	code, body = ruleOpsPostAs(t, baseURL+"/v1/model/call", ocadapter.BuildModelCallRequest(ocadapter.ModelCallParams{
		EnvelopeParams: ocadapter.EnvelopeParams{
			RunID:     modelAllowRunID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "model",
		},
		Attributes: map[string]any{
			"provider": "openai",
			"model":    "gpt-4o",
			"prompt":   "OpenClaw mediated call with non-sensitive content.",
		},
	}), spiffeID)
	assertDecision("model allow", code, body, 200, "MODEL_ALLOW")

	toolAllowRunID := "openclaw-it-tool-allow"
	code, body = ruleOpsPostAs(t, baseURL+"/v1/tool/execute", ocadapter.BuildToolExecuteRequest(ocadapter.ToolExecuteParams{
		EnvelopeParams: ocadapter.EnvelopeParams{
			RunID:     toolAllowRunID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "tool",
		},
		Resource: "tool/read",
		Attributes: map[string]any{
			"capability_id": "tool.default.mcp",
			"tool_name":     "read",
		},
	}), spiffeID)
	assertDecision("tool allow", code, body, 200, "TOOL_ALLOW")

	modelDenyRunID := "openclaw-it-model-deny"
	code, body = ruleOpsPostAs(t, baseURL+"/v1/model/call", ocadapter.BuildModelCallRequest(ocadapter.ModelCallParams{
		EnvelopeParams: ocadapter.EnvelopeParams{
			RunID:     modelDenyRunID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "model",
		},
		Attributes: map[string]any{
			"provider":       "openai",
			"model":          "gpt-4o",
			"direct_egress":  true,
			"mediation_mode": "direct",
		},
	}), spiffeID)
	assertDecision("model deny direct egress", code, body, 403, "MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED")

	toolDenyRunID := "openclaw-it-tool-deny"
	code, body = ruleOpsPostAs(t, baseURL+"/v1/tool/execute", ocadapter.BuildToolExecuteRequest(ocadapter.ToolExecuteParams{
		EnvelopeParams: ocadapter.EnvelopeParams{
			RunID:     toolDenyRunID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "tool",
		},
		Resource: "tool/write",
		Attributes: map[string]any{
			"capability_id": "tool.unapproved.mcp",
			"tool_name":     "write",
		},
	}), spiffeID)
	assertDecision("tool deny unapproved capability", code, body, 403, "TOOL_CAPABILITY_DENIED")
}

func ruleOpsPostAs(t *testing.T, url string, payload map[string]any, spiffeID string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s failed: %v", url, err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
