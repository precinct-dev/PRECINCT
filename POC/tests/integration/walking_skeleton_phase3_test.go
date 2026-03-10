package integration

import (
	"fmt"
	"testing"
	"time"
)

func TestPhase3WalkingSkeleton_AllPlanesAllowAndDeny(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := fmt.Sprintf("phase3-it-session-%d", time.Now().UnixNano())
	nowUTC := time.Now().UTC().Format(time.RFC3339)

	decisionIDs := map[string]struct{}{}
	assertPlaneDecision := func(label string, code int, body map[string]any, wantCode int, wantReason, wantRunID string) {
		t.Helper()
		if code != wantCode {
			t.Fatalf("%s: expected status %d, got %d body=%v", label, wantCode, code, body)
		}
		if reason := stringField(body["reason_code"]); reason != wantReason {
			t.Fatalf("%s: expected reason %q, got %q body=%v", label, wantReason, reason, body)
		}
		decisionID := stringField(body["decision_id"])
		traceID := stringField(body["trace_id"])
		env := mapField(body["envelope"])
		if decisionID == "" || traceID == "" {
			t.Fatalf("%s: missing decision/trace ids body=%v", label, body)
		}
		if envSession := stringField(env["session_id"]); envSession != sessionID {
			t.Fatalf("%s: expected envelope.session_id=%q, got %q", label, sessionID, envSession)
		}
		if envRunID := stringField(env["run_id"]); envRunID != wantRunID {
			t.Fatalf("%s: expected envelope.run_id=%q, got %q", label, wantRunID, envRunID)
		}
		if _, exists := decisionIDs[decisionID]; exists {
			t.Fatalf("%s: decision_id %q reused unexpectedly", label, decisionID)
		}
		decisionIDs[decisionID] = struct{}{}
	}

	// Connector lifecycle bootstrap for ingress runtime gate.
	registerCode, registerResp := ruleOpsPostAs(t, baseURL+"/v1/connectors/register", map[string]any{
		"connector_id": "compose-webhook",
		"manifest": map[string]any{
			"connector_id":     "compose-webhook",
			"connector_type":   "webhook",
			"source_principal": spiffeID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     "bootstrap-signature",
			},
		},
	}, adminSPIFFEIDForTest())
	if registerCode != 200 {
		t.Fatalf("connector register expected 200, got %d body=%v", registerCode, registerResp)
	}
	connectorSig := nestedRuleOpsField(registerResp, "record", "expected_signature")
	if connectorSig == "" {
		t.Fatalf("connector register missing expected_signature body=%v", registerResp)
	}
	registerCode, registerResp = ruleOpsPostAs(t, baseURL+"/v1/connectors/register", map[string]any{
		"connector_id": "compose-webhook",
		"manifest": map[string]any{
			"connector_id":     "compose-webhook",
			"connector_type":   "webhook",
			"source_principal": spiffeID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     connectorSig,
			},
		},
	}, adminSPIFFEIDForTest())
	if registerCode != 200 {
		t.Fatalf("connector re-register expected 200, got %d body=%v", registerCode, registerResp)
	}
	for _, op := range []string{"validate", "approve", "activate"} {
		code, body := ruleOpsPostAs(t, baseURL+"/v1/connectors/"+op, map[string]any{"connector_id": "compose-webhook"}, adminSPIFFEIDForTest())
		if code != 200 {
			t.Fatalf("connector %s expected 200, got %d body=%v", op, code, body)
		}
	}

	ingressAllowRunID := "phase3-it-ingress-allow"
	code, body := ruleOpsPost(t, baseURL+"/v1/ingress/submit", map[string]any{
		"envelope": map[string]any{
			"run_id":          ingressAllowRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          ingressAllowRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_id":        "compose-webhook",
				"connector_signature": connectorSig,
				"source_id":           "compose-webhook",
				"source_principal":    spiffeID,
				"event_id":            "evt-phase3-it-ingress-allow",
				"event_timestamp":     nowUTC,
			},
		},
	})
	assertPlaneDecision("ingress allow", code, body, 200, "INGRESS_ALLOW", ingressAllowRunID)

	contextAllowRunID := "phase3-it-context-allow"
	code, body = ruleOpsPost(t, baseURL+"/v1/context/admit", map[string]any{
		"envelope": map[string]any{
			"run_id":          contextAllowRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "context",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          contextAllowRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "context",
			},
			"action":   "context.admit",
			"resource": "context/segment",
			"attributes": map[string]any{
				"scan_passed":               true,
				"prompt_check_passed":       true,
				"prompt_injection_detected": false,
			},
		},
	})
	assertPlaneDecision("context allow", code, body, 200, "CONTEXT_ALLOW", contextAllowRunID)

	contextDenyRunID := "phase3-it-context-deny"
	code, body = ruleOpsPost(t, baseURL+"/v1/context/admit", map[string]any{
		"envelope": map[string]any{
			"run_id":          contextDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "context",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          contextDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "context",
			},
			"action":   "context.admit",
			"resource": "context/segment",
			"attributes": map[string]any{
				"scan_passed":               false,
				"prompt_check_passed":       false,
				"prompt_injection_detected": true,
			},
		},
	})
	assertPlaneDecision("context deny", code, body, 403, "CONTEXT_NO_SCAN_NO_SEND", contextDenyRunID)

	modelAllowRunID := "phase3-it-model-allow"
	code, body = ruleOpsPost(t, baseURL+"/v1/model/call", map[string]any{
		"envelope": map[string]any{
			"run_id":          modelAllowRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "model",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          modelAllowRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "model",
			},
			"action":   "model.call",
			"resource": "model/inference",
			"attributes": map[string]any{
				"provider": "openai",
				"model":    "gpt-4o",
			},
		},
	})
	assertPlaneDecision("model allow", code, body, 200, "MODEL_ALLOW", modelAllowRunID)

	modelDenyRunID := "phase3-it-model-deny"
	code, body = ruleOpsPost(t, baseURL+"/v1/model/call", map[string]any{
		"envelope": map[string]any{
			"run_id":          modelDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "model",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          modelDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "model",
			},
			"action":   "model.call",
			"resource": "model/inference",
			"attributes": map[string]any{
				"provider":           "openai",
				"model":              "gpt-4o",
				"compliance_profile": "hipaa",
				"prompt_has_phi":     true,
				"prompt_action":      "deny",
				"prompt":             "Patient record with SSN 123-45-6789",
			},
		},
	})
	assertPlaneDecision("model deny", code, body, 403, "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED", modelDenyRunID)

	toolAllowRunID := "phase3-it-tool-allow"
	code, body = ruleOpsPost(t, baseURL+"/v1/tool/execute", map[string]any{
		"envelope": map[string]any{
			"run_id":          toolAllowRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "tool",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          toolAllowRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "tool",
			},
			"action":   "tool.execute",
			"resource": "tool/read",
			"attributes": map[string]any{
				"capability_id": "tool.default.mcp",
				"tool_name":     "read",
			},
		},
	})
	assertPlaneDecision("tool allow", code, body, 200, "TOOL_ALLOW", toolAllowRunID)

	toolAdapterDenyRunID := "phase3-it-tool-adapter-deny"
	code, body = ruleOpsPost(t, baseURL+"/v1/tool/execute", map[string]any{
		"envelope": map[string]any{
			"run_id":          toolAdapterDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "tool",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          toolAdapterDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "tool",
			},
			"action":   "tool.execute",
			"resource": "tool/read",
			"attributes": map[string]any{
				"capability_id": "tool.default.mcp",
				"tool_name":     "read",
				"protocol":      "cli",
			},
		},
	})
	assertPlaneDecision("tool adapter deny", code, body, 403, "TOOL_ADAPTER_UNSUPPORTED", toolAdapterDenyRunID)

	toolDenyRunID := "phase3-it-tool-deny"
	code, body = ruleOpsPost(t, baseURL+"/v1/tool/execute", map[string]any{
		"envelope": map[string]any{
			"run_id":          toolDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "tool",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          toolDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "tool",
			},
			"action":   "tool.execute",
			"resource": "tool/write",
			"attributes": map[string]any{
				"capability_id": "tool.unapproved.mcp",
				"tool_name":     "write",
			},
		},
	})
	assertPlaneDecision("tool deny", code, body, 403, "TOOL_CAPABILITY_DENIED", toolDenyRunID)

	loopAllowRunID := "phase3-it-loop-allow"
	code, body = ruleOpsPost(t, baseURL+"/v1/loop/check", map[string]any{
		"envelope": map[string]any{
			"run_id":          loopAllowRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "loop",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          loopAllowRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "loop",
			},
			"action":   "loop.check",
			"resource": "loop/external-governor",
			"attributes": map[string]any{
				"limits": map[string]any{
					"max_steps":              10,
					"max_tool_calls":         10,
					"max_model_calls":        10,
					"max_wall_time_ms":       60000,
					"max_egress_bytes":       100000,
					"max_model_cost_usd":     1.0,
					"max_provider_failovers": 2,
					"max_risk_score":         0.9,
				},
				"usage": map[string]any{
					"steps":              1,
					"tool_calls":         1,
					"model_calls":        1,
					"wall_time_ms":       1000,
					"egress_bytes":       10,
					"model_cost_usd":     0.01,
					"provider_failovers": 0,
					"risk_score":         0.2,
				},
			},
		},
	})
	assertPlaneDecision("loop allow", code, body, 200, "LOOP_ALLOW", loopAllowRunID)

	loopToolCallsDenyRunID := "phase3-it-loop-deny-tool-calls"
	code, body = ruleOpsPost(t, baseURL+"/v1/loop/check", map[string]any{
		"envelope": map[string]any{
			"run_id":          loopToolCallsDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "loop",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          loopToolCallsDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "loop",
			},
			"action":   "loop.check",
			"resource": "loop/external-governor",
			"attributes": map[string]any{
				"limits": map[string]any{
					"max_steps":              10,
					"max_tool_calls":         1,
					"max_model_calls":        10,
					"max_wall_time_ms":       60000,
					"max_egress_bytes":       100000,
					"max_model_cost_usd":     1.0,
					"max_provider_failovers": 2,
					"max_risk_score":         0.9,
				},
				"usage": map[string]any{
					"steps":              1,
					"tool_calls":         2,
					"model_calls":        1,
					"wall_time_ms":       1000,
					"egress_bytes":       10,
					"model_cost_usd":     0.01,
					"provider_failovers": 0,
					"risk_score":         0.2,
				},
			},
		},
	})
	assertPlaneDecision("loop deny tool calls", code, body, 429, "LOOP_HALT_MAX_TOOL_CALLS", loopToolCallsDenyRunID)

	loopRiskDenyRunID := "phase3-it-loop-deny-risk"
	code, body = ruleOpsPost(t, baseURL+"/v1/loop/check", map[string]any{
		"envelope": map[string]any{
			"run_id":          loopRiskDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "loop",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          loopRiskDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "loop",
			},
			"action":   "loop.check",
			"resource": "loop/external-governor",
			"attributes": map[string]any{
				"limits": map[string]any{
					"max_steps":              10,
					"max_tool_calls":         10,
					"max_model_calls":        10,
					"max_wall_time_ms":       60000,
					"max_egress_bytes":       100000,
					"max_model_cost_usd":     1.0,
					"max_provider_failovers": 2,
					"max_risk_score":         0.5,
				},
				"usage": map[string]any{
					"steps":              1,
					"tool_calls":         1,
					"model_calls":        1,
					"wall_time_ms":       1000,
					"egress_bytes":       10,
					"model_cost_usd":     0.01,
					"provider_failovers": 0,
					"risk_score":         0.8,
				},
			},
		},
	})
	assertPlaneDecision("loop deny risk", code, body, 403, "LOOP_HALT_MAX_RISK_SCORE", loopRiskDenyRunID)

	loopDenyRunID := "phase3-it-loop-deny"
	code, body = ruleOpsPost(t, baseURL+"/v1/loop/check", map[string]any{
		"envelope": map[string]any{
			"run_id":          loopDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "loop",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          loopDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "loop",
			},
			"action":   "loop.check",
			"resource": "loop/external-governor",
			"attributes": map[string]any{
				"limits": map[string]any{
					"max_steps":              1,
					"max_tool_calls":         10,
					"max_model_calls":        10,
					"max_wall_time_ms":       60000,
					"max_egress_bytes":       100000,
					"max_model_cost_usd":     1.0,
					"max_provider_failovers": 2,
					"max_risk_score":         0.9,
				},
				"usage": map[string]any{
					"steps":              2,
					"tool_calls":         1,
					"model_calls":        1,
					"wall_time_ms":       1000,
					"egress_bytes":       10,
					"model_cost_usd":     0.01,
					"provider_failovers": 0,
					"risk_score":         0.2,
				},
			},
		},
	})
	assertPlaneDecision("loop deny", code, body, 429, "LOOP_HALT_MAX_STEPS", loopDenyRunID)

	revokeCode, revokeBody := ruleOpsPostAs(t, baseURL+"/v1/connectors/revoke", map[string]any{"connector_id": "compose-webhook"}, adminSPIFFEIDForTest())
	if revokeCode != 200 {
		t.Fatalf("connector revoke expected 200, got %d body=%v", revokeCode, revokeBody)
	}

	ingressDenyRunID := "phase3-it-ingress-deny"
	code, body = ruleOpsPost(t, baseURL+"/v1/ingress/submit", map[string]any{
		"envelope": map[string]any{
			"run_id":          ingressDenyRunID,
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          ingressDenyRunID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_id":        "compose-webhook",
				"connector_signature": connectorSig,
				"source_id":           "compose-webhook",
				"source_principal":    spiffeID,
				"event_id":            "evt-phase3-it-ingress-deny",
				"event_timestamp":     nowUTC,
			},
		},
	})
	assertPlaneDecision("ingress deny", code, body, 403, "INGRESS_SOURCE_UNAUTHENTICATED", ingressDenyRunID)

	if len(decisionIDs) != 13 {
		t.Fatalf("expected 13 unique plane decision ids, got %d", len(decisionIDs))
	}
}

func mapField(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func stringField(v any) string {
	s, _ := v.(string)
	return s
}
