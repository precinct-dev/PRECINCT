// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package skeleton

import "testing"

func TestBuildIngressSubmitRequest(t *testing.T) {
	req := BuildIngressSubmitRequest(IngressSubmitParams{
		EnvelopeParams: EnvelopeParams{
			RunID:     "openclaw-it-ingress-allow",
			SessionID: "openclaw-it-session-1",
			SPIFFEID:  "spiffe://poc.local/agents/mcp-client/openclaw/dev",
			Plane:     "ingress",
		},
		ConnectorType:      "webhook",
		ConnectorID:        "openclaw-webhook",
		ConnectorSignature: "sig-1",
		SourceID:           "openclaw-webhook",
		SourcePrincipal:    "spiffe://poc.local/agents/mcp-client/openclaw/dev",
		EventID:            "evt-1",
		Nonce:              "nonce-1",
		EventTimestamp:     "2026-02-13T00:00:00Z",
		Payload: map[string]any{
			"channel": "webhook",
		},
	})

	env := mapField(t, req["envelope"])
	if env["plane"] != "ingress" {
		t.Fatalf("expected ingress plane, got %v", env["plane"])
	}
	policy := mapField(t, req["policy"])
	if policy["action"] != "ingress.admit" {
		t.Fatalf("expected ingress action, got %v", policy["action"])
	}
	if policy["resource"] != "ingress/event" {
		t.Fatalf("expected ingress resource, got %v", policy["resource"])
	}
	attrs := mapField(t, policy["attributes"])
	if attrs["connector_type"] != "webhook" {
		t.Fatalf("expected webhook connector type, got %v", attrs["connector_type"])
	}
	if attrs["nonce"] != "nonce-1" {
		t.Fatalf("expected nonce-1, got %v", attrs["nonce"])
	}
	if _, ok := attrs["payload"].(map[string]any); !ok {
		t.Fatalf("expected payload map, got %T", attrs["payload"])
	}
}

func TestBuildContextMemoryRequestClonesAttributes(t *testing.T) {
	attrs := map[string]any{
		"scan_passed":               true,
		"prompt_check_passed":       true,
		"prompt_injection_detected": false,
	}
	req := BuildContextMemoryRequest(ContextAdmitParams{
		EnvelopeParams: EnvelopeParams{
			RunID:     "openclaw-it-context-allow",
			SessionID: "openclaw-it-session-1",
			SPIFFEID:  "spiffe://poc.local/agents/mcp-client/openclaw/dev",
			Plane:     "context",
		},
		Attributes: attrs,
	})
	attrs["scan_passed"] = false

	policy := mapField(t, req["policy"])
	gotAttrs := mapField(t, policy["attributes"])
	if gotAttrs["scan_passed"] != true {
		t.Fatalf("expected attributes to be cloned, got %v", gotAttrs["scan_passed"])
	}
}

func TestBuildToolExecuteRequestSupportsResourceOverride(t *testing.T) {
	req := BuildToolExecuteRequest(ToolExecuteParams{
		EnvelopeParams: EnvelopeParams{
			RunID:     "openclaw-it-tool-deny",
			SessionID: "openclaw-it-session-1",
			SPIFFEID:  "spiffe://poc.local/agents/mcp-client/openclaw/dev",
			Plane:     "tool",
		},
		Resource: "tool/write",
		Attributes: map[string]any{
			"capability_id": "tool.unapproved.mcp",
			"tool_name":     "write",
		},
	})

	policy := mapField(t, req["policy"])
	if policy["resource"] != "tool/write" {
		t.Fatalf("expected tool/write resource, got %v", policy["resource"])
	}
}

func mapField(t *testing.T, v any) map[string]any {
	t.Helper()
	out, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", v)
	}
	return out
}
