// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

const policyTestMaxRequestSizeBytes = 10 * 1024 * 1024 // 10 MiB (MAX_REQUEST_SIZE_BYTES default)

type PolicyTestLayer struct {
	Step   int    `json:"step"`
	Layer  string `json:"layer"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

type PolicyTestOfflineOutput struct {
	Mode          string            `json:"mode"`
	SPIFFEID      string            `json:"spiffe_id"`
	Tool          string            `json:"tool"`
	Layers        []PolicyTestLayer `json:"layers"`
	Verdict       string            `json:"verdict"`
	BlockingLayer int               `json:"blocking_layer,omitempty"`
	Note          string            `json:"note"`
}

func RunPolicyTestOffline(spiffeID, tool, rawParams, opaPolicyDir, toolRegistryPath string) (PolicyTestOfflineOutput, error) {
	out := PolicyTestOfflineOutput{
		Mode:     "offline",
		SPIFFEID: strings.TrimSpace(spiffeID),
		Tool:     strings.TrimSpace(tool),
		Layers:   make([]PolicyTestLayer, 0, 6),
		Note:     "Runtime layers 7-13 require --runtime flag with running stack",
	}

	if out.SPIFFEID == "" {
		return out, fmt.Errorf("spiffe-id is empty")
	}
	if out.Tool == "" {
		return out, fmt.Errorf("tool is empty")
	}

	grantsPath := strings.TrimRight(strings.TrimSpace(opaPolicyDir), "/") + "/tool_grants.yaml"
	grants, err := loadIdentityGrants(grantsPath)
	if err != nil {
		return out, err
	}
	tools, err := loadIdentityTools(strings.TrimSpace(toolRegistryPath))
	if err != nil {
		return out, err
	}

	rawParams = strings.TrimSpace(rawParams)
	if rawParams == "" {
		rawParams = "{}"
	}

	requestJSON := fmt.Sprintf(`{"jsonrpc":"2.0","method":%q,"params":%s,"id":1}`, out.Tool, rawParams)
	estimatedSize := len(requestJSON)

	var parsedParams map[string]any
	blocked := 0

	add := func(step int, layer, result, detail string) {
		out.Layers = append(out.Layers, PolicyTestLayer{
			Step:   step,
			Layer:  layer,
			Result: result,
			Detail: detail,
		})
	}
	skip := func(step int, layer string) {
		add(step, layer, "SKIP", fmt.Sprintf("blocked at layer %d", blocked))
	}
	fail := func(step int, layer, detail string) {
		add(step, layer, "FAIL", detail)
		blocked = step
	}

	// Layer 1: Request size
	if estimatedSize > policyTestMaxRequestSizeBytes {
		fail(1, "Request Size Limit", fmt.Sprintf("estimated_size=%d max=%d", estimatedSize, policyTestMaxRequestSizeBytes))
	} else {
		add(1, "Request Size Limit", "PASS", fmt.Sprintf("estimated_size=%d max=%d", estimatedSize, policyTestMaxRequestSizeBytes))
	}

	// Layer 2: Body shape (JSON-RPC 2.0)
	if blocked > 0 {
		skip(2, "Body Shape")
	} else {
		var paramsAny any
		if err := json.Unmarshal([]byte(rawParams), &paramsAny); err != nil {
			fail(2, "Body Shape", fmt.Sprintf("invalid params JSON: %v", err))
		} else {
			var ok bool
			parsedParams, ok = paramsAny.(map[string]any)
			if !ok {
				fail(2, "Body Shape", "params must be a JSON object")
			} else {
				if strings.TrimSpace(out.Tool) == "" {
					fail(2, "Body Shape", "method is empty")
				} else {
					add(2, "Body Shape", "PASS", "valid JSON-RPC 2.0")
				}
			}
		}
	}

	// Layer 3: SPIFFE trust domain
	if blocked > 0 {
		skip(3, "SPIFFE Auth")
	} else {
		trustDomain, ok := extractTrustDomain(out.SPIFFEID)
		if !ok {
			fail(3, "SPIFFE Auth", "invalid SPIFFE ID format")
		} else if trustDomain != "poc.local" {
			fail(3, "SPIFFE Auth", fmt.Sprintf("trust_domain=%s expected=poc.local", trustDomain))
		} else {
			add(3, "SPIFFE Auth", "PASS", "trust_domain=poc.local")
		}
	}

	// Layer 4: Tool registry lookup + hash sanity check.
	var toolDef identityRegistryTool
	if blocked > 0 {
		skip(4, "Tool Registry")
	} else {
		var found bool
		for _, t := range tools {
			if strings.TrimSpace(t.Name) == out.Tool {
				toolDef = t
				found = true
				break
			}
		}
		if !found {
			fail(4, "Tool Registry", fmt.Sprintf("tool=%s not found in registry", out.Tool))
		} else {
			hash := strings.TrimSpace(toolDef.Hash)
			if len(hash) != 64 {
				fail(4, "Tool Registry", fmt.Sprintf("tool=%s hash invalid length=%d", out.Tool, len(hash)))
			} else if _, err := hex.DecodeString(hash); err != nil {
				fail(4, "Tool Registry", fmt.Sprintf("tool=%s hash not hex: %v", out.Tool, err))
			} else {
				add(4, "Tool Registry", "PASS", fmt.Sprintf("tool=%s hash=verified", out.Tool))
			}
		}
	}

	// Layer 5: OPA grants evaluation from tool_grants.yaml.
	if blocked > 0 {
		skip(5, "OPA Policy")
	} else {
		matched := matchGrants(grants, out.SPIFFEID)
		if len(matched) == 0 {
			fail(5, "OPA Policy", "no matching grants")
		} else {
			var allow bool
			var grantDesc string
			for _, g := range matched {
				if toolInList("*", g.AllowedTools) || toolInList(out.Tool, g.AllowedTools) {
					allow = true
					grantDesc = strings.TrimSpace(g.Description)
					if grantDesc == "" {
						grantDesc = g.SpiffePattern
					}
					break
				}
			}
			if !allow {
				fail(5, "OPA Policy", fmt.Sprintf("tool=%s not granted for identity", out.Tool))
			} else {
				add(5, "OPA Policy", "PASS", fmt.Sprintf("grant=%s", grantDesc))
			}
		}
	}

	// Layer 6: DLP scan over params.
	if blocked > 0 {
		skip(6, "DLP Scanner")
	} else {
		scanner := middleware.NewBuiltInScanner()
		paramsJSON, _ := json.Marshal(parsedParams)
		scan := scanner.Scan(string(paramsJSON))
		if scan.HasCredentials || scan.HasPII || scan.HasSuspicious {
			fail(6, "DLP Scanner", fmt.Sprintf("detections=%s", strings.Join(scan.Flags, ",")))
		} else {
			add(6, "DLP Scanner", "PASS", "no detections")
		}
	}

	if blocked == 0 {
		out.Verdict = "ALLOWED"
	} else {
		out.Verdict = "DENIED"
		out.BlockingLayer = blocked
	}

	return out, nil
}

func RunPolicyTestRuntime(
	spiffeID, tool, rawParams, opaPolicyDir, toolRegistryPath, keydbURL, gatewayURL, sessionID string,
) (PolicyTestOfflineOutput, error) {
	out, err := RunPolicyTestOffline(spiffeID, tool, rawParams, opaPolicyDir, toolRegistryPath)
	if err != nil {
		return out, err
	}

	out.Mode = "full"
	out.Note = ""
	blocked := out.BlockingLayer

	add := func(step int, layer, result, detail string) {
		out.Layers = append(out.Layers, PolicyTestLayer{
			Step:   step,
			Layer:  layer,
			Result: result,
			Detail: detail,
		})
	}
	skip := func(step int, layer string) {
		add(step, layer, "SKIP", fmt.Sprintf("blocked at layer %d", blocked))
	}
	fail := func(step int, layer, detail string) {
		add(step, layer, "FAIL", detail)
		blocked = step
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keydbURL = strings.TrimSpace(keydbURL)
	if keydbURL == "" {
		return out, fmt.Errorf("keydb URL is empty (set --keydb-url or PRECINCT_KEYDB_URL)")
	}
	kdb, err := NewKeyDB(keydbURL)
	if err != nil {
		return out, err
	}
	defer func() { _ = kdb.Close() }()

	gatewayURL = strings.TrimSpace(gatewayURL)
	if gatewayURL == "" {
		return out, fmt.Errorf("gateway URL is empty (set --gateway-url or PRECINCT_GATEWAY_URL)")
	}
	client := NewClient(gatewayURL)

	paramsJSON := strings.TrimSpace(rawParams)
	if paramsJSON == "" {
		paramsJSON = "{}"
	}

	sessionRisk := 0.0
	sessionID = strings.TrimSpace(sessionID)

	// Layer 7: Session context check.
	if blocked > 0 {
		skip(7, "Session Context")
	} else if sessionID == "" {
		add(7, "Session Context", "SKIP", "no session-id provided")
	} else {
		score, found, err := kdb.GetSessionRiskScore(ctx, sessionID)
		if err != nil {
			fail(7, "Session Context", fmt.Sprintf("session lookup failed: %v", err))
		} else if !found {
			fail(7, "Session Context", fmt.Sprintf("session_id=%s not found", sessionID))
		} else {
			sessionRisk = score
			add(7, "Session Context", "PASS", fmt.Sprintf("risk_score=%.2f", score))
		}
	}

	// Layer 8: Step-up gating check from risk_thresholds.yaml.
	if blocked > 0 {
		skip(8, "Step-Up Gating")
	} else {
		riskPath := resolveRiskThresholdsPath(opaPolicyDir)
		riskCfg, err := middleware.LoadRiskConfig(riskPath)
		if err != nil {
			fail(8, "Step-Up Gating", fmt.Sprintf("load risk config failed: %v", err))
		} else {
			totalRisk := riskScoreToTotal(sessionRisk)
			switch {
			case totalRisk <= riskCfg.Thresholds.FastPathMax:
				add(8, "Step-Up Gating", "PASS", fmt.Sprintf("total_risk=%d gate=fast_path", totalRisk))
			case totalRisk <= riskCfg.Thresholds.StepUpMax:
				add(8, "Step-Up Gating", "PASS", fmt.Sprintf("total_risk=%d gate=step_up", totalRisk))
			case totalRisk <= riskCfg.Thresholds.ApprovalMax:
				fail(8, "Step-Up Gating", fmt.Sprintf("total_risk=%d gate=approval_required", totalRisk))
			default:
				fail(8, "Step-Up Gating", fmt.Sprintf("total_risk=%d gate=deny", totalRisk))
			}
		}
	}

	// Layer 9: Deep scan availability.
	if blocked > 0 {
		skip(9, "Deep Scan")
	} else {
		if strings.TrimSpace(os.Getenv("GUARD_API_KEY")) == "" {
			add(9, "Deep Scan", "SKIP", "guard model not configured")
		} else {
			add(9, "Deep Scan", "PASS", "GUARD_API_KEY configured")
		}
	}

	// Layer 10: Rate limiter state from KeyDB counters.
	if blocked > 0 {
		skip(10, "Rate Limiter")
	} else {
		rpm := envIntOrDefault("RATE_LIMIT_RPM", 600)
		burst := envIntOrDefault("RATE_LIMIT_BURST", 100)
		counters, err := kdb.GetRateLimitCounters(ctx, out.SPIFFEID, rpm, burst)
		if err != nil {
			fail(10, "Rate Limiter", fmt.Sprintf("rate-limit lookup failed: %v", err))
		} else if counters.Remaining <= 0 {
			fail(10, "Rate Limiter", fmt.Sprintf("remaining=%d/%d", counters.Remaining, counters.Limit))
		} else {
			add(10, "Rate Limiter", "PASS", fmt.Sprintf("remaining=%d/%d", counters.Remaining, counters.Limit))
		}
	}

	// Layer 11: Circuit breaker state from gateway admin endpoint.
	if blocked > 0 {
		skip(11, "Circuit Breaker")
	} else {
		cb, err := client.GetCircuitBreaker(ctx, out.Tool)
		if err != nil {
			fail(11, "Circuit Breaker", fmt.Sprintf("circuit-breaker lookup failed: %v", err))
		} else if strings.EqualFold(strings.TrimSpace(cb.State), "open") {
			fail(11, "Circuit Breaker", "state=open")
		} else {
			add(11, "Circuit Breaker", "PASS", fmt.Sprintf("state=%s", cb.State))
		}
	}

	// Layer 12: Token substitution check.
	if blocked > 0 {
		skip(12, "Token Substitution")
	} else {
		tokens := middleware.FindSPIKETokens(paramsJSON)
		if strings.Contains(paramsJSON, "$SPIKE{") && len(tokens) == 0 {
			fail(12, "Token Substitution", "invalid SPIKE token syntax")
		} else if len(tokens) == 0 {
			add(12, "Token Substitution", "PASS", "no SPIKE tokens in params")
		} else {
			for _, tokenStr := range tokens {
				if _, err := middleware.ParseSPIKEToken(tokenStr); err != nil {
					fail(12, "Token Substitution", fmt.Sprintf("invalid token %q: %v", tokenStr, err))
					break
				}
			}
			if blocked == 0 {
				add(12, "Token Substitution", "PASS", fmt.Sprintf("token_count=%d syntax=valid", len(tokens)))
			}
		}
	}

	// Layer 13: Audit log check (simulated dry-run only).
	if blocked > 0 {
		skip(13, "Audit Log")
	} else {
		add(13, "Audit Log", "PASS", "(would log)")
	}

	if blocked == 0 {
		out.Verdict = "ALLOWED"
		out.BlockingLayer = 0
	} else {
		out.Verdict = "DENIED"
		out.BlockingLayer = blocked
	}

	return out, nil
}

func RenderPolicyTestOfflineJSON(out PolicyTestOfflineOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderPolicyTestOfflineTable(out PolicyTestOfflineOutput) (string, error) {
	var buf bytes.Buffer
	mode := strings.TrimSpace(out.Mode)
	if mode == "" {
		mode = "offline"
	}
	_, _ = fmt.Fprintf(&buf, "DRY RUN (%s): %s calling %s\n\n", mode, out.SPIFFEID, out.Tool)

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STEP\tLAYER\tRESULT\tDETAIL")
	for _, layer := range out.Layers {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", layer.Step, layer.Layer, layer.Result, layer.Detail)
	}
	_ = tw.Flush()

	_, _ = fmt.Fprintln(&buf, "")
	if out.Verdict == "ALLOWED" && strings.EqualFold(mode, "offline") {
		_, _ = fmt.Fprintln(&buf, "VERDICT: ALLOWED (offline layers 1-6)")
	} else if out.Verdict == "ALLOWED" {
		_, _ = fmt.Fprintln(&buf, "VERDICT: ALLOWED")
	} else {
		_, _ = fmt.Fprintf(&buf, "VERDICT: DENIED (blocked at layer %d)\n", out.BlockingLayer)
	}
	if strings.TrimSpace(out.Note) != "" {
		_, _ = fmt.Fprintf(&buf, "NOTE: %s\n", out.Note)
	}
	return buf.String(), nil
}

func extractTrustDomain(spiffeID string) (string, bool) {
	const prefix = "spiffe://"
	if !strings.HasPrefix(spiffeID, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(spiffeID, prefix)
	if strings.TrimSpace(rest) == "" {
		return "", false
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[0], true
}

func resolveRiskThresholdsPath(opaPolicyDir string) string {
	trimmed := strings.TrimSpace(strings.TrimRight(opaPolicyDir, "/"))
	if trimmed == "" {
		return filepath.Join("config", "risk_thresholds.yaml")
	}
	return filepath.Join(filepath.Dir(trimmed), "risk_thresholds.yaml")
}

func riskScoreToTotal(score float64) int {
	total := int(score * 10.0)
	if total < 0 {
		return 0
	}
	if total > 12 {
		return 12
	}
	return total
}

func envIntOrDefault(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}
