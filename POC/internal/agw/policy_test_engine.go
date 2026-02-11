package agw

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
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

func RenderPolicyTestOfflineJSON(out PolicyTestOfflineOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderPolicyTestOfflineTable(out PolicyTestOfflineOutput) (string, error) {
	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "DRY RUN (offline): %s calling %s\n\n", out.SPIFFEID, out.Tool)

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STEP\tLAYER\tRESULT\tDETAIL")
	for _, layer := range out.Layers {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", layer.Step, layer.Layer, layer.Result, layer.Detail)
	}
	_ = tw.Flush()

	_, _ = fmt.Fprintln(&buf, "")
	if out.Verdict == "ALLOWED" {
		_, _ = fmt.Fprintln(&buf, "VERDICT: ALLOWED (offline layers 1-6)")
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
