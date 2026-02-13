package gateway

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// NOTE: These Phase 3 plane policy engines are scaffolding to keep the POC
// implementation compile-safe while we incrementally wire enforcement into
// specific ingress/context/loop/tool paths. The "hard controls" remain in
// existing middleware (OPA, DLP, deep scan, step-up gating, rate limiting).

type ingressPlanePolicyEngine struct{}

func newIngressPlanePolicyEngine() *ingressPlanePolicyEngine {
	return &ingressPlanePolicyEngine{}
}

type contextPlanePolicyEngine struct{}

func newContextPlanePolicyEngine() *contextPlanePolicyEngine {
	return &contextPlanePolicyEngine{}
}

type loopRunRecord struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

type loopPlanePolicyEngine struct {
	mu   sync.Mutex
	runs []loopRunRecord
}

func newLoopPlanePolicyEngine() *loopPlanePolicyEngine {
	return &loopPlanePolicyEngine{
		runs: make([]loopRunRecord, 0),
	}
}

func (l *loopPlanePolicyEngine) listRuns() []loopRunRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]loopRunRecord, len(l.runs))
	copy(out, l.runs)
	return out
}

type toolPlanePolicyEngine struct {
	capabilityRegistryV2Path string
	rules                    map[string]toolCapabilityRule
}

type capabilityRegistryV2 struct {
	Version      string                    `yaml:"version"`
	Capabilities []capabilityRegistryEntry `yaml:"capabilities"`
}

type capabilityRegistryEntry struct {
	ID             string                  `yaml:"id"`
	Kind           string                  `yaml:"kind"`
	Protocol       string                  `yaml:"protocol"`
	Server         string                  `yaml:"server"`
	Allowlist      []string                `yaml:"allowlist"`
	Adapters       []string                `yaml:"adapters"`
	ActionPolicies []toolActionPolicyEntry `yaml:"action_policies"`
}

type toolActionPolicyEntry struct {
	Action        string   `yaml:"action"`
	Resources     []string `yaml:"resources"`
	AllowedTools  []string `yaml:"allowed_tools"`
	RequireStepUp bool     `yaml:"require_step_up"`
}

type toolCapabilityRule struct {
	CapabilityID string
	Protocol     string
	Adapters     map[string]struct{}
	AllowTools   map[string]struct{}
	Actions      []toolActionRule
}

type toolActionRule struct {
	Action        string
	Resources     map[string]struct{}
	AllowedTools  map[string]struct{}
	RequireStepUp bool
}

type toolPlaneEvalResult struct {
	Decision            Decision
	Reason              ReasonCode
	HTTPStatus          int
	Metadata            map[string]any
	RequireStepUp       bool
	RequestedAction     string
	RequestedResource   string
	RequestedTool       string
	RequestedCapability string
	RequestedAdapter    string
}

func newToolPlanePolicyEngine(capabilityRegistryV2Path string) *toolPlanePolicyEngine {
	engine := &toolPlanePolicyEngine{
		capabilityRegistryV2Path: strings.TrimSpace(capabilityRegistryV2Path),
		rules:                    defaultToolCapabilityRules(),
	}
	if err := engine.loadRulesFromFile(); err != nil {
		log.Printf("phase3 tool plane: using built-in defaults (registry load failed: %v)", err)
	}
	return engine
}

func (t *toolPlanePolicyEngine) loadRulesFromFile() error {
	if t == nil {
		return nil
	}
	path := strings.TrimSpace(t.capabilityRegistryV2Path)
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var cfg capabilityRegistryV2
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	rules := make(map[string]toolCapabilityRule)
	for _, entry := range cfg.Capabilities {
		if strings.ToLower(strings.TrimSpace(entry.Kind)) != "tool" {
			continue
		}
		capabilityID := strings.TrimSpace(entry.ID)
		if capabilityID == "" {
			continue
		}

		protocol := strings.ToLower(strings.TrimSpace(entry.Protocol))
		adapterSet := make(map[string]struct{})
		if protocol != "" {
			adapterSet[protocol] = struct{}{}
		}
		for _, adapter := range entry.Adapters {
			if v := strings.ToLower(strings.TrimSpace(adapter)); v != "" {
				adapterSet[v] = struct{}{}
			}
		}
		if len(adapterSet) == 0 {
			adapterSet["mcp"] = struct{}{}
		}

		allowTools := make(map[string]struct{})
		for _, tool := range entry.Allowlist {
			if v := strings.TrimSpace(tool); v != "" {
				allowTools[v] = struct{}{}
			}
		}

		actionRules := make([]toolActionRule, 0, len(entry.ActionPolicies))
		for _, policy := range entry.ActionPolicies {
			action := strings.TrimSpace(policy.Action)
			if action == "" {
				continue
			}

			resourceSet := make(map[string]struct{})
			for _, res := range policy.Resources {
				if v := strings.TrimSpace(res); v != "" {
					resourceSet[v] = struct{}{}
				}
			}

			allowedTools := make(map[string]struct{})
			for _, tool := range policy.AllowedTools {
				if v := strings.TrimSpace(tool); v != "" {
					allowedTools[v] = struct{}{}
				}
			}

			actionRules = append(actionRules, toolActionRule{
				Action:        action,
				Resources:     resourceSet,
				AllowedTools:  allowedTools,
				RequireStepUp: policy.RequireStepUp,
			})
		}

		// Backward compatibility for minimal registries: default action policy.
		if len(actionRules) == 0 {
			actionRules = append(actionRules, toolActionRule{
				Action:       "tool.execute",
				Resources:    map[string]struct{}{},
				AllowedTools: cloneStringSet(allowTools),
			})
		}

		rules[capabilityID] = toolCapabilityRule{
			CapabilityID: capabilityID,
			Protocol:     protocol,
			Adapters:     adapterSet,
			AllowTools:   allowTools,
			Actions:      actionRules,
		}
	}

	if len(rules) == 0 {
		return nil
	}

	t.rules = rules
	return nil
}

func defaultToolCapabilityRules() map[string]toolCapabilityRule {
	return map[string]toolCapabilityRule{
		"tool.default.mcp": {
			CapabilityID: "tool.default.mcp",
			Protocol:     "mcp",
			Adapters: map[string]struct{}{
				"mcp": struct{}{},
			},
			AllowTools: map[string]struct{}{
				"read":          struct{}{},
				"tavily_search": struct{}{},
			},
			Actions: []toolActionRule{
				{
					Action: "tool.execute",
					Resources: map[string]struct{}{
						"tool/read":   struct{}{},
						"tool/search": struct{}{},
					},
					AllowedTools: map[string]struct{}{
						"read":          struct{}{},
						"tavily_search": struct{}{},
					},
				},
			},
		},
		"tool.highrisk.cli": {
			CapabilityID: "tool.highrisk.cli",
			Protocol:     "cli",
			Adapters: map[string]struct{}{
				"cli": struct{}{},
			},
			AllowTools: map[string]struct{}{
				"bash": struct{}{},
			},
			Actions: []toolActionRule{
				{
					Action: "tool.execute",
					Resources: map[string]struct{}{
						"tool/write": struct{}{},
						"tool/exec":  struct{}{},
					},
					AllowedTools: map[string]struct{}{
						"bash": struct{}{},
					},
					RequireStepUp: true,
				},
			},
		},
	}
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (t *toolPlanePolicyEngine) evaluate(req PlaneRequestV2) toolPlaneEvalResult {
	deny := func(reason ReasonCode, metadata map[string]any) toolPlaneEvalResult {
		return toolPlaneEvalResult{
			Decision:   DecisionDeny,
			Reason:     reason,
			HTTPStatus: statusForToolReason(reason),
			Metadata:   metadata,
		}
	}
	stepUp := func(metadata map[string]any) toolPlaneEvalResult {
		return toolPlaneEvalResult{
			Decision:      DecisionStepUp,
			Reason:        ReasonToolStepUpRequired,
			HTTPStatus:    statusForToolReason(ReasonToolStepUpRequired),
			Metadata:      metadata,
			RequireStepUp: true,
		}
	}

	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	capabilityID := strings.TrimSpace(getStringAttr(attrs, "capability_id", ""))
	toolName := strings.TrimSpace(getStringAttr(attrs, "tool_name", ""))
	adapter := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "adapter", "")))
	if adapter == "" {
		adapter = strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "protocol", "")))
	}
	requestedAction := strings.TrimSpace(req.Policy.Action)
	requestedResource := strings.TrimSpace(req.Policy.Resource)

	resultMetadata := map[string]any{
		"capability_id": capabilityID,
		"tool_name":     toolName,
		"adapter":       adapter,
		"action":        requestedAction,
		"resource":      requestedResource,
	}

	rule, ok := t.rules[capabilityID]
	if !ok || capabilityID == "" || toolName == "" {
		resultMetadata["known_capabilities"] = sortedRuleKeys(t.rules)
		return deny(ReasonToolCapabilityDenied, resultMetadata)
	}

	if len(rule.AllowTools) > 0 {
		if _, allowed := rule.AllowTools[toolName]; !allowed {
			return deny(ReasonToolCapabilityDenied, resultMetadata)
		}
	}

	if adapter == "" {
		adapter = rule.Protocol
		resultMetadata["adapter"] = adapter
	}
	if len(rule.Adapters) > 0 {
		if _, allowed := rule.Adapters[adapter]; !allowed {
			resultMetadata["allowed_adapters"] = sortedStringSet(rule.Adapters)
			return deny(ReasonToolAdapterUnsupported, resultMetadata)
		}
	}

	matchedAction := false
	matchedActionAndResource := false
	for _, actionRule := range rule.Actions {
		if actionRule.Action != requestedAction {
			continue
		}
		matchedAction = true

		if len(actionRule.Resources) > 0 {
			if _, ok := actionRule.Resources[requestedResource]; !ok {
				continue
			}
		}
		if len(actionRule.AllowedTools) > 0 {
			if _, ok := actionRule.AllowedTools[toolName]; !ok {
				continue
			}
		}
		matchedActionAndResource = true

		if actionRule.RequireStepUp {
			resultMetadata["requires_step_up"] = true
			return stepUp(resultMetadata)
		}

		return toolPlaneEvalResult{
			Decision: DecisionAllow,
			Reason:   ReasonToolAllow,
			Metadata: mergeMetadata(resultMetadata, map[string]any{
				"requires_step_up": false,
			}),
			HTTPStatus: statusForToolReason(ReasonToolAllow),
		}
	}

	if !matchedAction {
		resultMetadata["policy_hint"] = "action_not_registered"
		return deny(ReasonToolActionDenied, resultMetadata)
	}
	if !matchedActionAndResource {
		resultMetadata["policy_hint"] = "resource_or_tool_not_allowed"
		return deny(ReasonToolActionDenied, resultMetadata)
	}

	return deny(ReasonToolActionDenied, resultMetadata)
}

func statusForToolReason(reason ReasonCode) int {
	switch reason {
	case ReasonToolAllow:
		return 200
	case ReasonToolStepUpRequired:
		return 428
	default:
		return 403
	}
}

func sortedStringSet(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	if len(out) <= 1 {
		return out
	}
	sortStrings(out)
	return out
}

func sortedRuleKeys(in map[string]toolCapabilityRule) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	if len(out) <= 1 {
		return out
	}
	sortStrings(out)
	return out
}

func sortStrings(values []string) {
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

type rlmGovernanceEngine struct{}

func newRLMGovernanceEngine() *rlmGovernanceEngine {
	return &rlmGovernanceEngine{}
}
