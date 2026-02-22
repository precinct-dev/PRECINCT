package gateway

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type loopRunRecord struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

type loopPlanePolicyEngine struct {
	mu    sync.Mutex
	runs  []loopRunRecord
	state map[string]*loopRunState
}

type loopLimitVector struct {
	MaxSteps             int
	MaxToolCalls         int
	MaxModelCalls        int
	MaxWallTimeMS        int
	MaxEgressBytes       int
	MaxModelCostUSD      float64
	MaxProviderFailovers int
	MaxRiskScore         float64
}

type loopUsageVector struct {
	Steps             int
	ToolCalls         int
	ModelCalls        int
	WallTimeMS        int
	EgressBytes       int
	ModelCostUSD      float64
	ProviderFailovers int
	RiskScore         float64
}

type loopRunState struct {
	Key        string
	RunID      string
	SessionID  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Status     string
	LastReason ReasonCode
	Limits     loopLimitVector
	Usage      loopUsageVector
}

type loopPlaneEvalResult struct {
	Decision   Decision
	Reason     ReasonCode
	HTTPStatus int
	Metadata   map[string]any
}

func newLoopPlanePolicyEngine() *loopPlanePolicyEngine {
	return &loopPlanePolicyEngine{
		runs:  make([]loopRunRecord, 0),
		state: make(map[string]*loopRunState),
	}
}

func (l *loopPlanePolicyEngine) listRuns() []loopRunRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]loopRunRecord, len(l.runs))
	copy(out, l.runs)
	return out
}

func (l *loopPlanePolicyEngine) evaluate(req PlaneRequestV2) loopPlaneEvalResult {
	deny := func(reason ReasonCode, metadata map[string]any) loopPlaneEvalResult {
		return loopPlaneEvalResult{
			Decision:   DecisionDeny,
			Reason:     reason,
			HTTPStatus: statusForLoopReason(reason),
			Metadata:   metadata,
		}
	}

	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	limitsRaw, _ := attrs["limits"].(map[string]any)
	usageRaw, _ := attrs["usage"].(map[string]any)
	if limitsRaw == nil {
		limitsRaw = map[string]any{}
	}
	if usageRaw == nil {
		usageRaw = map[string]any{}
	}

	key := req.Envelope.RunID + "|" + req.Envelope.SessionID
	now := time.Now().UTC()
	incomingLimits := parseLoopLimits(limitsRaw)
	incomingUsage := parseLoopUsage(usageRaw)

	l.mu.Lock()
	defer l.mu.Unlock()

	state, exists := l.state[key]
	if !exists {
		state = &loopRunState{
			Key:       key,
			RunID:     req.Envelope.RunID,
			SessionID: req.Envelope.SessionID,
			CreatedAt: now,
			UpdatedAt: now,
			Status:    "active",
			Limits:    incomingLimits,
			Usage:     incomingUsage,
		}
		l.state[key] = state
		l.runs = append(l.runs, loopRunRecord{
			ID:        key,
			CreatedAt: now,
			Status:    "active",
		})
	} else {
		if !loopLimitsEqual(state.Limits, incomingLimits) {
			state.Status = "denied"
			state.LastReason = ReasonLoopLimitsImmutableViolation
			state.UpdatedAt = now
			l.updateRunRecordLocked(state)
			return deny(ReasonLoopLimitsImmutableViolation, map[string]any{
				"run_id":          req.Envelope.RunID,
				"session_id":      req.Envelope.SessionID,
				"stored_limits":   state.Limits.toMap(),
				"incoming_limits": incomingLimits.toMap(),
			})
		}
		if state.Status == "halted" {
			return deny(ReasonLoopRunAlreadyTerminated, map[string]any{
				"run_id":        req.Envelope.RunID,
				"session_id":    req.Envelope.SessionID,
				"halt_reason":   state.LastReason,
				"current_usage": state.Usage.toMap(),
				"limits":        state.Limits.toMap(),
			})
		}
		state.Usage = mergeLoopUsage(state.Usage, incomingUsage)
		state.UpdatedAt = now
	}

	breachReason, breachMeta, breached := evaluateLoopBreach(state)
	if breached {
		state.Status = "halted"
		state.LastReason = breachReason
		state.UpdatedAt = now
		l.updateRunRecordLocked(state)
		metadata := map[string]any{
			"run_id":        state.RunID,
			"session_id":    state.SessionID,
			"limits":        state.Limits.toMap(),
			"current_usage": state.Usage.toMap(),
		}
		return deny(breachReason, mergeMetadata(metadata, breachMeta))
	}

	state.Status = "active"
	state.LastReason = ReasonLoopAllow
	state.UpdatedAt = now
	l.updateRunRecordLocked(state)

	return loopPlaneEvalResult{
		Decision:   DecisionAllow,
		Reason:     ReasonLoopAllow,
		HTTPStatus: statusForLoopReason(ReasonLoopAllow),
		Metadata: map[string]any{
			"run_id":        state.RunID,
			"session_id":    state.SessionID,
			"limits":        state.Limits.toMap(),
			"current_usage": state.Usage.toMap(),
		},
	}
}

func (l *loopPlanePolicyEngine) updateRunRecordLocked(state *loopRunState) {
	for idx := range l.runs {
		if l.runs[idx].ID == state.Key {
			l.runs[idx].Status = state.Status
			return
		}
	}
	l.runs = append(l.runs, loopRunRecord{
		ID:        state.Key,
		CreatedAt: state.CreatedAt,
		Status:    state.Status,
	})
}

func statusForLoopReason(reason ReasonCode) int {
	switch reason {
	case ReasonLoopAllow:
		return 200
	case ReasonLoopLimitsImmutableViolation:
		return 403
	default:
		return 429
	}
}

func parseLoopLimits(raw map[string]any) loopLimitVector {
	return loopLimitVector{
		MaxSteps:             getIntAttr(raw, "max_steps", 0),
		MaxToolCalls:         getIntAttr(raw, "max_tool_calls", 0),
		MaxModelCalls:        getIntAttr(raw, "max_model_calls", 0),
		MaxWallTimeMS:        getIntAttr(raw, "max_wall_time_ms", 0),
		MaxEgressBytes:       getIntAttr(raw, "max_egress_bytes", 0),
		MaxModelCostUSD:      getFloatAttr(raw, "max_model_cost_usd", 0),
		MaxProviderFailovers: getIntAttr(raw, "max_provider_failovers", 0),
		MaxRiskScore:         getFloatAttr(raw, "max_risk_score", 0),
	}
}

func parseLoopUsage(raw map[string]any) loopUsageVector {
	return loopUsageVector{
		Steps:             getIntAttr(raw, "steps", 0),
		ToolCalls:         getIntAttr(raw, "tool_calls", 0),
		ModelCalls:        getIntAttr(raw, "model_calls", 0),
		WallTimeMS:        getIntAttr(raw, "wall_time_ms", 0),
		EgressBytes:       getIntAttr(raw, "egress_bytes", 0),
		ModelCostUSD:      getFloatAttr(raw, "model_cost_usd", 0),
		ProviderFailovers: getIntAttr(raw, "provider_failovers", 0),
		RiskScore:         getFloatAttr(raw, "risk_score", 0),
	}
}

func mergeLoopUsage(existing, incoming loopUsageVector) loopUsageVector {
	out := existing
	if incoming.Steps > out.Steps {
		out.Steps = incoming.Steps
	}
	if incoming.ToolCalls > out.ToolCalls {
		out.ToolCalls = incoming.ToolCalls
	}
	if incoming.ModelCalls > out.ModelCalls {
		out.ModelCalls = incoming.ModelCalls
	}
	if incoming.WallTimeMS > out.WallTimeMS {
		out.WallTimeMS = incoming.WallTimeMS
	}
	if incoming.EgressBytes > out.EgressBytes {
		out.EgressBytes = incoming.EgressBytes
	}
	if incoming.ModelCostUSD > out.ModelCostUSD {
		out.ModelCostUSD = incoming.ModelCostUSD
	}
	if incoming.ProviderFailovers > out.ProviderFailovers {
		out.ProviderFailovers = incoming.ProviderFailovers
	}
	if incoming.RiskScore > out.RiskScore {
		out.RiskScore = incoming.RiskScore
	}
	return out
}

func evaluateLoopBreach(state *loopRunState) (ReasonCode, map[string]any, bool) {
	if state == nil {
		return "", nil, false
	}
	if state.Limits.MaxSteps > 0 && state.Usage.Steps > state.Limits.MaxSteps {
		return ReasonLoopHaltMaxSteps, map[string]any{
			"limit_name": "max_steps",
			"limit":      state.Limits.MaxSteps,
			"usage":      state.Usage.Steps,
		}, true
	}
	if state.Limits.MaxToolCalls > 0 && state.Usage.ToolCalls > state.Limits.MaxToolCalls {
		return ReasonLoopHaltMaxToolCalls, map[string]any{
			"limit_name": "max_tool_calls",
			"limit":      state.Limits.MaxToolCalls,
			"usage":      state.Usage.ToolCalls,
		}, true
	}
	if state.Limits.MaxModelCalls > 0 && state.Usage.ModelCalls > state.Limits.MaxModelCalls {
		return ReasonLoopHaltMaxModelCalls, map[string]any{
			"limit_name": "max_model_calls",
			"limit":      state.Limits.MaxModelCalls,
			"usage":      state.Usage.ModelCalls,
		}, true
	}
	if state.Limits.MaxWallTimeMS > 0 && state.Usage.WallTimeMS > state.Limits.MaxWallTimeMS {
		return ReasonLoopHaltMaxWallTime, map[string]any{
			"limit_name": "max_wall_time_ms",
			"limit":      state.Limits.MaxWallTimeMS,
			"usage":      state.Usage.WallTimeMS,
		}, true
	}
	if state.Limits.MaxEgressBytes > 0 && state.Usage.EgressBytes > state.Limits.MaxEgressBytes {
		return ReasonLoopHaltMaxEgressBytes, map[string]any{
			"limit_name": "max_egress_bytes",
			"limit":      state.Limits.MaxEgressBytes,
			"usage":      state.Usage.EgressBytes,
		}, true
	}
	if state.Limits.MaxModelCostUSD > 0 && state.Usage.ModelCostUSD > state.Limits.MaxModelCostUSD {
		return ReasonLoopHaltMaxModelCost, map[string]any{
			"limit_name": "max_model_cost_usd",
			"limit":      state.Limits.MaxModelCostUSD,
			"usage":      state.Usage.ModelCostUSD,
		}, true
	}
	if state.Limits.MaxProviderFailovers > 0 && state.Usage.ProviderFailovers > state.Limits.MaxProviderFailovers {
		return ReasonLoopHaltMaxProviderFailovers, map[string]any{
			"limit_name": "max_provider_failovers",
			"limit":      state.Limits.MaxProviderFailovers,
			"usage":      state.Usage.ProviderFailovers,
		}, true
	}
	if state.Limits.MaxRiskScore > 0 && state.Usage.RiskScore > state.Limits.MaxRiskScore {
		return ReasonLoopHaltRiskScore, map[string]any{
			"limit_name": "max_risk_score",
			"limit":      state.Limits.MaxRiskScore,
			"usage":      state.Usage.RiskScore,
		}, true
	}
	return "", nil, false
}

func loopLimitsEqual(a, b loopLimitVector) bool {
	return a.MaxSteps == b.MaxSteps &&
		a.MaxToolCalls == b.MaxToolCalls &&
		a.MaxModelCalls == b.MaxModelCalls &&
		a.MaxWallTimeMS == b.MaxWallTimeMS &&
		a.MaxEgressBytes == b.MaxEgressBytes &&
		a.MaxModelCostUSD == b.MaxModelCostUSD &&
		a.MaxProviderFailovers == b.MaxProviderFailovers &&
		a.MaxRiskScore == b.MaxRiskScore
}

func (v loopLimitVector) toMap() map[string]any {
	return map[string]any{
		"max_steps":              v.MaxSteps,
		"max_tool_calls":         v.MaxToolCalls,
		"max_model_calls":        v.MaxModelCalls,
		"max_wall_time_ms":       v.MaxWallTimeMS,
		"max_egress_bytes":       v.MaxEgressBytes,
		"max_model_cost_usd":     v.MaxModelCostUSD,
		"max_provider_failovers": v.MaxProviderFailovers,
		"max_risk_score":         v.MaxRiskScore,
	}
}

func (v loopUsageVector) toMap() map[string]any {
	return map[string]any{
		"steps":              v.Steps,
		"tool_calls":         v.ToolCalls,
		"model_calls":        v.ModelCalls,
		"wall_time_ms":       v.WallTimeMS,
		"egress_bytes":       v.EgressBytes,
		"model_cost_usd":     v.ModelCostUSD,
		"provider_failovers": v.ProviderFailovers,
		"risk_score":         v.RiskScore,
	}
}

func getFloatAttr(attrs map[string]any, key string, fallback float64) float64 {
	raw, ok := attrs[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return fallback
		}
		return parsed
	default:
		return fallback
	}
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
		slog.Warn("phase3 tool plane: using built-in defaults, registry load failed", "error", err)
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
