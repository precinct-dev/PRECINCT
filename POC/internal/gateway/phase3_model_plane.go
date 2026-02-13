package gateway

import (
	"strconv"
	"strings"
	"sync"
)

type modelProviderPolicy struct {
	AllowedModels     map[string]bool
	AllowedResidency  map[string]bool
	AllowHighRiskMode bool
	FallbackProviders []string
}

type modelBudgetProfile struct {
	LimitUnits    int
	NearLimitFrom int
}

type modelPlanePolicyEngine struct {
	mu            sync.Mutex
	providers     map[string]modelProviderPolicy
	budgetProfile map[string]modelBudgetProfile
	usage         map[string]int
}

func newModelPlanePolicyEngine() *modelPlanePolicyEngine {
	return &modelPlanePolicyEngine{
		providers: map[string]modelProviderPolicy{
			"groq": {
				AllowedModels: map[string]bool{
					"llama-3.3-70b-versatile": true,
					"llama-3.1-8b-instant":    true,
				},
				AllowedResidency: map[string]bool{
					"us": true,
				},
				AllowHighRiskMode: false,
				FallbackProviders: []string{"openai"},
			},
			"openai": {
				AllowedModels: map[string]bool{
					"gpt-4o":      true,
					"gpt-4o-mini": true,
				},
				AllowedResidency: map[string]bool{
					"us": true,
					"eu": true,
				},
				AllowHighRiskMode: false,
				FallbackProviders: []string{"azure_openai"},
			},
			"azure_openai": {
				AllowedModels: map[string]bool{
					"gpt-4o":      true,
					"gpt-4o-mini": true,
				},
				AllowedResidency: map[string]bool{
					"us": true,
					"eu": true,
				},
				AllowHighRiskMode: false,
			},
			"anthropic": {
				AllowedModels: map[string]bool{
					"claude-3-5-sonnet": true,
				},
				AllowedResidency: map[string]bool{
					"us": true,
				},
				AllowHighRiskMode: false,
			},
		},
		budgetProfile: map[string]modelBudgetProfile{
			"standard": {LimitUnits: 100, NearLimitFrom: 90},
			"tiny":     {LimitUnits: 2, NearLimitFrom: 2},
		},
		usage: make(map[string]int),
	}
}

func (m *modelPlanePolicyEngine) evaluate(req PlaneRequestV2) (Decision, ReasonCode, int, map[string]any) {
	attrs := req.Policy.Attributes

	if attrs == nil {
		attrs = map[string]any{}
	}
	if isBypassRequested(attrs) {
		return DecisionDeny, ReasonModelDirectEgressDeny, 403, map[string]any{"policy_gate": "direct_egress_blocked"}
	}

	provider := strings.ToLower(getStringAttr(attrs, "provider", "openai"))
	model := getStringAttr(attrs, "model", "gpt-4o")
	residency := strings.ToLower(getStringAttr(attrs, "residency_intent", "us"))
	riskMode := strings.ToLower(getStringAttr(attrs, "risk_mode", "low"))
	stepUpApproved := getBoolAttr(attrs, "step_up_approved", false)
	budgetProfile := strings.ToLower(getStringAttr(attrs, "budget_profile", "standard"))
	budgetUnits := getIntAttr(attrs, "budget_units", 1)
	if budgetUnits < 1 {
		budgetUnits = 1
	}

	policy, ok := m.providers[provider]
	if !ok || !policy.AllowedModels[model] {
		return DecisionDeny, ReasonModelProviderDenied, 403, map[string]any{"provider": provider, "model": model}
	}
	if !policy.AllowedResidency[residency] {
		return DecisionDeny, ReasonModelResidencyDenied, 403, map[string]any{"provider": provider, "residency_intent": residency}
	}
	if riskMode == "high" && !policy.AllowHighRiskMode && !stepUpApproved {
		return DecisionDeny, ReasonModelRiskModeDenied, 403, map[string]any{
			"provider":          provider,
			"risk_mode":         riskMode,
			"approval_required": true,
		}
	}

	promptDecision, promptReason, promptStatus, promptMetadata, promptHandled := evaluatePromptSafety(attrs)
	if promptHandled && promptDecision != DecisionAllow {
		return promptDecision, promptReason, promptStatus, promptMetadata
	}

	nearLimit, exhausted := m.reserveBudget(req.Envelope.Tenant, budgetProfile, budgetUnits)
	if exhausted {
		metadata := map[string]any{
			"provider":       provider,
			"budget_profile": budgetProfile,
			"budget_units":   budgetUnits,
		}
		if promptHandled {
			metadata["prompt_safety_reason"] = promptReason
			for k, v := range promptMetadata {
				metadata[k] = v
			}
		}
		return DecisionDeny, ReasonModelBudgetExhausted, 429, metadata
	}

	simulateProviderError := getBoolAttr(attrs, "simulate_provider_error", false) || getIntAttr(attrs, "simulate_provider_status", 200) >= 500
	if simulateProviderError {
		fallbackProvider, ok := m.selectFallback(provider, model, residency, riskMode)
		if !ok {
			metadata := map[string]any{
				"provider":       provider,
				"model":          model,
				"residency":      residency,
				"budget_profile": budgetProfile,
			}
			if promptHandled {
				metadata["prompt_safety_reason"] = promptReason
				for k, v := range promptMetadata {
					metadata[k] = v
				}
			}
			return DecisionDeny, ReasonModelNoFallback, 502, metadata
		}
		metadata := map[string]any{
			"provider_original": provider,
			"provider_used":     fallbackProvider,
			"model":             model,
			"residency":         residency,
			"budget_profile":    budgetProfile,
		}
		if promptHandled {
			metadata["prompt_safety_reason"] = promptReason
			for k, v := range promptMetadata {
				metadata[k] = v
			}
		}
		return DecisionAllow, ReasonModelFallbackApplied, 200, metadata
	}

	reason := ReasonModelAllow
	if promptHandled && promptReason != "" {
		reason = promptReason
	} else if nearLimit {
		reason = ReasonModelBudgetNearLimit
	}
	metadata := map[string]any{
		"provider":         provider,
		"model":            model,
		"residency":        residency,
		"risk_mode":        riskMode,
		"step_up_approved": stepUpApproved,
		"budget_profile":   budgetProfile,
	}
	if promptHandled {
		metadata["prompt_safety_reason"] = promptReason
		for k, v := range promptMetadata {
			metadata[k] = v
		}
	}
	return DecisionAllow, reason, 200, metadata
}

func (m *modelPlanePolicyEngine) reserveBudget(tenant, profile string, units int) (nearLimit bool, exhausted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.budgetProfile[profile]
	if !ok {
		b = m.budgetProfile["standard"]
	}

	key := tenant + "|" + profile
	next := m.usage[key] + units
	if next > b.LimitUnits {
		return false, true
	}
	m.usage[key] = next
	return next >= b.NearLimitFrom, false
}

func (m *modelPlanePolicyEngine) selectFallback(provider, model, residency, riskMode string) (string, bool) {
	primary, ok := m.providers[provider]
	if !ok {
		return "", false
	}
	for _, candidate := range primary.FallbackProviders {
		cp, ok := m.providers[candidate]
		if !ok {
			continue
		}
		if !cp.AllowedModels[model] || !cp.AllowedResidency[residency] {
			continue
		}
		if riskMode == "high" && !cp.AllowHighRiskMode {
			continue
		}
		return candidate, true
	}
	return "", false
}

func isBypassRequested(attrs map[string]any) bool {
	if getBoolAttr(attrs, "direct_egress", false) {
		return true
	}
	mode := strings.ToLower(getStringAttr(attrs, "mediation_mode", "mediated"))
	return mode == "direct" || mode == "bypass"
}

func getStringAttr(attrs map[string]any, key, fallback string) string {
	raw, ok := attrs[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return fallback
		}
		return trimmed
	default:
		return fallback
	}
}

func getBoolAttr(attrs map[string]any, key string, fallback bool) bool {
	raw, ok := attrs[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fallback
		}
		return parsed
	default:
		return fallback
	}
}

func getIntAttr(attrs map[string]any, key string, fallback int) int {
	raw, ok := attrs[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fallback
		}
		return parsed
	default:
		return fallback
	}
}
