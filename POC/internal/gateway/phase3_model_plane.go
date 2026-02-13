package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
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
	mu                       sync.Mutex
	providers                map[string]modelProviderPolicy
	providerEndpoints        map[string]string
	catalogVersion           string
	catalogDigest            string
	catalogSignatureVerified bool
	budgetProfile            map[string]modelBudgetProfile
	usage                    map[string]int
	enforceMediationGate     bool
	enforceHIPAAPromptSafety bool
}

func newModelPlanePolicyEngine() *modelPlanePolicyEngine {
	return newModelPlanePolicyEngineWithControls(true, true)
}

func newModelPlanePolicyEngineWithControls(enforceMediationGate, enforceHIPAAPromptSafety bool) *modelPlanePolicyEngine {
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
		providerEndpoints: map[string]string{
			"groq":         "https://api.groq.com/openai/v1/chat/completions",
			"openai":       "https://api.openai.com/v1/chat/completions",
			"azure_openai": "",
		},
		catalogVersion:           "builtin",
		catalogDigest:            "",
		catalogSignatureVerified: false,
		budgetProfile: map[string]modelBudgetProfile{
			"standard": {LimitUnits: 100, NearLimitFrom: 90},
			"tiny":     {LimitUnits: 2, NearLimitFrom: 2},
		},
		usage:                    make(map[string]int),
		enforceMediationGate:     enforceMediationGate,
		enforceHIPAAPromptSafety: enforceHIPAAPromptSafety,
	}
}

func (m *modelPlanePolicyEngine) evaluate(req PlaneRequestV2) (Decision, ReasonCode, int, map[string]any) {
	attrs := req.Policy.Attributes

	if attrs == nil {
		attrs = map[string]any{}
	}
	if m.enforceMediationGate && isBypassRequested(attrs) {
		return DecisionDeny, ReasonModelDirectEgressDeny, 403, map[string]any{"policy_gate": "direct_egress_blocked"}
	}

	provider := strings.ToLower(getStringAttr(attrs, "provider", "openai"))
	model := getStringAttr(attrs, "model", "gpt-4o")
	residency := strings.ToLower(getStringAttr(attrs, "residency_intent", "us"))
	riskMode := strings.ToLower(getStringAttr(attrs, "risk_mode", "low"))
	stepUpApproved := getBoolAttr(attrs, "step_up_approved", false)
	budgetProfile := strings.ToLower(getStringAttr(attrs, "budget_profile", "standard"))
	budgetUnits := getIntAttr(attrs, "budget_units", 1)
	enforcementProfile := strings.ToLower(getStringAttr(attrs, "enforcement_profile", ""))
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

	promptDecision, promptReason, promptStatus, promptMetadata, promptHandled := evaluatePromptSafety(attrs, m.enforceHIPAAPromptSafety)
	if promptHandled && promptDecision != DecisionAllow {
		if enforcementProfile != "" && promptMetadata != nil {
			promptMetadata["enforcement_profile"] = enforcementProfile
		}
		return promptDecision, promptReason, promptStatus, promptMetadata
	}

	nearLimit, exhausted := m.reserveBudget(req.Envelope.Tenant, budgetProfile, budgetUnits)
	if exhausted {
		metadata := map[string]any{
			"provider":       provider,
			"budget_profile": budgetProfile,
			"budget_units":   budgetUnits,
		}
		if enforcementProfile != "" {
			metadata["enforcement_profile"] = enforcementProfile
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
			if enforcementProfile != "" {
				metadata["enforcement_profile"] = enforcementProfile
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
		if enforcementProfile != "" {
			metadata["enforcement_profile"] = enforcementProfile
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
	for k, v := range m.catalogMetadata() {
		metadata[k] = v
	}
	if enforcementProfile != "" {
		metadata["enforcement_profile"] = enforcementProfile
	}
	if promptHandled {
		metadata["prompt_safety_reason"] = promptReason
		for k, v := range promptMetadata {
			metadata[k] = v
		}
	}
	return DecisionAllow, reason, 200, metadata
}

type modelProviderCatalogV2 struct {
	Version   string                         `yaml:"version"`
	Providers []modelProviderCatalogProvider `yaml:"providers"`
}

type modelProviderCatalogProvider struct {
	Name              string   `yaml:"name"`
	Endpoint          string   `yaml:"endpoint"`
	AllowedModels     []string `yaml:"allowed_models"`
	AllowedResidency  []string `yaml:"allowed_residency"`
	AllowHighRiskMode bool     `yaml:"allow_high_risk_mode"`
	FallbackProviders []string `yaml:"fallback_providers"`
}

func (m *modelPlanePolicyEngine) loadProviderCatalog(path string, publicKeyPath string) error {
	if m == nil {
		return nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	catalogBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read model provider catalog: %w", err)
	}
	signatureVerified := false
	if strings.TrimSpace(publicKeyPath) != "" {
		if err := verifyYAMLCatalogSignature(catalogBytes, path, publicKeyPath); err != nil {
			return fmt.Errorf("model provider catalog signature verification failed: %w", err)
		}
		signatureVerified = true
	}

	var catalog modelProviderCatalogV2
	if err := yaml.Unmarshal(catalogBytes, &catalog); err != nil {
		return fmt.Errorf("parse model provider catalog: %w", err)
	}
	if strings.TrimSpace(catalog.Version) == "" {
		return fmt.Errorf("model provider catalog missing version")
	}
	if len(catalog.Providers) == 0 {
		return fmt.Errorf("model provider catalog has no providers")
	}

	newProviders := make(map[string]modelProviderPolicy)
	newEndpoints := make(map[string]string)
	for _, p := range catalog.Providers {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if name == "" {
			continue
		}
		models := make(map[string]bool)
		for _, model := range p.AllowedModels {
			if v := strings.TrimSpace(model); v != "" {
				models[v] = true
			}
		}
		if len(models) == 0 {
			return fmt.Errorf("provider %s has empty allowed_models", name)
		}
		residency := make(map[string]bool)
		for _, intent := range p.AllowedResidency {
			if v := strings.ToLower(strings.TrimSpace(intent)); v != "" {
				residency[v] = true
			}
		}
		if len(residency) == 0 {
			return fmt.Errorf("provider %s has empty allowed_residency", name)
		}
		endpoint := strings.TrimSpace(p.Endpoint)
		if endpoint == "" {
			return fmt.Errorf("provider %s has empty endpoint", name)
		}
		newEndpoints[name] = endpoint
		newProviders[name] = modelProviderPolicy{
			AllowedModels:     models,
			AllowedResidency:  residency,
			AllowHighRiskMode: p.AllowHighRiskMode,
			FallbackProviders: p.FallbackProviders,
		}
	}
	if len(newProviders) == 0 {
		return fmt.Errorf("model provider catalog has no valid providers")
	}

	digest := sha256.Sum256(catalogBytes)
	m.mu.Lock()
	m.providers = newProviders
	m.providerEndpoints = newEndpoints
	m.catalogVersion = catalog.Version
	m.catalogDigest = hex.EncodeToString(digest[:])
	m.catalogSignatureVerified = signatureVerified
	m.mu.Unlock()
	return nil
}

func (m *modelPlanePolicyEngine) expectedProviderEndpoint(provider string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	endpoint, ok := m.providerEndpoints[strings.ToLower(strings.TrimSpace(provider))]
	return endpoint, ok
}

func (m *modelPlanePolicyEngine) catalogMetadata() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"provider_catalog_version":            m.catalogVersion,
		"provider_catalog_digest":             m.catalogDigest,
		"provider_catalog_signature_verified": m.catalogSignatureVerified,
	}
}

func verifyYAMLCatalogSignature(data []byte, catalogPath string, publicKeyPath string) error {
	pubPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return fmt.Errorf("decode PEM public key")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	edKey, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not Ed25519")
	}
	sigRaw, err := os.ReadFile(catalogPath + ".sig")
	if err != nil {
		return fmt.Errorf("read signature file: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(edKey, data, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
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
