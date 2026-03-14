package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/redis/go-redis/v9"
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
	budgetClient             *redis.Client
	budgetTTL                time.Duration
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
		budgetTTL:                24 * time.Hour,
		enforceMediationGate:     enforceMediationGate,
		enforceHIPAAPromptSafety: enforceHIPAAPromptSafety,
	}
}

func (m *modelPlanePolicyEngine) enableDistributedBudgetStore(client *redis.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.budgetClient = client
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

	missionDecision, missionReason, missionStatus, missionMetadata, missionHandled := evaluateMissionBoundary(attrs)
	if missionHandled && missionDecision != DecisionAllow {
		if enforcementProfile != "" && missionMetadata != nil {
			missionMetadata["enforcement_profile"] = enforcementProfile
		}
		return missionDecision, missionReason, missionStatus, missionMetadata
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
		if missionHandled {
			metadata["mission_boundary_reason"] = missionReason
			for k, v := range missionMetadata {
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
			if missionHandled {
				metadata["mission_boundary_reason"] = missionReason
				for k, v := range missionMetadata {
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
		if missionHandled {
			metadata["mission_boundary_reason"] = missionReason
			for k, v := range missionMetadata {
				metadata[k] = v
			}
		}
		return DecisionAllow, ReasonModelFallbackApplied, 200, metadata
	}

	reason := ReasonModelAllow
	if promptHandled && promptReason != "" {
		reason = promptReason
	} else if missionHandled && missionReason != "" {
		reason = missionReason
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
	if missionHandled {
		metadata["mission_boundary_reason"] = missionReason
		for k, v := range missionMetadata {
			metadata[k] = v
		}
	}
	return DecisionAllow, reason, 200, metadata
}

func evaluateMissionBoundary(attrs map[string]any) (Decision, ReasonCode, int, map[string]any, bool) {
	if attrs == nil {
		attrs = map[string]any{}
	}

	mode := strings.ToLower(getStringAttr(attrs, "mission_boundary_mode", ""))
	purpose := getStringAttr(attrs, "agent_purpose", "")
	allowedIntents := getStringListAttr(attrs, "allowed_intents")
	allowedTopics := getStringListAttr(attrs, "allowed_topics")
	blockedTopics := getStringListAttr(attrs, "blocked_topics")
	if mode == "" && purpose == "" && len(allowedIntents) == 0 && len(allowedTopics) == 0 && len(blockedTopics) == 0 {
		return DecisionAllow, "", 0, nil, false
	}
	if mode == "" {
		mode = "enforce"
	}

	allowedTerms := append([]string{}, allowedIntents...)
	allowedTerms = append(allowedTerms, allowedTopics...)
	prompt := getStringAttr(attrs, "prompt", "")
	matchedAllowed := missionBoundaryMatches(prompt, allowedTerms)
	matchedBlocked := missionBoundaryMatches(prompt, blockedTopics)
	inScope := strings.TrimSpace(prompt) == "" || len(matchedBlocked) == 0
	if inScope && strings.TrimSpace(prompt) != "" && len(allowedTerms) > 0 {
		inScope = len(matchedAllowed) > 0
	}

	meta := map[string]any{
		"mission_boundary_enforced": true,
		"mission_boundary_mode":     mode,
		"agent_purpose":             purpose,
		"allowed_intents":           allowedIntents,
		"allowed_topics":            allowedTopics,
		"blocked_topics":            blockedTopics,
		"matched_allowed_terms":     matchedAllowed,
		"matched_blocked_terms":     matchedBlocked,
	}
	if inScope {
		meta["mission_boundary_verdict"] = "in_scope"
		return DecisionAllow, ReasonModelAllow, http.StatusOK, meta, true
	}

	action := normalizeMissionOutOfScopeAction(getStringAttr(attrs, "out_of_scope_action", "deny"))
	meta["mission_boundary_verdict"] = "out_of_scope"
	meta["out_of_scope_action"] = action
	if mode == "advisory" || mode == "monitor" {
		meta["mission_boundary_enforced"] = false
		return DecisionAllow, ReasonModelAllow, http.StatusOK, meta, true
	}

	if action == "rewrite" || action == "handoff" {
		meta["synthetic_assistant_response"] = buildMissionBoundaryFallbackResponse(
			purpose,
			allowedIntents,
			action,
			getStringAttr(attrs, "out_of_scope_message", ""),
		)
		return DecisionDeny, ReasonModelMissionScopeFallback, http.StatusForbidden, meta, true
	}

	return DecisionDeny, ReasonModelMissionScopeDenied, http.StatusForbidden, meta, true
}

func missionBoundaryMatches(prompt string, terms []string) []string {
	normalizedPrompt := normalizeMissionBoundaryText(prompt)
	if normalizedPrompt == "" || len(terms) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	matches := make([]string, 0, len(terms))
	for _, term := range terms {
		normalizedTerm := normalizeMissionBoundaryText(term)
		if normalizedTerm == "" {
			continue
		}
		if _, ok := seen[normalizedTerm]; ok {
			continue
		}
		if strings.Contains(normalizedPrompt, normalizedTerm) {
			seen[normalizedTerm] = struct{}{}
			matches = append(matches, normalizedTerm)
		}
	}
	return matches
}

func normalizeMissionBoundaryText(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	lastSpace := true
	for _, ch := range raw {
		switch {
		case unicode.IsLetter(ch) || unicode.IsDigit(ch):
			b.WriteRune(ch)
			lastSpace = false
		case !lastSpace:
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

func normalizeMissionOutOfScopeAction(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "rewrite", "handoff":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "deny"
	}
}

func buildMissionBoundaryFallbackResponse(purpose string, allowedIntents []string, action string, override string) string {
	override = strings.TrimSpace(override)
	if override != "" {
		if len(override) > 280 {
			override = override[:280]
		}
		return override
	}

	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		purpose = "this assistant's assigned task"
	}
	if len(allowedIntents) > 0 {
		joined := strings.Join(limitMissionIntentList(humanizeMissionIntents(allowedIntents), 4), ", ")
		if action == "handoff" {
			return fmt.Sprintf("I can only help with %s. Please ask about %s, or contact a human agent for anything outside that scope.", purpose, joined)
		}
		return fmt.Sprintf("I can only help with %s. Please ask about %s.", purpose, joined)
	}
	if action == "handoff" {
		return fmt.Sprintf("I can only help with %s. Please contact a human agent for anything outside that scope.", purpose)
	}
	return fmt.Sprintf("I can only help with %s. Please ask a request within that scope.", purpose)
}

func limitMissionIntentList(intents []string, max int) []string {
	if len(intents) <= max {
		return intents
	}
	return intents[:max]
}

func humanizeMissionIntents(intents []string) []string {
	out := make([]string, 0, len(intents))
	for _, intent := range intents {
		out = append(out, strings.ReplaceAll(intent, "_", " "))
	}
	return out
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
	if m.budgetClient != nil {
		near, ex, err := m.reserveBudgetDistributed(tenant, profile, units)
		if err != nil {
			// Fail closed on distributed-state failure in strict/prod posture.
			return false, true
		}
		return near, ex
	}

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

func (m *modelPlanePolicyEngine) reserveBudgetDistributed(tenant, profile string, units int) (nearLimit bool, exhausted bool, err error) {
	m.mu.Lock()
	b, ok := m.budgetProfile[profile]
	if !ok {
		b = m.budgetProfile["standard"]
	}
	client := m.budgetClient
	ttl := m.budgetTTL
	m.mu.Unlock()

	if client == nil {
		return false, true, fmt.Errorf("model budget store unavailable")
	}
	key := "modelbudget:" + tenant + "|" + profile
	res, err := modelBudgetReserveLua.Run(context.Background(), client, []string{key},
		units,
		b.LimitUnits,
		b.NearLimitFrom,
		int(ttl.Seconds()),
	).Result()
	if err != nil {
		return false, true, fmt.Errorf("distributed model budget reserve failed: %w", err)
	}
	values, ok := res.([]interface{})
	if !ok || len(values) != 2 {
		return false, true, fmt.Errorf("unexpected budget reserve response type %T", res)
	}
	exhaustedFlag, okExhausted := values[0].(int64)
	nearFlag, okNear := values[1].(int64)
	if !okExhausted || !okNear {
		return false, true, fmt.Errorf("unexpected budget reserve values %T/%T", values[0], values[1])
	}
	return nearFlag == 1, exhaustedFlag == 1, nil
}

var modelBudgetReserveLua = redis.NewScript(`
-- KEYS[1] = budget key
-- ARGV[1] = units
-- ARGV[2] = limit
-- ARGV[3] = near_limit_from
-- ARGV[4] = ttl_seconds

local key = KEYS[1]
local units = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local near_from = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local current = tonumber(redis.call("GET", key) or "0")
local next = current + units

if next > limit then
  return {1, 0}
end

redis.call("SET", key, tostring(next))
if ttl > 0 then
  redis.call("EXPIRE", key, ttl)
end

if next >= near_from then
  return {0, 1}
end
return {0, 0}
`)

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

func getStringListAttr(attrs map[string]any, key string) []string {
	raw, ok := attrs[key]
	if !ok {
		return nil
	}
	values := make([]string, 0)
	appendValue := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		values = append(values, v)
	}
	switch v := raw.(type) {
	case string:
		for _, part := range strings.Split(v, ",") {
			appendValue(part)
		}
	case []string:
		for _, part := range v {
			appendValue(part)
		}
	case []any:
		for _, item := range v {
			appendValue(stringValue(item))
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}
