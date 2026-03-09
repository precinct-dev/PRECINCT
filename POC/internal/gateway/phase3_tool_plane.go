package gateway

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type toolExecutionInput struct {
	Protocol     string
	CapabilityID string
	WorkloadID   string
	ToolName     string
	Command      string
	Args         []string
}

type capabilityRegistryV2 struct {
	CapabilityGrants []capabilityGrantV2 `yaml:"capability_grants"`
}

type capabilityGrantV2 struct {
	ID               string   `yaml:"id"`
	Tenant           string   `yaml:"tenant"`
	Workload         string   `yaml:"workload"`
	Protocol         string   `yaml:"protocol"`
	CapabilityType   string   `yaml:"capability_type"`
	CapabilityID     string   `yaml:"capability_id"`
	EffectType       string   `yaml:"effect_type"`
	RiskLevel        string   `yaml:"risk_level"`
	RequiresStepUp   bool     `yaml:"requires_step_up"`
	AllowedActions   []string `yaml:"allowed_actions"`
	AllowedResources []string `yaml:"allowed_resources"`
	AllowedTools     []string `yaml:"allowed_tools"`
	AllowedCommands  []string `yaml:"allowed_commands"`
	MaxArgs          int      `yaml:"max_args"`
	DeniedArgTokens  []string `yaml:"denied_arg_tokens"`
}

type toolPlanePolicyEngine struct {
	mu       sync.RWMutex
	registry capabilityRegistryV2
}

func newToolPlanePolicyEngine(registryPath string) *toolPlanePolicyEngine {
	registry := defaultCapabilityRegistryV2()
	if loaded, ok := loadCapabilityRegistryV2(registryPath); ok {
		registry = loaded
	}
	normalizeCapabilityRegistry(&registry)
	return &toolPlanePolicyEngine{
		registry: registry,
	}
}

func (p *toolPlanePolicyEngine) evaluate(req PlaneRequestV2) (Decision, ReasonCode, int, map[string]any) {
	input, err := parseToolExecutionInput(req.Envelope, req.Policy.Attributes)
	if err != nil {
		return DecisionDeny, ReasonToolSchemaInvalid, 400, map[string]any{
			"schema_error": err.Error(),
		}
	}

	grant, ok := p.resolveGrant(req, input)
	if !ok {
		return DecisionDeny, ReasonToolCapabilityDenied, 403, map[string]any{
			"tenant":        req.Envelope.Tenant,
			"workload_id":   input.WorkloadID,
			"protocol":      input.Protocol,
			"capability_id": input.CapabilityID,
			"action":        req.Policy.Action,
			"resource":      req.Policy.Resource,
		}
	}

	if grant.RequiresStepUp {
		return DecisionStepUp, ReasonToolStepUpRequired, 202, toolDecisionMetadata(grant, req, input)
	}

	switch input.Protocol {
	case "mcp":
		if !valueAllowed(input.ToolName, grant.AllowedTools) {
			metadata := toolDecisionMetadata(grant, req, input)
			metadata["tool_name"] = input.ToolName
			return DecisionDeny, ReasonToolActionDenied, 403, metadata
		}
		metadata := toolDecisionMetadata(grant, req, input)
		metadata["tool_name"] = input.ToolName
		metadata["execution_mode"] = "policy_mediated"
		return DecisionAllow, ReasonToolAllow, 200, metadata
	case "cli":
		if !valueAllowed(input.Command, grant.AllowedCommands) {
			metadata := toolDecisionMetadata(grant, req, input)
			metadata["command"] = input.Command
			return DecisionDeny, ReasonToolCLICommandDenied, 403, metadata
		}
		if grant.MaxArgs > 0 && len(input.Args) > grant.MaxArgs {
			metadata := toolDecisionMetadata(grant, req, input)
			metadata["command"] = input.Command
			metadata["args_count"] = len(input.Args)
			return DecisionDeny, ReasonToolCLIArgsDenied, 403, metadata
		}
		if hasDeniedCLIArgToken(input.Args, grant.DeniedArgTokens) {
			metadata := toolDecisionMetadata(grant, req, input)
			metadata["command"] = input.Command
			return DecisionDeny, ReasonToolCLIArgsDenied, 403, metadata
		}
		metadata := toolDecisionMetadata(grant, req, input)
		metadata["command"] = input.Command
		metadata["args_count"] = len(input.Args)
		metadata["execution_mode"] = "policy_mediated"
		return DecisionAllow, ReasonToolAllow, 200, metadata
	default:
		return DecisionDeny, ReasonToolAdapterUnsupported, 400, map[string]any{
			"protocol": input.Protocol,
		}
	}
}

func (p *toolPlanePolicyEngine) resolveGrant(req PlaneRequestV2, input toolExecutionInput) (capabilityGrantV2, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, grant := range p.registry.CapabilityGrants {
		if !matchesScopedValue(req.Envelope.Tenant, grant.Tenant) {
			continue
		}
		if !matchesScopedValue(input.WorkloadID, grant.Workload) {
			continue
		}
		if !matchesScopedValue(input.Protocol, grant.Protocol) {
			continue
		}
		if !matchesScopedValue(input.CapabilityID, grant.CapabilityID) {
			continue
		}
		if !valueAllowed(req.Policy.Action, grant.AllowedActions) {
			continue
		}
		if !valueAllowed(req.Policy.Resource, grant.AllowedResources) {
			continue
		}
		return grant, true
	}
	return capabilityGrantV2{}, false
}

func parseToolExecutionInput(envelope RunEnvelope, attrs map[string]any) (toolExecutionInput, error) {
	if attrs == nil {
		return toolExecutionInput{}, fmt.Errorf("attributes are required")
	}

	protocol := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "protocol", "")))
	if protocol == "" {
		return toolExecutionInput{}, fmt.Errorf("protocol is required")
	}
	switch protocol {
	case "mcp", "cli":
	default:
		return toolExecutionInput{}, fmt.Errorf("protocol must be one of mcp/cli")
	}

	workloadID := strings.TrimSpace(getStringAttr(attrs, "workload_id", ""))
	if workloadID == "" {
		workloadID = inferWorkloadIDFromSPIFFE(envelope.ActorSPIFFEID)
	}
	if workloadID == "" {
		return toolExecutionInput{}, fmt.Errorf("workload_id could not be inferred")
	}

	capabilityID := strings.TrimSpace(getStringAttr(attrs, "capability_id", "tool.default"))
	input := toolExecutionInput{
		Protocol:     protocol,
		CapabilityID: capabilityID,
		WorkloadID:   workloadID,
	}

	switch protocol {
	case "mcp":
		toolName := strings.TrimSpace(getStringAttr(attrs, "tool_name", ""))
		if toolName == "" {
			return toolExecutionInput{}, fmt.Errorf("tool_name is required for mcp protocol")
		}
		input.ToolName = strings.ToLower(toolName)
	case "cli":
		command := strings.TrimSpace(getStringAttr(attrs, "command", ""))
		if command == "" {
			return toolExecutionInput{}, fmt.Errorf("command is required for cli protocol")
		}
		if strings.Contains(command, " ") {
			return toolExecutionInput{}, fmt.Errorf("command must be a single token")
		}
		input.Command = strings.ToLower(command)
		input.Args = parseStringSlice(attrs["args"])
	}

	return input, nil
}

func inferWorkloadIDFromSPIFFE(spiffeID string) string {
	trimmed := strings.TrimSpace(spiffeID)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return ""
	}
	last := strings.TrimSpace(parts[len(parts)-1])
	if last == "" {
		return ""
	}
	if last == "dev" || last == "prod" || last == "staging" {
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[len(parts)-2])
		}
	}
	return last
}

func parseStringSlice(raw any) []string {
	switch v := raw.(type) {
	case nil:
		return nil
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			trimmed := strings.TrimSpace(item)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			trimmed := strings.TrimSpace(fmt.Sprintf("%v", item))
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	default:
		trimmed := strings.TrimSpace(fmt.Sprintf("%v", raw))
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	}
}

func matchesScopedValue(value, scope string) bool {
	if strings.TrimSpace(scope) == "" || scope == "*" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(scope))
}

func valueAllowed(value string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range allowed {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		switch {
		case candidate == "*":
			return true
		case candidate == normalizedValue:
			return true
		case strings.HasSuffix(candidate, "*"):
			prefix := strings.TrimSuffix(candidate, "*")
			if strings.HasPrefix(normalizedValue, prefix) {
				return true
			}
		}
	}
	return false
}

func hasDeniedCLIArgToken(args, deniedTokens []string) bool {
	tokens := deniedTokens
	if len(tokens) == 0 {
		tokens = []string{";", "&&", "||", "|", "$(", "`", ">", "<"}
	}
	for _, arg := range args {
		for _, token := range tokens {
			if token == "" {
				continue
			}
			if strings.Contains(arg, token) {
				return true
			}
		}
	}
	return false
}

func toolDecisionMetadata(grant capabilityGrantV2, req PlaneRequestV2, input toolExecutionInput) map[string]any {
	return map[string]any{
		"adapter_protocol":   input.Protocol,
		"capability_grant":   grant.ID,
		"capability_type":    grant.CapabilityType,
		"capability_id":      grant.CapabilityID,
		"effect_type":        grant.EffectType,
		"risk_level":         grant.RiskLevel,
		"tenant":             req.Envelope.Tenant,
		"workload_id":        input.WorkloadID,
		"policy_path":        "shared_tool_plane_policy_v2",
		"tenant_scope_match": true,
	}
}

func defaultCapabilityRegistryV2() capabilityRegistryV2 {
	return capabilityRegistryV2{
		CapabilityGrants: []capabilityGrantV2{
			{
				ID:               "tenant-a-mcp-tools",
				Tenant:           "tenant-a",
				Workload:         "dspy-researcher",
				Protocol:         "mcp",
				CapabilityType:   "tool",
				CapabilityID:     "tool.default.mcp",
				EffectType:       "read",
				RiskLevel:        "low",
				AllowedActions:   []string{"tool.execute"},
				AllowedResources: []string{"tool/*"},
				AllowedTools:     []string{"read", "grep", "bash"},
			},
			{
				ID:               "tenant-a-cli-tools",
				Tenant:           "tenant-a",
				Workload:         "dspy-researcher",
				Protocol:         "cli",
				CapabilityType:   "tool",
				CapabilityID:     "tool.default.cli",
				EffectType:       "read",
				RiskLevel:        "medium",
				AllowedActions:   []string{"tool.execute"},
				AllowedResources: []string{"tool/cli/*"},
				AllowedCommands:  []string{"ls", "echo", "cat", "grep"},
				MaxArgs:          6,
				DeniedArgTokens:  []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
			},
		},
	}
}

func loadCapabilityRegistryV2(path string) (capabilityRegistryV2, bool) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return capabilityRegistryV2{}, false
	}
	data, err := os.ReadFile(trimmed)
	if err != nil {
		log.Printf("[WARN] failed to read capability registry v2 %s: %v (using defaults)", trimmed, err)
		return capabilityRegistryV2{}, false
	}
	var registry capabilityRegistryV2
	if err := yaml.Unmarshal(data, &registry); err != nil {
		log.Printf("[WARN] failed to parse capability registry v2 %s: %v (using defaults)", trimmed, err)
		return capabilityRegistryV2{}, false
	}
	if len(registry.CapabilityGrants) == 0 {
		log.Printf("[WARN] capability registry v2 %s has no grants (using defaults)", trimmed)
		return capabilityRegistryV2{}, false
	}
	return registry, true
}

func normalizeCapabilityRegistry(registry *capabilityRegistryV2) {
	for i := range registry.CapabilityGrants {
		grant := &registry.CapabilityGrants[i]
		grant.ID = strings.TrimSpace(grant.ID)
		if grant.ID == "" {
			grant.ID = fmt.Sprintf("grant-%d", i+1)
		}
		grant.Tenant = strings.ToLower(strings.TrimSpace(grant.Tenant))
		grant.Workload = strings.ToLower(strings.TrimSpace(grant.Workload))
		grant.Protocol = strings.ToLower(strings.TrimSpace(grant.Protocol))
		grant.CapabilityType = strings.ToLower(strings.TrimSpace(grant.CapabilityType))
		grant.CapabilityID = strings.ToLower(strings.TrimSpace(grant.CapabilityID))
		grant.EffectType = strings.ToLower(strings.TrimSpace(grant.EffectType))
		grant.RiskLevel = strings.ToLower(strings.TrimSpace(grant.RiskLevel))
		grant.AllowedActions = normalizeStringSlice(grant.AllowedActions)
		grant.AllowedResources = normalizeStringSlice(grant.AllowedResources)
		grant.AllowedTools = normalizeStringSlice(grant.AllowedTools)
		grant.AllowedCommands = normalizeStringSlice(grant.AllowedCommands)
		grant.DeniedArgTokens = normalizeStringSlice(grant.DeniedArgTokens)
	}
}

func normalizeStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.ToLower(strings.TrimSpace(item))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
