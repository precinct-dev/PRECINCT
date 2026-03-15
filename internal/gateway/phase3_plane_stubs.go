package gateway

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	ID              string                  `yaml:"id"`
	Kind            string                  `yaml:"kind"`
	Protocol        string                  `yaml:"protocol"`
	Server          string                  `yaml:"server"`
	Allowlist       []string                `yaml:"allowlist"`
	Adapters        []string                `yaml:"adapters"`
	ActionPolicies  []toolActionPolicyEntry `yaml:"action_policies"`
	AllowedCommands []string                `yaml:"allowed_commands"`
	MaxArgs         int                     `yaml:"max_args"`
	DeniedArgTokens []string                `yaml:"denied_arg_tokens"`
}

type toolActionPolicyEntry struct {
	Action        string   `yaml:"action"`
	Resources     []string `yaml:"resources"`
	AllowedTools  []string `yaml:"allowed_tools"`
	RequireStepUp bool     `yaml:"require_step_up"`
}

type toolCapabilityRule struct {
	CapabilityID    string
	Protocol        string
	Adapters        map[string]struct{}
	AllowTools      map[string]struct{}
	Actions         []toolActionRule
	AllowedCommands map[string]struct{}
	MaxArgs         int
	DeniedArgTokens []string
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

		allowedCommands := make(map[string]struct{})
		for _, cmd := range entry.AllowedCommands {
			if v := strings.ToLower(strings.TrimSpace(cmd)); v != "" {
				allowedCommands[v] = struct{}{}
			}
		}

		deniedArgTokens := make([]string, 0, len(entry.DeniedArgTokens))
		for _, tok := range entry.DeniedArgTokens {
			if tok != "" {
				deniedArgTokens = append(deniedArgTokens, tok)
			}
		}

		rules[capabilityID] = toolCapabilityRule{
			CapabilityID:    capabilityID,
			Protocol:        protocol,
			Adapters:        adapterSet,
			AllowTools:      allowTools,
			Actions:         actionRules,
			AllowedCommands: allowedCommands,
			MaxArgs:         entry.MaxArgs,
			DeniedArgTokens: deniedArgTokens,
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
			AllowedCommands: map[string]struct{}{
				"ls":   {},
				"echo": {},
				"cat":  {},
				"grep": {},
			},
			MaxArgs:         10,
			DeniedArgTokens: []string{";", "&&", "||", "|", "$(", "`", ">", "<"},
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
		"tool.messaging.http": {
			CapabilityID: "tool.messaging.http",
			Protocol:     "http",
			Adapters: map[string]struct{}{
				"http": {},
			},
			AllowTools: map[string]struct{}{
				"messaging_send":   {},
				"messaging_status": {},
			},
			Actions: []toolActionRule{
				{
					Action: "tool.invoke",
					Resources: map[string]struct{}{
						"messaging_send":   {},
						"messaging_status": {},
					},
					AllowedTools: map[string]struct{}{
						"messaging_send":   {},
						"messaging_status": {},
					},
				},
			},
		},
		// OC-di1n: Email channel mediation capability.
		"tool.messaging.email": {
			CapabilityID: "tool.messaging.email",
			Protocol:     "email",
			Adapters: map[string]struct{}{
				"email": {},
			},
			AllowTools: map[string]struct{}{
				"messaging_send":   {},
				"messaging_status": {},
			},
			Actions: []toolActionRule{
				{
					Action: "tool.invoke",
					Resources: map[string]struct{}{
						"messaging_send":   {},
						"messaging_status": {},
					},
					AllowedTools: map[string]struct{}{
						"messaging_send":   {},
						"messaging_status": {},
					},
				},
			},
		},
		// OC-di1n: Discord channel mediation capability.
		"tool.messaging.discord": {
			CapabilityID: "tool.messaging.discord",
			Protocol:     "discord",
			Adapters: map[string]struct{}{
				"discord": {},
			},
			AllowTools: map[string]struct{}{
				"messaging_send":  {},
				"discord_command": {},
			},
			Actions: []toolActionRule{
				{
					Action:    "messaging_send",
					Resources: map[string]struct{}{},
					AllowedTools: map[string]struct{}{
						"messaging_send": {},
					},
				},
				{
					Action:    "discord_command",
					Resources: map[string]struct{}{},
					AllowedTools: map[string]struct{}{
						"discord_command": {},
					},
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

	// CLI protocol adapter: enforce command allowlist, arg count, denied tokens,
	// and reject nested shell interpreters that would bypass mediation.
	if adapter == "cli" {
		command := strings.TrimSpace(getStringAttr(attrs, "command", ""))
		if command == "" {
			resultMetadata["cli_error"] = "command is required for cli protocol"
			return deny(ReasonToolSchemaInvalid, resultMetadata)
		}
		if strings.Contains(command, " ") {
			resultMetadata["cli_error"] = "command must be a single token (no spaces)"
			resultMetadata["command"] = command
			return deny(ReasonToolSchemaInvalid, resultMetadata)
		}
		command = strings.ToLower(command)
		resultMetadata["command"] = command

		args := parseStringSlice(attrs["args"])
		resultMetadata["args_count"] = len(args)

		if isDeniedCLIInterpreterCommand(command) {
			resultMetadata["cli_error"] = "nested shell interpreter commands are not permitted"
			return deny(ReasonToolCLICommandDenied, resultMetadata)
		}

		if len(rule.AllowedCommands) > 0 {
			if _, allowed := rule.AllowedCommands[command]; !allowed {
				resultMetadata["allowed_commands"] = sortedStringSet(rule.AllowedCommands)
				return deny(ReasonToolCLICommandDenied, resultMetadata)
			}
		}

		if rule.MaxArgs > 0 && len(args) > rule.MaxArgs {
			resultMetadata["max_args"] = rule.MaxArgs
			return deny(ReasonToolCLIArgsDenied, resultMetadata)
		}

		if hasDeniedCLIArgToken(args, rule.DeniedArgTokens) {
			resultMetadata["denied_arg_tokens"] = rule.DeniedArgTokens
			return deny(ReasonToolCLIArgsDenied, resultMetadata)
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

// hasDeniedCLIArgToken scans CLI arguments for denied shell-injection tokens.
// If deniedTokens is empty, the default set is used: ; && || | $( ` > <
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

func isDeniedCLIInterpreterCommand(command string) bool {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "ash", "bash", "dash", "ksh", "sh", "zsh":
		return true
	default:
		return false
	}
}

// parseStringSlice coerces a raw attribute value into a []string.
// Handles nil, []string, []any, and single string inputs.
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
