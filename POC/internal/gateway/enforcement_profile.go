package gateway

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

const (
	enforcementProfileDev                = "dev"
	enforcementProfileProdStandard       = "prod_standard"
	enforcementProfileProdRegulatedHIPAA = "prod_regulated_hipaa"
)

type enforcementProfileDefinition struct {
	Name            string
	Description     string
	StartupGateMode string

	RequireSPIFFEProd  bool
	RequireMCPModeMCP  bool
	RequireMediation   bool
	RequireHIPAAGuard  bool
	RequiredControlIDs []string
}

type enforcementProfileControls struct {
	EnforceModelMediationGate bool `json:"enforce_model_mediation_gate"`
	EnforceHIPAAPromptSafety  bool `json:"enforce_hipaa_prompt_safety_gate"`
}

type enforcementProfileConformance struct {
	Status     string   `json:"status"`
	Violations []string `json:"violations,omitempty"`
}

type enforcementProfileRuntime struct {
	Name            string                        `json:"name"`
	Description     string                        `json:"description"`
	StartupGateMode string                        `json:"startup_gate_mode"`
	RequiredControl []string                      `json:"required_controls"`
	Runtime         map[string]string             `json:"runtime"`
	Controls        enforcementProfileControls    `json:"controls"`
	Conformance     enforcementProfileConformance `json:"conformance"`
	GeneratedAt     string                        `json:"generated_at"`
}

var enforcementProfileCatalog = map[string]enforcementProfileDefinition{
	enforcementProfileDev: {
		Name:            enforcementProfileDev,
		Description:     "Developer profile with permissive startup checks and portable defaults.",
		StartupGateMode: "permissive",
		RequiredControlIDs: []string{
			"enforce_model_mediation_gate",
		},
	},
	enforcementProfileProdStandard: {
		Name:              enforcementProfileProdStandard,
		Description:       "Production baseline profile with strict startup conformance gates.",
		StartupGateMode:   "strict",
		RequireSPIFFEProd: true,
		RequireMCPModeMCP: true,
		RequireMediation:  true,
		RequiredControlIDs: []string{
			"spiffe_mode=prod",
			"mcp_transport_mode=mcp",
			"upstream_url=https",
			"enforce_model_mediation_gate",
			"approval_signing_key",
		},
	},
	enforcementProfileProdRegulatedHIPAA: {
		Name:              enforcementProfileProdRegulatedHIPAA,
		Description:       "Strict regulated profile with HIPAA prompt safety and mediation gates.",
		StartupGateMode:   "strict",
		RequireSPIFFEProd: true,
		RequireMCPModeMCP: true,
		RequireMediation:  true,
		RequireHIPAAGuard: true,
		RequiredControlIDs: []string{
			"spiffe_mode=prod",
			"mcp_transport_mode=mcp",
			"upstream_url=https",
			"enforce_model_mediation_gate",
			"enforce_hipaa_prompt_safety_gate",
			"approval_signing_key",
		},
	},
}

func resolveEnforcementProfile(cfg *Config) (*enforcementProfileRuntime, error) {
	if cfg == nil {
		return nil, fmt.Errorf("gateway config is required")
	}

	profileName := strings.ToLower(strings.TrimSpace(cfg.EnforcementProfile))
	if profileName == "" {
		profileName = enforcementProfileDev
	}
	def, ok := enforcementProfileCatalog[profileName]
	if !ok {
		return nil, fmt.Errorf("unsupported enforcement profile %q", profileName)
	}

	mcpMode := strings.ToLower(strings.TrimSpace(cfg.MCPTransportMode))
	if mcpMode == "" {
		mcpMode = "mcp"
	}
	spiffeMode := strings.ToLower(strings.TrimSpace(cfg.SPIFFEMode))
	if spiffeMode == "" {
		spiffeMode = "dev"
	}

	// Backward compatibility: callers that build Config literals without the
	// new profile controls should retain secure defaults instead of Go zero-values.
	controls := enforcementProfileControls{
		EnforceModelMediationGate: true,
		EnforceHIPAAPromptSafety:  true,
	}
	if cfg.EnforcementControlOverrides {
		controls = enforcementProfileControls{
			EnforceModelMediationGate: cfg.EnforceModelMediationGate,
			EnforceHIPAAPromptSafety:  cfg.EnforceHIPAAPromptSafetyGate,
		}
	}

	var violations []string
	if def.RequireSPIFFEProd && spiffeMode != "prod" {
		violations = append(violations, "spiffe_mode must be prod")
	}
	if def.RequireMCPModeMCP && mcpMode != "mcp" {
		violations = append(violations, "mcp_transport_mode must be mcp")
	}
	if def.RequireMediation && !controls.EnforceModelMediationGate {
		violations = append(violations, "enforce_model_mediation_gate must be true")
	}
	if def.RequireHIPAAGuard && !controls.EnforceHIPAAPromptSafety {
		violations = append(violations, "enforce_hipaa_prompt_safety_gate must be true")
	}
	if def.StartupGateMode == "strict" {
		signingKey := strings.TrimSpace(cfg.ApprovalSigningKey)
		switch {
		case signingKey == "":
			violations = append(violations, "approval_signing_key must be set in strict profiles")
		case !middleware.IsApprovalSigningKeyStrong(signingKey):
			violations = append(violations, fmt.Sprintf("approval_signing_key must be at least %d characters and non-default", middleware.MinApprovalSigningKeyLength))
		}

		// Strict MCP mode must not permit plaintext upstream execution.
		// Enforce HTTPS so the MCP path can only run over TLS transport.
		if mcpMode == "mcp" {
			upstream := strings.TrimSpace(cfg.UpstreamURL)
			switch {
			case upstream == "":
				violations = append(violations, "upstream_url must be set in strict profiles when mcp_transport_mode=mcp")
			default:
				parsed, err := url.Parse(upstream)
				if err != nil || parsed.Scheme == "" {
					violations = append(violations, "upstream_url must be a valid URL in strict profiles when mcp_transport_mode=mcp")
				} else if !strings.EqualFold(parsed.Scheme, "https") {
					violations = append(violations, "upstream_url must use https in strict profiles when mcp_transport_mode=mcp")
				}
			}
		}
	}

	conformance := enforcementProfileConformance{Status: "pass"}
	if len(violations) > 0 {
		conformance = enforcementProfileConformance{
			Status:     "fail",
			Violations: append([]string(nil), violations...),
		}
	}

	runtime := &enforcementProfileRuntime{
		Name:            def.Name,
		Description:     def.Description,
		StartupGateMode: def.StartupGateMode,
		RequiredControl: append([]string(nil), def.RequiredControlIDs...),
		Runtime: map[string]string{
			"spiffe_mode":        spiffeMode,
			"mcp_transport_mode": mcpMode,
		},
		Controls:    controls,
		Conformance: conformance,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if def.StartupGateMode == "strict" && len(violations) > 0 {
		return nil, fmt.Errorf("enforcement profile %q startup conformance failed: %s", def.Name, strings.Join(violations, "; "))
	}

	return runtime, nil
}

func (p *enforcementProfileRuntime) snapshot() enforcementProfileRuntime {
	if p == nil {
		return enforcementProfileRuntime{
			Name:            enforcementProfileDev,
			Description:     "Developer profile with permissive startup checks and portable defaults.",
			StartupGateMode: "permissive",
			RequiredControl: []string{"enforce_model_mediation_gate"},
			Runtime: map[string]string{
				"spiffe_mode":        "dev",
				"mcp_transport_mode": "mcp",
			},
			Controls: enforcementProfileControls{
				EnforceModelMediationGate: true,
				EnforceHIPAAPromptSafety:  true,
			},
			Conformance: enforcementProfileConformance{Status: "pass"},
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	out := *p
	if p.RequiredControl != nil {
		out.RequiredControl = append([]string(nil), p.RequiredControl...)
	}
	if p.Runtime != nil {
		out.Runtime = make(map[string]string, len(p.Runtime))
		for k, v := range p.Runtime {
			out.Runtime[k] = v
		}
	}
	if p.Conformance.Violations != nil {
		out.Conformance.Violations = append([]string(nil), p.Conformance.Violations...)
	}
	return out
}

func (p *enforcementProfileRuntime) export(path string) error {
	if p == nil {
		return nil
	}
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(trimmed), 0o755); err != nil {
		return fmt.Errorf("create profile export dir: %w", err)
	}
	payload, err := json.MarshalIndent(p.snapshot(), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile metadata: %w", err)
	}
	if err := os.WriteFile(trimmed, payload, 0o644); err != nil {
		return fmt.Errorf("write profile metadata export: %w", err)
	}
	return nil
}
