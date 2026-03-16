package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

const (
	BypassCheckSPIFFEIdentity = "spiffe_identity_required"
	BypassCheckAdminAllowlist = "admin_allowlist_required"
	BypassCheckDemoModeGate   = "demo_mode_gate_required"
)

// OPABypassContract defines one explicit OPA bypass contract and the
// compensating checks that must be enforced for that route class.
type OPABypassContract struct {
	ID                       string
	ExactPaths               []string
	PathPrefixes             []string
	RequiresWebSocketUpgrade bool
	RequiredChecks           []string
	PassthroughReason        string
	ProbePath                string
	ProbeMethod              string
}

var (
	opaBypassContractsMu sync.RWMutex
	opaBypassContracts   = defaultOPABypassContracts()
)

func defaultOPABypassContracts() []OPABypassContract {
	return []OPABypassContract{
		{
			ID:                "demo_rugpull_controls",
			ExactPaths:        []string{"/__demo__/rugpull/on", "/__demo__/rugpull/off"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity, BypassCheckDemoModeGate, BypassCheckAdminAllowlist},
			PassthroughReason: "demo control endpoint passthrough (contracted)",
			ProbePath:         "/__demo__/rugpull/on",
			ProbeMethod:       http.MethodPost,
		},
		{
			ID:                "demo_ratelimit_proof",
			ExactPaths:        []string{"/__demo__/ratelimit"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity, BypassCheckDemoModeGate},
			PassthroughReason: "demo ratelimit endpoint passthrough (contracted)",
			ProbePath:         "/__demo__/ratelimit",
			ProbeMethod:       http.MethodGet,
		},
		{
			ID: "connector_lifecycle_mutations",
			ExactPaths: []string{
				"/v1/connectors/register",
				"/v1/connectors/validate",
				"/v1/connectors/approve",
				"/v1/connectors/activate",
				"/v1/connectors/revoke",
			},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity, BypassCheckAdminAllowlist},
			PassthroughReason: "connector lifecycle mutation passthrough (contracted)",
			ProbePath:         "/v1/connectors/register",
			ProbeMethod:       http.MethodPost,
		},
		{
			ID:                "connector_observability_routes",
			ExactPaths:        []string{"/v1/connectors/status", "/v1/connectors/report"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity},
			PassthroughReason: "connector read-only passthrough (contracted)",
			ProbePath:         "/v1/connectors/report",
			ProbeMethod:       http.MethodGet,
		},
		{
			ID:                "phase3_plane_routes",
			PathPrefixes:      []string{"/v1/ingress/", "/v1/context/", "/v1/model/", "/v1/tool/", "/v1/loop/"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity},
			PassthroughReason: "phase3 plane passthrough (contracted)",
			ProbePath:         "/v1/model/call",
			ProbeMethod:       http.MethodPost,
		},
		{
			ID:                "openai_model_egress",
			PathPrefixes:      []string{"/openai/v1/"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity},
			PassthroughReason: "openai model egress passthrough (contracted)",
			ProbePath:         "/openai/v1/chat/completions",
			ProbeMethod:       http.MethodPost,
		},
		{
			ID:                "anthropic_model_egress",
			ExactPaths:        []string{"/v1/messages"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity},
			PassthroughReason: "anthropic model egress passthrough (contracted)",
			ProbePath:         "/v1/messages",
			ProbeMethod:       http.MethodPost,
		},
		{
			ID:                "admin_control_plane",
			ExactPaths:        []string{"/admin"},
			PathPrefixes:      []string{"/admin/"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity, BypassCheckAdminAllowlist},
			PassthroughReason: "admin passthrough (contracted)",
			ProbePath:         "/admin/dlp/rulesets",
			ProbeMethod:       http.MethodGet,
		},
		{
			ID:                       "websocket_upgrade",
			RequiresWebSocketUpgrade: true,
			RequiredChecks:           []string{BypassCheckSPIFFEIdentity},
			PassthroughReason:        "websocket upgrade passthrough (contracted)",
			ProbePath:                "/ws",
			ProbeMethod:              http.MethodGet,
		},
		{
			ID:                "tools_invoke_compat",
			ExactPaths:        []string{"/tools/invoke"},
			RequiredChecks:    []string{BypassCheckSPIFFEIdentity},
			PassthroughReason: "tools/invoke passthrough (contracted)",
			ProbePath:         "/tools/invoke",
			ProbeMethod:       http.MethodPost,
		},
	}
}

func cloneOPABypassContracts(in []OPABypassContract) []OPABypassContract {
	out := make([]OPABypassContract, 0, len(in))
	for _, c := range in {
		item := OPABypassContract{
			ID:                       c.ID,
			RequiresWebSocketUpgrade: c.RequiresWebSocketUpgrade,
			PassthroughReason:        c.PassthroughReason,
			ProbePath:                c.ProbePath,
			ProbeMethod:              c.ProbeMethod,
		}
		item.ExactPaths = append([]string(nil), c.ExactPaths...)
		item.PathPrefixes = append([]string(nil), c.PathPrefixes...)
		item.RequiredChecks = append([]string(nil), c.RequiredChecks...)
		out = append(out, item)
	}
	return out
}

// ListOPABypassContracts returns a copy of active bypass contracts.
func ListOPABypassContracts() []OPABypassContract {
	opaBypassContractsMu.RLock()
	defer opaBypassContractsMu.RUnlock()
	return cloneOPABypassContracts(opaBypassContracts)
}

// SetOPABypassContractsForTest overrides contracts for test scenarios.
// It returns a restore function that must be deferred by callers.
func SetOPABypassContractsForTest(contracts []OPABypassContract) func() {
	opaBypassContractsMu.Lock()
	prev := cloneOPABypassContracts(opaBypassContracts)
	opaBypassContracts = cloneOPABypassContracts(contracts)
	opaBypassContractsMu.Unlock()
	return func() {
		opaBypassContractsMu.Lock()
		opaBypassContracts = prev
		opaBypassContractsMu.Unlock()
	}
}

func contractMatchesRequest(contract OPABypassContract, r *http.Request) bool {
	if contract.RequiresWebSocketUpgrade && !isWebSocketUpgradeRequest(r) {
		return false
	}

	path := r.URL.Path
	for _, exact := range contract.ExactPaths {
		if path == exact {
			return true
		}
	}
	for _, prefix := range contract.PathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Contracts that are websocket-only may intentionally omit path selectors.
	return contract.RequiresWebSocketUpgrade && len(contract.ExactPaths) == 0 && len(contract.PathPrefixes) == 0
}

// MatchOPABypassContract returns the first matching OPA bypass contract for request.
func MatchOPABypassContract(r *http.Request) (OPABypassContract, bool) {
	for _, contract := range ListOPABypassContracts() {
		if contractMatchesRequest(contract, r) {
			return contract, true
		}
	}
	return OPABypassContract{}, false
}

// ValidateOPABypassContracts validates contract shape and compensating checks.
func ValidateOPABypassContracts() error {
	contracts := ListOPABypassContracts()
	if len(contracts) == 0 {
		return fmt.Errorf("opa bypass contract validation failed: no bypass contracts defined")
	}

	allowedChecks := map[string]struct{}{
		BypassCheckSPIFFEIdentity: {},
		BypassCheckAdminAllowlist: {},
		BypassCheckDemoModeGate:   {},
	}
	seenIDs := map[string]struct{}{}
	var violations []string

	for _, contract := range contracts {
		id := strings.TrimSpace(contract.ID)
		if id == "" {
			violations = append(violations, "contract id is required")
			continue
		}
		if _, dup := seenIDs[id]; dup {
			violations = append(violations, "duplicate contract id: "+id)
		}
		seenIDs[id] = struct{}{}

		if len(contract.RequiredChecks) == 0 {
			violations = append(violations, fmt.Sprintf("contract %q must define at least one compensating check", id))
		}
		if len(contract.ExactPaths) == 0 && len(contract.PathPrefixes) == 0 && !contract.RequiresWebSocketUpgrade {
			violations = append(violations, fmt.Sprintf("contract %q must define a path matcher or websocket matcher", id))
		}
		if strings.TrimSpace(contract.ProbePath) == "" {
			violations = append(violations, fmt.Sprintf("contract %q must define a probe path", id))
		}
		for _, check := range contract.RequiredChecks {
			checkID := strings.TrimSpace(check)
			if _, ok := allowedChecks[checkID]; !ok {
				violations = append(violations, fmt.Sprintf("contract %q uses unsupported check %q", id, checkID))
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("opa bypass contract validation failed: %s", strings.Join(violations, "; "))
	}

	return nil
}
