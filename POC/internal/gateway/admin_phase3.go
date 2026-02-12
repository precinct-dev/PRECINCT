package gateway

import (
	"encoding/json"
	"net/http"
)

type dlpRulesetStatus struct {
	ActiveVersion string `json:"active_version"`
	ActiveDigest  string `json:"active_digest"`
	Mode          string `json:"mode"`
	Note          string `json:"note,omitempty"`
}

// adminDLPRulesetsHandler exposes read-only DLP ruleset metadata.
// Phase 3 intent: this becomes the control-plane entry point for governed
// ruleset CRUD (with approvals, signing, rollbacks). For the POC we keep it
// strictly introspective to avoid fragile state.
func (g *Gateway) adminDLPRulesetsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "method not allowed",
		})
		return
	}

	version, digest := "", ""
	if g.dlpRuleOps != nil {
		version, digest = g.dlpRuleOps.ActiveRuleset()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dlpRulesetStatus{
		ActiveVersion: version,
		ActiveDigest:  digest,
		Mode:          "builtin",
		Note:          "POC mode: ruleset is code-defined; CRUD is future Phase 3 hardening.",
	})
}

// adminLoopRunsHandler exposes read-only loop run metadata. In the POC the loop
// plane is enforced mostly via immutable external limits (rate limiting, timeouts).
func (g *Gateway) adminLoopRunsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "method not allowed",
		})
		return
	}

	var runs []loopRunRecord
	if g.loopPolicy != nil {
		runs = g.loopPolicy.listRuns()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"runs": runs,
	})
}
