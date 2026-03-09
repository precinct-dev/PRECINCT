package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

type dlpRulesetsResponse struct {
	Active   *dlpRuleset  `json:"active,omitempty"`
	Rulesets []dlpRuleset `json:"rulesets,omitempty"`
	Status   string       `json:"status"`
	Error    string       `json:"error,omitempty"`
}

func (g *Gateway) adminDLPRulesetsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if g.dlpRuleOps == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{
			Status: "failed",
			Error:  "dlp ruleops manager not initialized",
		})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/dlp/rulesets")
	path = strings.Trim(path, "/")

	switch {
	case path == "":
		g.handleDLPRulesetsCollection(w, r)
		return
	case path == "active":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		active, ok := g.dlpRuleOps.active()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: "no active ruleset"})
			return
		}
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "ok", Active: active})
		return
	case path == "rollback":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req dlpRulesetRollbackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: "invalid request body"})
			return
		}
		rs, err := g.dlpRuleOps.rollback(req.TargetVersion, time.Now().UTC())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: err.Error()})
			return
		}
		g.auditDLPRulesetEvent(r, "dlp.ruleset.rollback", "dlp_ruleset_rollback", rs)
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "rolled_back", Active: rs})
		return
	default:
		parts := strings.Split(path, "/")
		if len(parts) == 2 && parts[1] == "approve" && r.Method == http.MethodPost {
			g.handleDLPRulesetApprove(w, r, parts[0])
			return
		}
		if len(parts) == 2 && parts[1] == "promote" && r.Method == http.MethodPost {
			g.handleDLPRulesetPromote(w, r, parts[0])
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: "unsupported dlp ruleset operation"})
	}
}

func (g *Gateway) handleDLPRulesetsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		active, _ := g.dlpRuleOps.active()
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{
			Status:   "ok",
			Active:   active,
			Rulesets: g.dlpRuleOps.list(),
		})
	case http.MethodPost:
		var req dlpRulesetUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: "invalid request body"})
			return
		}
		rs, created, err := g.dlpRuleOps.upsertDraft(req, time.Now().UTC())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: err.Error()})
			return
		}
		if created {
			g.auditDLPRulesetEvent(r, "dlp.ruleset.create", "dlp_ruleset_create", rs)
		} else {
			g.auditDLPRulesetEvent(r, "dlp.ruleset.update", "dlp_ruleset_update", rs)
		}
		status := "updated"
		if created {
			status = "created"
		}
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: status, Active: rs})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleDLPRulesetApprove(w http.ResponseWriter, r *http.Request, version string) {
	var req dlpRulesetApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: "invalid request body"})
		return
	}
	rs, err := g.dlpRuleOps.approve(version, req.Approver, req.Signature, time.Now().UTC())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: err.Error()})
		return
	}
	g.auditDLPRulesetEvent(r, "dlp.ruleset.approve", "dlp_ruleset_approve", rs)
	_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "approved", Active: rs})
}

func (g *Gateway) handleDLPRulesetPromote(w http.ResponseWriter, r *http.Request, version string) {
	rs, err := g.dlpRuleOps.promote(version, time.Now().UTC())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "failed", Error: err.Error()})
		return
	}
	g.auditDLPRulesetEvent(r, "dlp.ruleset.promote", "dlp_ruleset_promote", rs)
	_ = json.NewEncoder(w).Encode(dlpRulesetsResponse{Status: "promoted", Active: rs})
}

func (g *Gateway) auditDLPRulesetEvent(r *http.Request, eventType, action string, rs *dlpRuleset) {
	if g.auditor == nil || rs == nil {
		return
	}
	g.auditor.Log(middleware.AuditEvent{
		EventType:  eventType,
		Severity:   "Info",
		SessionID:  middleware.GetSessionID(r.Context()),
		DecisionID: middleware.GetDecisionID(r.Context()),
		TraceID:    middleware.GetTraceID(r.Context()),
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     action,
		Result: fmt.Sprintf(
			"version=%s digest=%s state=%s approved=%t signed=%t",
			rs.Version, rs.Digest, rs.State, rs.Approved, rs.Signed,
		),
		Method: r.Method,
		Path:   r.URL.Path,
	})
}
