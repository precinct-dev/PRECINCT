package gateway

import (
	"fmt"
	"math"
	"strings"
	"sync"
)

type rlmLimits struct {
	MaxDepth       int
	MaxSubcalls    int
	MaxBudgetUnits float64
}

type rlmLineageState struct {
	LineageID          string
	RootRunID          string
	Limits             rlmLimits
	UsedSubcalls       int
	UsedBudgetUnits    float64
	LastObservedRunID  string
	LastParentRunID    string
	LastParentDecision string
}

type rlmExecutionInput struct {
	Apply             bool
	ExecutionMode     string
	LineageID         string
	ParentRunID       string
	ParentDecisionID  string
	Depth             int
	Subcall           bool
	UASGSMediated     bool
	SubcallBudgetUnit float64
	Limits            rlmLimits
}

type rlmGovernanceEngine struct {
	mu     sync.Mutex
	states map[string]*rlmLineageState
}

func newRLMGovernanceEngine() *rlmGovernanceEngine {
	return &rlmGovernanceEngine{
		states: make(map[string]*rlmLineageState),
	}
}

func (e *rlmGovernanceEngine) evaluate(req PlaneRequestV2) (bool, Decision, ReasonCode, int, map[string]any) {
	input, err := parseRLMExecutionInput(req)
	if err != nil {
		return true, DecisionDeny, ReasonRLMSchemaInvalid, 400, map[string]any{
			"rlm_schema_error": err.Error(),
		}
	}
	if !input.Apply {
		return false, "", "", 0, nil
	}

	if input.Subcall && !input.UASGSMediated {
		return true, DecisionDeny, ReasonRLMBypassDenied, 403, map[string]any{
			"rlm_lineage_id":      input.LineageID,
			"rlm_depth":           input.Depth,
			"rlm_parent_run":      input.ParentRunID,
			"rlm_parent_decision": input.ParentDecisionID,
			"uasgs_mediated":      false,
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	state, exists := e.states[input.LineageID]
	if !exists {
		state = &rlmLineageState{
			LineageID: input.LineageID,
			RootRunID: req.Envelope.RunID,
			Limits:    input.Limits,
		}
		e.states[input.LineageID] = state
	}

	if input.Depth > state.Limits.MaxDepth {
		return true, DecisionDeny, ReasonRLMHaltMaxDepth, 429, e.metadata(state, input, req.Envelope.RunID)
	}
	if state.UsedSubcalls+1 > state.Limits.MaxSubcalls {
		return true, DecisionDeny, ReasonRLMHaltMaxSubcalls, 429, e.metadata(state, input, req.Envelope.RunID)
	}
	if state.UsedBudgetUnits+input.SubcallBudgetUnit > state.Limits.MaxBudgetUnits {
		return true, DecisionDeny, ReasonRLMHaltMaxBudget, 429, e.metadata(state, input, req.Envelope.RunID)
	}

	state.UsedSubcalls++
	state.UsedBudgetUnits += input.SubcallBudgetUnit
	state.LastObservedRunID = req.Envelope.RunID
	state.LastParentRunID = input.ParentRunID
	state.LastParentDecision = input.ParentDecisionID

	return true, DecisionAllow, ReasonRLMAllow, 200, e.metadata(state, input, req.Envelope.RunID)
}

func (e *rlmGovernanceEngine) metadata(state *rlmLineageState, input rlmExecutionInput, runID string) map[string]any {
	return map[string]any{
		"rlm_mode":                   true,
		"rlm_lineage_id":             state.LineageID,
		"rlm_root_run_id":            state.RootRunID,
		"rlm_current_run_id":         runID,
		"rlm_parent_run_id":          input.ParentRunID,
		"rlm_parent_decision_id":     input.ParentDecisionID,
		"rlm_depth":                  input.Depth,
		"rlm_subcall_budget_units":   input.SubcallBudgetUnit,
		"rlm_subcalls_used":          state.UsedSubcalls,
		"rlm_subcalls_remaining":     maxInt(0, state.Limits.MaxSubcalls-state.UsedSubcalls),
		"rlm_budget_units_used":      state.UsedBudgetUnits,
		"rlm_budget_units_remaining": roundFloat(maxFloat(0, state.Limits.MaxBudgetUnits-state.UsedBudgetUnits), 4),
		"rlm_limits": map[string]any{
			"max_depth":        state.Limits.MaxDepth,
			"max_subcalls":     state.Limits.MaxSubcalls,
			"max_budget_units": state.Limits.MaxBudgetUnits,
		},
	}
}

func parseRLMExecutionInput(req PlaneRequestV2) (rlmExecutionInput, error) {
	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}

	mode := strings.ToLower(strings.TrimSpace(req.Envelope.ExecutionMode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "execution_mode", "standard")))
	}
	subcall := getBoolAttr(attrs, "rlm_subcall", false)
	if mode != "rlm" && !subcall {
		return rlmExecutionInput{Apply: false}, nil
	}
	if mode != "rlm" && subcall {
		return rlmExecutionInput{}, fmt.Errorf("rlm_subcall requires execution_mode=rlm")
	}

	lineageID := strings.TrimSpace(req.Envelope.LineageID)
	if lineageID == "" {
		lineageID = strings.TrimSpace(getStringAttr(attrs, "lineage_id", ""))
	}
	if lineageID == "" {
		return rlmExecutionInput{}, fmt.Errorf("lineage_id is required for rlm execution")
	}

	depth := getIntAttr(attrs, "rlm_depth", -1)
	if depth < 0 {
		return rlmExecutionInput{}, fmt.Errorf("rlm_depth is required and must be >= 0")
	}

	parentRunID := strings.TrimSpace(req.Envelope.ParentRunID)
	if parentRunID == "" {
		parentRunID = strings.TrimSpace(getStringAttr(attrs, "parent_run_id", ""))
	}
	parentDecisionID := strings.TrimSpace(req.Envelope.ParentDecisionID)
	if parentDecisionID == "" {
		parentDecisionID = strings.TrimSpace(getStringAttr(attrs, "parent_decision_id", ""))
	}
	if depth > 0 && parentRunID == "" {
		return rlmExecutionInput{}, fmt.Errorf("parent_run_id is required when rlm_depth > 0")
	}

	limits := defaultRLMLimits()
	if rawLimits, ok := attrs["rlm_limits"]; ok {
		parsed, err := parseRLMLimits(rawLimits)
		if err != nil {
			return rlmExecutionInput{}, err
		}
		limits = parsed
	}

	cost := getFloatAttr(attrs, "rlm_subcall_budget_units", 1.0)
	if cost <= 0 {
		cost = 1.0
	}

	mediated := getBoolAttr(attrs, "uasgs_mediated", false)
	if depth == 0 && !subcall {
		// Root RLM invocation may omit explicit mediation marker.
		mediated = true
	}

	return rlmExecutionInput{
		Apply:             true,
		ExecutionMode:     mode,
		LineageID:         lineageID,
		ParentRunID:       parentRunID,
		ParentDecisionID:  parentDecisionID,
		Depth:             depth,
		Subcall:           subcall || depth > 0,
		UASGSMediated:     mediated,
		SubcallBudgetUnit: cost,
		Limits:            limits,
	}, nil
}

func parseRLMLimits(raw any) (rlmLimits, error) {
	limits, ok := raw.(map[string]any)
	if !ok {
		return rlmLimits{}, fmt.Errorf("rlm_limits must be an object")
	}
	maxDepth := getIntAttr(limits, "max_depth", 0)
	maxSubcalls := getIntAttr(limits, "max_subcalls", 0)
	maxBudget := getFloatAttr(limits, "max_budget_units", 0)
	if maxDepth <= 0 || maxSubcalls <= 0 || maxBudget <= 0 {
		return rlmLimits{}, fmt.Errorf("rlm_limits values must be > 0")
	}
	return rlmLimits{
		MaxDepth:       maxDepth,
		MaxSubcalls:    maxSubcalls,
		MaxBudgetUnits: maxBudget,
	}, nil
}

func defaultRLMLimits() rlmLimits {
	return rlmLimits{
		MaxDepth:       6,
		MaxSubcalls:    64,
		MaxBudgetUnits: 128,
	}
}

func getFloatAttr(attrs map[string]any, key string, fallback float64) float64 {
	raw, ok := attrs[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case float32:
		return float64(v)
	case float64:
		return v
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return fallback
	}
}

func roundFloat(v float64, places int) float64 {
	if places <= 0 {
		return math.Round(v)
	}
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
