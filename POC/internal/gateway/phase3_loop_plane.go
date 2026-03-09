package gateway

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type loopRunGovernanceState string

const (
	loopStateCreated                   loopRunGovernanceState = "CREATED"
	loopStateRunning                   loopRunGovernanceState = "RUNNING"
	loopStateWaitingApproval           loopRunGovernanceState = "WAITING_APPROVAL"
	loopStateCompleted                 loopRunGovernanceState = "COMPLETED"
	loopStateHaltedPolicy              loopRunGovernanceState = "HALTED_POLICY"
	loopStateHaltedBudget              loopRunGovernanceState = "HALTED_BUDGET"
	loopStateHaltedProviderUnavailable loopRunGovernanceState = "HALTED_PROVIDER_UNAVAILABLE"
	loopStateHaltedOperator            loopRunGovernanceState = "HALTED_OPERATOR"
)

type loopImmutableLimits struct {
	MaxSteps             int
	MaxToolCalls         int
	MaxModelCalls        int
	MaxWallTimeMS        int
	MaxEgressBytes       int
	MaxModelCostUSD      float64
	MaxProviderFailovers int
	MaxRiskScore         float64
}

type loopUsageSnapshot struct {
	Steps             int
	ToolCalls         int
	ModelCalls        int
	WallTimeMS        int
	EgressBytes       int
	ModelCostUSD      float64
	ProviderFailovers int
	RiskScore         float64
}

type loopCheckInput struct {
	Event               string
	StepUpRequired      bool
	OperatorHalt        bool
	ProviderUnavailable bool
	Limits              loopImmutableLimits
	Usage               loopUsageSnapshot
}

type loopRunRecord struct {
	RunID          string                 `json:"run_id"`
	SessionID      string                 `json:"session_id"`
	Tenant         string                 `json:"tenant"`
	State          loopRunGovernanceState `json:"state"`
	HaltReason     ReasonCode             `json:"halt_reason,omitempty"`
	Limits         loopImmutableLimits    `json:"limits"`
	Usage          loopUsageSnapshot      `json:"usage"`
	LastDecisionID string                 `json:"last_decision_id,omitempty"`
	LastTraceID    string                 `json:"last_trace_id,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type loopPlanePolicyEngine struct {
	mu   sync.Mutex
	runs map[string]loopRunRecord
}

func newLoopPlanePolicyEngine() *loopPlanePolicyEngine {
	return &loopPlanePolicyEngine{
		runs: make(map[string]loopRunRecord),
	}
}

func (p *loopPlanePolicyEngine) evaluate(req PlaneRequestV2, decisionID, traceID string, now time.Time) (Decision, ReasonCode, int, map[string]any) {
	input, err := parseLoopCheckInput(req.Policy.Attributes)
	if err != nil {
		return DecisionDeny, ReasonLoopSchemaInvalid, 400, map[string]any{
			"schema_error": err.Error(),
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	record, exists := p.runs[req.Envelope.RunID]
	if !exists {
		record = loopRunRecord{
			RunID:     req.Envelope.RunID,
			SessionID: req.Envelope.SessionID,
			Tenant:    req.Envelope.Tenant,
			State:     loopStateCreated,
			Limits:    input.Limits,
			CreatedAt: now,
			UpdatedAt: now,
		}
	} else if !loopLimitsEqual(record.Limits, input.Limits) {
		return DecisionDeny, ReasonLoopLimitsImmutableViolation, httpStatusForbidden, map[string]any{
			"run_id":           req.Envelope.RunID,
			"governance_state": record.State,
			"frozen_limits":    record.Limits,
			"requested_limits": input.Limits,
		}
	}

	record.Usage = input.Usage
	record.UpdatedAt = now
	record.LastDecisionID = decisionID
	record.LastTraceID = traceID

	// Terminal states are immutable for deterministic external governance.
	if isLoopTerminalState(record.State) {
		if record.State == loopStateCompleted {
			p.runs[req.Envelope.RunID] = record
			return DecisionAllow, ReasonLoopCompleted, 200, loopMetadata(record, req.Envelope.RunID, "run_completed")
		}
		if record.HaltReason == "" {
			record.HaltReason = ReasonLoopRunAlreadyTerminated
		}
		p.runs[req.Envelope.RunID] = record
		return DecisionDeny, record.HaltReason, httpStatusConflict, loopMetadata(record, req.Envelope.RunID, "run_already_halted")
	}

	if input.OperatorHalt || input.Event == "operator_halt" {
		record.State = loopStateHaltedOperator
		record.HaltReason = ReasonLoopHaltOperator
		p.runs[req.Envelope.RunID] = record
		return DecisionDeny, ReasonLoopHaltOperator, httpStatusConflict, loopMetadata(record, req.Envelope.RunID, "operator_halt")
	}

	if input.ProviderUnavailable || input.Event == "provider_unavailable" {
		record.State = loopStateHaltedProviderUnavailable
		record.HaltReason = ReasonLoopHaltProviderUnavailable
		p.runs[req.Envelope.RunID] = record
		return DecisionDeny, ReasonLoopHaltProviderUnavailable, httpStatusBadGateway, loopMetadata(record, req.Envelope.RunID, "provider_unavailable")
	}

	if input.StepUpRequired || input.Event == "approval_required" {
		record.State = loopStateWaitingApproval
		p.runs[req.Envelope.RunID] = record
		return DecisionStepUp, ReasonLoopStepUpRequired, httpStatusAccepted, loopMetadata(record, req.Envelope.RunID, "waiting_approval")
	}
	if input.Event == "approval_granted" && record.State == loopStateWaitingApproval {
		record.State = loopStateRunning
	}

	if exceeded, reason := loopLimitReason(input.Usage, record.Limits); exceeded {
		record.HaltReason = reason
		if reason == ReasonLoopHaltRiskScore {
			record.State = loopStateHaltedPolicy
			p.runs[req.Envelope.RunID] = record
			return DecisionDeny, reason, httpStatusForbidden, loopMetadata(record, req.Envelope.RunID, "halted_policy")
		}
		record.State = loopStateHaltedBudget
		p.runs[req.Envelope.RunID] = record
		return DecisionDeny, reason, httpStatusTooManyRequests, loopMetadata(record, req.Envelope.RunID, "halted_budget")
	}

	if input.Event == "complete" {
		record.State = loopStateCompleted
		p.runs[req.Envelope.RunID] = record
		return DecisionAllow, ReasonLoopCompleted, 200, loopMetadata(record, req.Envelope.RunID, "run_completed")
	}

	record.State = loopStateRunning
	p.runs[req.Envelope.RunID] = record
	return DecisionAllow, ReasonLoopAllow, 200, loopMetadata(record, req.Envelope.RunID, "run_running")
}

func (p *loopPlanePolicyEngine) listRuns() []loopRunRecord {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]loopRunRecord, 0, len(p.runs))
	for _, r := range p.runs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].RunID < out[j].RunID
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out
}

func (p *loopPlanePolicyEngine) getRun(runID string) (loopRunRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.runs[runID]
	return r, ok
}

func parseLoopCheckInput(attrs map[string]any) (loopCheckInput, error) {
	if attrs == nil {
		return loopCheckInput{}, fmt.Errorf("attributes are required")
	}
	limitsAny, ok := attrs["limits"]
	if !ok {
		return loopCheckInput{}, fmt.Errorf("limits are required")
	}
	limitsObj, ok := limitsAny.(map[string]any)
	if !ok {
		return loopCheckInput{}, fmt.Errorf("limits must be an object")
	}
	usageAny, ok := attrs["usage"]
	if !ok {
		return loopCheckInput{}, fmt.Errorf("usage is required")
	}
	usageObj, ok := usageAny.(map[string]any)
	if !ok {
		return loopCheckInput{}, fmt.Errorf("usage must be an object")
	}

	limits := loopImmutableLimits{
		MaxSteps:             parsePositiveInt(limitsObj, "max_steps"),
		MaxToolCalls:         parsePositiveInt(limitsObj, "max_tool_calls"),
		MaxModelCalls:        parsePositiveInt(limitsObj, "max_model_calls"),
		MaxWallTimeMS:        parsePositiveInt(limitsObj, "max_wall_time_ms"),
		MaxEgressBytes:       parsePositiveInt(limitsObj, "max_egress_bytes"),
		MaxModelCostUSD:      parsePositiveFloat(limitsObj, "max_model_cost_usd"),
		MaxProviderFailovers: parsePositiveInt(limitsObj, "max_provider_failovers"),
		MaxRiskScore:         parsePositiveFloat(limitsObj, "max_risk_score"),
	}
	if limits.MaxSteps == 0 || limits.MaxToolCalls == 0 || limits.MaxModelCalls == 0 || limits.MaxWallTimeMS == 0 ||
		limits.MaxEgressBytes == 0 || limits.MaxModelCostUSD == 0 || limits.MaxProviderFailovers == 0 || limits.MaxRiskScore == 0 {
		return loopCheckInput{}, fmt.Errorf("all immutable limits must be > 0")
	}

	usage := loopUsageSnapshot{
		Steps:             parseNonNegativeInt(usageObj, "steps"),
		ToolCalls:         parseNonNegativeInt(usageObj, "tool_calls"),
		ModelCalls:        parseNonNegativeInt(usageObj, "model_calls"),
		WallTimeMS:        parseNonNegativeInt(usageObj, "wall_time_ms"),
		EgressBytes:       parseNonNegativeInt(usageObj, "egress_bytes"),
		ModelCostUSD:      parseNonNegativeFloat(usageObj, "model_cost_usd"),
		ProviderFailovers: parseNonNegativeInt(usageObj, "provider_failovers"),
		RiskScore:         parseNonNegativeFloat(usageObj, "risk_score"),
	}

	event := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "event", "boundary")))
	switch event {
	case "boundary", "approval_required", "approval_granted", "complete", "provider_unavailable", "operator_halt":
	default:
		return loopCheckInput{}, fmt.Errorf("unsupported event %q", event)
	}

	return loopCheckInput{
		Event:               event,
		StepUpRequired:      getBoolAttr(attrs, "step_up_required", false),
		OperatorHalt:        getBoolAttr(attrs, "operator_halt", false),
		ProviderUnavailable: getBoolAttr(attrs, "provider_unavailable", false),
		Limits:              limits,
		Usage:               usage,
	}, nil
}

func parsePositiveInt(obj map[string]any, key string) int {
	v := getIntAttr(obj, key, 0)
	if v < 0 {
		return 0
	}
	return v
}

func parsePositiveFloat(obj map[string]any, key string) float64 {
	v := parseFloatAttr(obj, key, 0)
	if v < 0 {
		return 0
	}
	return v
}

func parseNonNegativeInt(obj map[string]any, key string) int {
	v := getIntAttr(obj, key, 0)
	if v < 0 {
		return 0
	}
	return v
}

func parseNonNegativeFloat(obj map[string]any, key string) float64 {
	v := parseFloatAttr(obj, key, 0)
	if v < 0 {
		return 0
	}
	return v
}

func parseFloatAttr(attrs map[string]any, key string, fallback float64) float64 {
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

func loopLimitReason(usage loopUsageSnapshot, limits loopImmutableLimits) (bool, ReasonCode) {
	switch {
	case usage.Steps > limits.MaxSteps:
		return true, ReasonLoopHaltMaxSteps
	case usage.ToolCalls > limits.MaxToolCalls:
		return true, ReasonLoopHaltMaxToolCalls
	case usage.ModelCalls > limits.MaxModelCalls:
		return true, ReasonLoopHaltMaxModelCalls
	case usage.WallTimeMS > limits.MaxWallTimeMS:
		return true, ReasonLoopHaltMaxWallTime
	case usage.EgressBytes > limits.MaxEgressBytes:
		return true, ReasonLoopHaltMaxEgressBytes
	case usage.ModelCostUSD > limits.MaxModelCostUSD:
		return true, ReasonLoopHaltMaxModelCost
	case usage.ProviderFailovers > limits.MaxProviderFailovers:
		return true, ReasonLoopHaltMaxProviderFailovers
	case usage.RiskScore > limits.MaxRiskScore:
		return true, ReasonLoopHaltRiskScore
	default:
		return false, ""
	}
}

func loopLimitsEqual(a, b loopImmutableLimits) bool {
	return a.MaxSteps == b.MaxSteps &&
		a.MaxToolCalls == b.MaxToolCalls &&
		a.MaxModelCalls == b.MaxModelCalls &&
		a.MaxWallTimeMS == b.MaxWallTimeMS &&
		a.MaxEgressBytes == b.MaxEgressBytes &&
		a.MaxModelCostUSD == b.MaxModelCostUSD &&
		a.MaxProviderFailovers == b.MaxProviderFailovers &&
		a.MaxRiskScore == b.MaxRiskScore
}

func loopMetadata(record loopRunRecord, runID, outcome string) map[string]any {
	return map[string]any{
		"run_id":           runID,
		"governance_state": record.State,
		"halt_reason":      record.HaltReason,
		"limits":           record.Limits,
		"usage":            record.Usage,
		"integration_mode": "boundary_only",
		"outcome":          outcome,
	}
}

func isLoopTerminalState(state loopRunGovernanceState) bool {
	switch state {
	case loopStateCompleted, loopStateHaltedPolicy, loopStateHaltedBudget, loopStateHaltedProviderUnavailable, loopStateHaltedOperator:
		return true
	default:
		return false
	}
}

const (
	httpStatusAccepted        = 202
	httpStatusConflict        = 409
	httpStatusForbidden       = 403
	httpStatusTooManyRequests = 429
	httpStatusBadGateway      = 502
)
