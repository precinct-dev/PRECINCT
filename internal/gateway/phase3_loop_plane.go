package gateway

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Loop Governance State Machine
// ---------------------------------------------------------------------------

// loopRunGovernanceState represents the lifecycle state of a governed agent loop run.
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

// ---------------------------------------------------------------------------
// Immutable limit and usage snapshot types
// ---------------------------------------------------------------------------

// loopImmutableLimits defines the frozen budget envelope for a loop run.
// Once set on the first evaluate call, limits cannot be changed for the lifetime
// of that run -- any mismatch triggers LOOP_LIMITS_IMMUTABLE_VIOLATION.
type loopImmutableLimits struct {
	MaxSteps             int     `json:"max_steps"`
	MaxToolCalls         int     `json:"max_tool_calls"`
	MaxModelCalls        int     `json:"max_model_calls"`
	MaxWallTimeMS        int     `json:"max_wall_time_ms"`
	MaxEgressBytes       int     `json:"max_egress_bytes"`
	MaxModelCostUSD      float64 `json:"max_model_cost_usd"`
	MaxProviderFailovers int     `json:"max_provider_failovers"`
	MaxRiskScore         float64 `json:"max_risk_score"`
}

// loopUsageSnapshot captures the current usage counters for a loop run.
type loopUsageSnapshot struct {
	Steps             int     `json:"steps"`
	ToolCalls         int     `json:"tool_calls"`
	ModelCalls        int     `json:"model_calls"`
	WallTimeMS        int     `json:"wall_time_ms"`
	EgressBytes       int     `json:"egress_bytes"`
	ModelCostUSD      float64 `json:"model_cost_usd"`
	ProviderFailovers int     `json:"provider_failovers"`
	RiskScore         float64 `json:"risk_score"`
}

// ---------------------------------------------------------------------------
// Parsed input from request attributes
// ---------------------------------------------------------------------------

type loopCheckInput struct {
	Event               string
	StepUpRequired      bool
	OperatorHalt        bool
	ProviderUnavailable bool
	Limits              loopImmutableLimits
	Usage               loopUsageSnapshot
}

// ---------------------------------------------------------------------------
// Loop run record -- the persistent per-run state
// ---------------------------------------------------------------------------

// loopRunRecord is the enriched run record used by the full state machine.
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

// ---------------------------------------------------------------------------
// Loop Plane Policy Engine
// ---------------------------------------------------------------------------

// loopPlanePolicyEngine is the stateful governance engine for agent loop runs.
// It maintains a map of run records keyed by run ID and enforces the full
// governance state machine on each evaluate call.
type loopPlanePolicyEngine struct {
	mu   sync.Mutex
	runs map[string]loopRunRecord
}

// newLoopPlanePolicyEngine constructs an engine with an empty run map.
func newLoopPlanePolicyEngine() *loopPlanePolicyEngine {
	return &loopPlanePolicyEngine{
		runs: make(map[string]loopRunRecord),
	}
}

// evaluate processes a loop check request through the governance state machine.
// Returns (decision, reason, httpStatus, metadata).
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
	} else if !loopImmutableLimitsEqual(record.Limits, input.Limits) {
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

	// Operator halt can arrive from any non-terminal state.
	if input.OperatorHalt || input.Event == "operator_halt" {
		record.State = loopStateHaltedOperator
		record.HaltReason = ReasonLoopHaltOperator
		p.runs[req.Envelope.RunID] = record
		return DecisionDeny, ReasonLoopHaltOperator, httpStatusConflict, loopMetadata(record, req.Envelope.RunID, "operator_halt")
	}

	// Provider unavailable from any non-terminal state.
	if input.ProviderUnavailable || input.Event == "provider_unavailable" {
		record.State = loopStateHaltedProviderUnavailable
		record.HaltReason = ReasonLoopHaltProviderUnavailable
		p.runs[req.Envelope.RunID] = record
		return DecisionDeny, ReasonLoopHaltProviderUnavailable, httpStatusBadGateway, loopMetadata(record, req.Envelope.RunID, "provider_unavailable")
	}

	// Step-up / approval required.
	if input.StepUpRequired || input.Event == "approval_required" {
		record.State = loopStateWaitingApproval
		p.runs[req.Envelope.RunID] = record
		return DecisionStepUp, ReasonLoopStepUpRequired, httpStatusAccepted, loopMetadata(record, req.Envelope.RunID, "waiting_approval")
	}

	// Approval granted: transition from WAITING_APPROVAL back to RUNNING.
	if input.Event == "approval_granted" && record.State == loopStateWaitingApproval {
		record.State = loopStateRunning
	}

	// Budget and policy limit checks.
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

	// Completion event.
	if input.Event == "complete" {
		record.State = loopStateCompleted
		p.runs[req.Envelope.RunID] = record
		return DecisionAllow, ReasonLoopCompleted, 200, loopMetadata(record, req.Envelope.RunID, "run_completed")
	}

	// Default: running boundary check.
	record.State = loopStateRunning
	p.runs[req.Envelope.RunID] = record
	return DecisionAllow, ReasonLoopAllow, 200, loopMetadata(record, req.Envelope.RunID, "run_running")
}

// listRuns returns a snapshot of all run records sorted by UpdatedAt descending.
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

// getRun retrieves a single run record by ID.
func (p *loopPlanePolicyEngine) getRun(runID string) (loopRunRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.runs[runID]
	return r, ok
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Numeric parsing helpers
// ---------------------------------------------------------------------------

func parsePositiveInt(obj map[string]any, key string) int {
	v := getIntAttr(obj, key, 0)
	if v < 0 {
		return 0
	}
	return v
}

func parsePositiveFloat(obj map[string]any, key string) float64 {
	v := getFloatAttr(obj, key, 0)
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
	v := getFloatAttr(obj, key, 0)
	if v < 0 {
		return 0
	}
	return v
}

// ---------------------------------------------------------------------------
// Limit checking and comparison
// ---------------------------------------------------------------------------

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

func loopImmutableLimitsEqual(a, b loopImmutableLimits) bool {
	return a.MaxSteps == b.MaxSteps &&
		a.MaxToolCalls == b.MaxToolCalls &&
		a.MaxModelCalls == b.MaxModelCalls &&
		a.MaxWallTimeMS == b.MaxWallTimeMS &&
		a.MaxEgressBytes == b.MaxEgressBytes &&
		a.MaxModelCostUSD == b.MaxModelCostUSD &&
		a.MaxProviderFailovers == b.MaxProviderFailovers &&
		a.MaxRiskScore == b.MaxRiskScore
}

// ---------------------------------------------------------------------------
// Metadata generation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Terminal state check
// ---------------------------------------------------------------------------

func isLoopTerminalState(state loopRunGovernanceState) bool {
	switch state {
	case loopStateCompleted, loopStateHaltedPolicy, loopStateHaltedBudget, loopStateHaltedProviderUnavailable, loopStateHaltedOperator:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// HTTP status constants
// ---------------------------------------------------------------------------

const (
	httpStatusAccepted        = 202
	httpStatusConflict        = 409
	httpStatusForbidden       = 403
	httpStatusTooManyRequests = 429
	httpStatusBadGateway      = 502
)
