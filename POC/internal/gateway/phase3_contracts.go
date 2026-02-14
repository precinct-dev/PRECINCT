package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Plane identifies the governed control plane a request belongs to.
type Plane string

const (
	PlaneIngress Plane = "ingress"
	PlaneModel   Plane = "model"
	PlaneContext Plane = "context"
	PlaneLoop    Plane = "loop"
	PlaneTool    Plane = "tool"
)

// Decision indicates the control-plane decision result.
type Decision string

const (
	DecisionAllow      Decision = "allow"
	DecisionDeny       Decision = "deny"
	DecisionQuarantine Decision = "quarantine"
	DecisionStepUp     Decision = "step_up"
)

// ReasonCode is the normalized reason taxonomy for Phase 3 plane decisions.
type ReasonCode string

const (
	ReasonIngressAllow                  ReasonCode = "INGRESS_ALLOW"
	ReasonIngressSchemaInvalid          ReasonCode = "INGRESS_SCHEMA_INVALID"
	ReasonIngressReplayDetected         ReasonCode = "INGRESS_REPLAY_DETECTED"
	ReasonIngressFreshnessStale         ReasonCode = "INGRESS_FRESHNESS_STALE"
	ReasonIngressSourceUnauth           ReasonCode = "INGRESS_SOURCE_UNAUTHENTICATED"
	ReasonIngressStepUpRequired         ReasonCode = "INGRESS_STEP_UP_REQUIRED"
	ReasonModelAllow                    ReasonCode = "MODEL_ALLOW"
	ReasonModelCallerUnauth             ReasonCode = "MODEL_CALLER_UNAUTHENTICATED"
	ReasonModelProviderDenied           ReasonCode = "MODEL_PROVIDER_DENIED"
	ReasonModelResidencyDenied          ReasonCode = "MODEL_PROVIDER_RESIDENCY_DENIED"
	ReasonModelRiskModeDenied           ReasonCode = "MODEL_PROVIDER_RISK_MODE_DENIED"
	ReasonModelBudgetNearLimit          ReasonCode = "MODEL_PROVIDER_BUDGET_NEAR_LIMIT"
	ReasonModelBudgetExhausted          ReasonCode = "MODEL_PROVIDER_BUDGET_EXHAUSTED"
	ReasonModelFallbackApplied          ReasonCode = "MODEL_PROVIDER_FALLBACK_APPLIED"
	ReasonModelNoFallback               ReasonCode = "MODEL_PROVIDER_DEGRADED_NO_APPROVED_FALLBACK"
	ReasonModelDirectEgressDeny         ReasonCode = "MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED"
	ReasonModelDestinationDenied        ReasonCode = "MODEL_PROVIDER_DESTINATION_DENIED"
	ReasonModelProviderUnavailable      ReasonCode = "MODEL_PROVIDER_UNAVAILABLE"
	ReasonModelProviderUpstreamError    ReasonCode = "MODEL_PROVIDER_UPSTREAM_ERROR"
	ReasonPromptSafetyRawDenied         ReasonCode = "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED"
	ReasonPromptSafetyRedacted          ReasonCode = "PROMPT_SAFETY_REDACTION_APPLIED"
	ReasonPromptSafetyTokenized         ReasonCode = "PROMPT_SAFETY_TOKENIZATION_APPLIED"
	ReasonPromptSafetyOverride          ReasonCode = "PROMPT_SAFETY_OVERRIDE_APPROVED"
	ReasonPromptSafetyOverrideReq       ReasonCode = "PROMPT_SAFETY_OVERRIDE_APPROVAL_REQUIRED"
	ReasonContextAllow                  ReasonCode = "CONTEXT_ALLOW"
	ReasonContextSchemaInvalid          ReasonCode = "CONTEXT_SCHEMA_INVALID"
	ReasonContextNoScanNoSend           ReasonCode = "CONTEXT_NO_SCAN_NO_SEND"
	ReasonContextPromptUnsafe           ReasonCode = "CONTEXT_PROMPT_INJECTION_UNSAFE"
	ReasonContextDLPRequired            ReasonCode = "CONTEXT_DLP_CLASSIFICATION_REQUIRED"
	ReasonContextDLPDenied              ReasonCode = "CONTEXT_DLP_CLASSIFICATION_DENIED"
	ReasonContextMemoryReadStepUp       ReasonCode = "CONTEXT_MEMORY_READ_STEP_UP_REQUIRED"
	ReasonContextMemoryWriteDenied ReasonCode = "CONTEXT_MEMORY_WRITE_DENIED"
	ReasonLoopAllow               ReasonCode = "LOOP_ALLOW"
	ReasonLoopSchemaInvalid             ReasonCode = "LOOP_SCHEMA_INVALID"
	ReasonLoopLimitsImmutableViolation  ReasonCode = "LOOP_LIMITS_IMMUTABLE_VIOLATION"
	ReasonLoopHaltMaxSteps              ReasonCode = "LOOP_HALT_MAX_STEPS"
	ReasonLoopHaltMaxToolCalls          ReasonCode = "LOOP_HALT_MAX_TOOL_CALLS"
	ReasonLoopHaltMaxModelCalls         ReasonCode = "LOOP_HALT_MAX_MODEL_CALLS"
	ReasonLoopHaltMaxWallTime           ReasonCode = "LOOP_HALT_MAX_WALL_TIME"
	ReasonLoopHaltMaxEgressBytes        ReasonCode = "LOOP_HALT_MAX_EGRESS_BYTES"
	ReasonLoopHaltMaxModelCost          ReasonCode = "LOOP_HALT_MAX_MODEL_COST"
	ReasonLoopHaltMaxProviderFailovers  ReasonCode = "LOOP_HALT_MAX_PROVIDER_FAILOVERS"
	ReasonLoopHaltRiskScore             ReasonCode = "LOOP_HALT_MAX_RISK_SCORE"
	ReasonLoopHaltProviderUnavailable   ReasonCode = "LOOP_HALT_PROVIDER_UNAVAILABLE"
	ReasonLoopHaltOperator              ReasonCode = "LOOP_HALT_OPERATOR"
	ReasonLoopStepUpRequired            ReasonCode = "LOOP_STEP_UP_REQUIRED"
	ReasonLoopCompleted                 ReasonCode = "LOOP_COMPLETED"
	ReasonLoopRunAlreadyTerminated      ReasonCode = "LOOP_RUN_ALREADY_TERMINATED"
	ReasonToolAllow                     ReasonCode = "TOOL_ALLOW"
	ReasonToolSchemaInvalid             ReasonCode = "TOOL_SCHEMA_INVALID"
	ReasonToolCapabilityDenied          ReasonCode = "TOOL_CAPABILITY_DENIED"
	ReasonToolAdapterUnsupported        ReasonCode = "TOOL_ADAPTER_UNSUPPORTED"
	ReasonToolActionDenied              ReasonCode = "TOOL_ACTION_DENIED"
	ReasonToolCLICommandDenied          ReasonCode = "TOOL_CLI_COMMAND_DENIED"
	ReasonToolCLIArgsDenied             ReasonCode = "TOOL_CLI_ARGS_DENIED"
	ReasonToolStepUpRequired            ReasonCode = "TOOL_STEP_UP_REQUIRED"
	ReasonRLMAllow                      ReasonCode = "RLM_ALLOW"
	ReasonRLMSchemaInvalid              ReasonCode = "RLM_SCHEMA_INVALID"
	ReasonRLMBypassDenied               ReasonCode = "RLM_BYPASS_DENIED"
	ReasonRLMHaltMaxDepth               ReasonCode = "RLM_HALT_MAX_DEPTH"
	ReasonRLMHaltMaxSubcalls            ReasonCode = "RLM_HALT_MAX_SUBCALLS"
	ReasonRLMHaltMaxBudget              ReasonCode = "RLM_HALT_MAX_SUBCALL_BUDGET"
	ReasonContractInvalid               ReasonCode = "CONTRACT_INVALID"
	ReasonContractPlaneMismatch         ReasonCode = "CONTRACT_PLANE_MISMATCH"
)

// RunEnvelope captures the common run/session metadata across all Phase 3 planes.
type RunEnvelope struct {
	RunID            string            `json:"run_id"`
	SessionID        string            `json:"session_id"`
	Tenant           string            `json:"tenant"`
	ActorSPIFFEID    string            `json:"actor_spiffe_id"`
	Plane            Plane             `json:"plane"`
	ExecutionMode    string            `json:"execution_mode,omitempty"`
	LineageID        string            `json:"lineage_id,omitempty"`
	ParentRunID      string            `json:"parent_run_id,omitempty"`
	ParentDecisionID string            `json:"parent_decision_id,omitempty"`
	TraceID          string            `json:"trace_id,omitempty"`
	DecisionID       string            `json:"decision_id,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// Validate checks required fields for the run envelope.
func (e RunEnvelope) Validate() error {
	if strings.TrimSpace(e.RunID) == "" {
		return errors.New("run_id is required")
	}
	if strings.TrimSpace(e.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if strings.TrimSpace(e.Tenant) == "" {
		return errors.New("tenant is required")
	}
	if strings.TrimSpace(e.ActorSPIFFEID) == "" {
		return errors.New("actor_spiffe_id is required")
	}
	switch e.Plane {
	case PlaneIngress, PlaneModel, PlaneContext, PlaneLoop, PlaneTool:
	default:
		return fmt.Errorf("unsupported plane: %q", e.Plane)
	}
	mode := strings.ToLower(strings.TrimSpace(e.ExecutionMode))
	if mode != "" && mode != "standard" && mode != "rlm" {
		return fmt.Errorf("execution_mode must be one of standard/rlm when set")
	}
	if mode == "rlm" && strings.TrimSpace(e.LineageID) == "" {
		return fmt.Errorf("lineage_id is required when execution_mode=rlm")
	}
	return nil
}

// PolicyInputV2 is the unified policy input shape for Phase 3 plane calls.
type PolicyInputV2 struct {
	Envelope   RunEnvelope    `json:"envelope"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Validate checks required fields for policy input.
func (p PolicyInputV2) Validate() error {
	if err := p.Envelope.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(p.Action) == "" {
		return errors.New("action is required")
	}
	if strings.TrimSpace(p.Resource) == "" {
		return errors.New("resource is required")
	}
	return nil
}

// PlaneRequestV2 is the baseline request contract for plane entry-point handlers.
type PlaneRequestV2 struct {
	Envelope RunEnvelope   `json:"envelope"`
	Policy   PolicyInputV2 `json:"policy"`
}

// Validate checks baseline invariants for plane request.
func (r PlaneRequestV2) Validate() error {
	if err := r.Envelope.Validate(); err != nil {
		return err
	}
	if err := r.Policy.Validate(); err != nil {
		return err
	}
	// Enforce one envelope source of truth across request wrappers.
	if !runEnvelopesEqual(r.Envelope, r.Policy.Envelope) {
		return errors.New("envelope and policy.envelope must match exactly")
	}
	return nil
}

func runEnvelopesEqual(a, b RunEnvelope) bool {
	return a.RunID == b.RunID &&
		a.SessionID == b.SessionID &&
		a.Tenant == b.Tenant &&
		a.ActorSPIFFEID == b.ActorSPIFFEID &&
		a.Plane == b.Plane &&
		a.ExecutionMode == b.ExecutionMode &&
		a.LineageID == b.LineageID &&
		a.ParentRunID == b.ParentRunID &&
		a.ParentDecisionID == b.ParentDecisionID &&
		a.TraceID == b.TraceID &&
		a.DecisionID == b.DecisionID &&
		reflect.DeepEqual(a.Metadata, b.Metadata)
}

// AuditEventV2 captures normalized audit fields for plane decision events.
type AuditEventV2 struct {
	EventType  string     `json:"event_type"`
	Plane      Plane      `json:"plane"`
	ReasonCode ReasonCode `json:"reason_code"`
	Decision   Decision   `json:"decision"`
	RunID      string     `json:"run_id"`
	SessionID  string     `json:"session_id"`
	DecisionID string     `json:"decision_id"`
	TraceID    string     `json:"trace_id"`
}

// Validate checks required fields for audit event contract.
func (a AuditEventV2) Validate() error {
	if strings.TrimSpace(a.EventType) == "" {
		return errors.New("event_type is required")
	}
	if strings.TrimSpace(a.RunID) == "" {
		return errors.New("run_id is required")
	}
	if strings.TrimSpace(a.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if strings.TrimSpace(a.DecisionID) == "" {
		return errors.New("decision_id is required")
	}
	if strings.TrimSpace(a.TraceID) == "" {
		return errors.New("trace_id is required")
	}
	switch a.Decision {
	case DecisionAllow, DecisionDeny, DecisionQuarantine, DecisionStepUp:
	default:
		return fmt.Errorf("unsupported decision: %q", a.Decision)
	}
	switch a.Plane {
	case PlaneIngress, PlaneModel, PlaneContext, PlaneLoop, PlaneTool:
	default:
		return fmt.Errorf("unsupported plane: %q", a.Plane)
	}
	return nil
}

// PlaneDecisionV2 is the baseline response contract for plane handlers.
type PlaneDecisionV2 struct {
	Decision   Decision       `json:"decision"`
	ReasonCode ReasonCode     `json:"reason_code"`
	Envelope   RunEnvelope    `json:"envelope"`
	TraceID    string         `json:"trace_id"`
	DecisionID string         `json:"decision_id"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}
