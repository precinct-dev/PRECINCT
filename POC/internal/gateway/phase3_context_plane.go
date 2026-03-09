package gateway

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type contextAdmissionInput struct {
	SegmentID               string
	Content                 string
	ScanPassed              bool
	PromptCheckPassed       bool
	PromptInjectionDetected bool
	DLPClassification       string
	ModelEgress             bool
	MemoryOperation         string
	MemoryTier              string
	Provenance              map[string]any
}

type contextAdmissionRecord struct {
	RecordID          string
	RunID             string
	SessionID         string
	Tenant            string
	SegmentID         string
	Decision          Decision
	ReasonCode        ReasonCode
	DecisionID        string
	TraceID           string
	MemoryOperation   string
	MemoryTier        string
	DLPClassification string
	Provenance        map[string]any
	RecordedAt        time.Time
}

type contextPlanePolicyEngine struct {
	mu      sync.Mutex
	records map[string]contextAdmissionRecord
}

func newContextPlanePolicyEngine() *contextPlanePolicyEngine {
	return &contextPlanePolicyEngine{
		records: make(map[string]contextAdmissionRecord),
	}
}

func (p *contextPlanePolicyEngine) evaluate(req PlaneRequestV2, decisionID, traceID string, now time.Time) (Decision, ReasonCode, int, map[string]any) {
	input, err := parseContextAdmissionInput(req.Policy.Attributes)
	if err != nil {
		decision, reason, status := DecisionDeny, ReasonContextSchemaInvalid, 400
		recordID := p.persistRecord(req.Envelope, input, decision, reason, decisionID, traceID, now)
		return decision, reason, status, map[string]any{
			"admission_record_id": recordID,
			"schema_error":        err.Error(),
			"persisted":           true,
		}
	}

	var (
		decision = DecisionAllow
		reason   = ReasonContextAllow
		status   = 200
	)

	switch {
	case !input.ScanPassed:
		decision, reason, status = DecisionDeny, ReasonContextNoScanNoSend, 403
	case !input.PromptCheckPassed || input.PromptInjectionDetected:
		decision, reason, status = DecisionDeny, ReasonContextPromptUnsafe, 403
	case input.ModelEgress && input.DLPClassification == "":
		decision, reason, status = DecisionDeny, ReasonContextDLPRequired, 403
	case input.MemoryOperation == "write" && input.MemoryTier == "long_term" && input.DLPClassification != "clean":
		decision, reason, status = DecisionDeny, ReasonContextMemoryWriteDenied, 403
	case input.MemoryOperation == "read" && input.MemoryTier == "regulated":
		decision, reason, status = DecisionStepUp, ReasonContextMemoryReadStepUp, 202
	case input.ModelEgress && (input.DLPClassification == "pii" || input.DLPClassification == "phi" || input.DLPClassification == "sensitive"):
		decision, reason, status = DecisionDeny, ReasonContextDLPDenied, 403
	}

	recordID := p.persistRecord(req.Envelope, input, decision, reason, decisionID, traceID, now)
	return decision, reason, status, map[string]any{
		"segment_id":          input.SegmentID,
		"memory_operation":    input.MemoryOperation,
		"memory_tier":         input.MemoryTier,
		"dlp_classification":  input.DLPClassification,
		"admission_record_id": recordID,
		"provenance":          input.Provenance,
		"persisted":           true,
	}
}

func (p *contextPlanePolicyEngine) persistRecord(
	envelope RunEnvelope,
	input contextAdmissionInput,
	decision Decision,
	reason ReasonCode,
	decisionID, traceID string,
	now time.Time,
) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	recordID := strings.Join([]string{
		envelope.Tenant,
		envelope.RunID,
		input.SegmentID,
		strconv.FormatInt(now.UnixNano(), 10),
	}, ":")
	p.records[recordID] = contextAdmissionRecord{
		RecordID:          recordID,
		RunID:             envelope.RunID,
		SessionID:         envelope.SessionID,
		Tenant:            envelope.Tenant,
		SegmentID:         input.SegmentID,
		Decision:          decision,
		ReasonCode:        reason,
		DecisionID:        decisionID,
		TraceID:           traceID,
		MemoryOperation:   input.MemoryOperation,
		MemoryTier:        input.MemoryTier,
		DLPClassification: input.DLPClassification,
		Provenance:        input.Provenance,
		RecordedAt:        now,
	}
	return recordID
}

func parseContextAdmissionInput(attrs map[string]any) (contextAdmissionInput, error) {
	if attrs == nil {
		return contextAdmissionInput{}, fmt.Errorf("attributes are required")
	}

	segmentID := strings.TrimSpace(getStringAttr(attrs, "segment_id", ""))
	if segmentID == "" {
		return contextAdmissionInput{}, fmt.Errorf("segment_id is required")
	}
	content := strings.TrimSpace(getStringAttr(attrs, "content", ""))
	if content == "" {
		return contextAdmissionInput{}, fmt.Errorf("content is required")
	}
	scanPassed, ok := parseRequiredBool(attrs, "scan_passed")
	if !ok {
		return contextAdmissionInput{}, fmt.Errorf("scan_passed is required")
	}
	promptChecked, ok := parseRequiredBool(attrs, "prompt_check_passed")
	if !ok {
		return contextAdmissionInput{}, fmt.Errorf("prompt_check_passed is required")
	}

	dlpClassification, ok := parseOptionalString(attrs, "dlp_classification")
	if ok {
		dlpClassification = strings.ToLower(strings.TrimSpace(dlpClassification))
	}

	memoryOperation := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "memory_operation", "none")))
	switch memoryOperation {
	case "none", "read", "write":
	default:
		return contextAdmissionInput{}, fmt.Errorf("memory_operation must be one of none/read/write")
	}

	memoryTier := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "memory_tier", "session")))
	switch memoryTier {
	case "ephemeral", "session", "long_term", "regulated":
	default:
		return contextAdmissionInput{}, fmt.Errorf("memory_tier must be one of ephemeral/session/long_term/regulated")
	}

	provenanceRaw, ok := attrs["provenance"]
	if !ok {
		return contextAdmissionInput{}, fmt.Errorf("provenance is required")
	}
	provenance, ok := provenanceRaw.(map[string]any)
	if !ok || len(provenance) == 0 {
		return contextAdmissionInput{}, fmt.Errorf("provenance must be a non-empty object")
	}

	return contextAdmissionInput{
		SegmentID:               segmentID,
		Content:                 content,
		ScanPassed:              scanPassed,
		PromptCheckPassed:       promptChecked,
		PromptInjectionDetected: getBoolAttr(attrs, "prompt_injection_detected", false),
		DLPClassification:       dlpClassification,
		ModelEgress:             getBoolAttr(attrs, "model_egress", true),
		MemoryOperation:         memoryOperation,
		MemoryTier:              memoryTier,
		Provenance:              provenance,
	}, nil
}

func parseRequiredBool(attrs map[string]any, key string) (bool, bool) {
	raw, ok := attrs[key]
	if !ok {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return false, false
		}
		return parsed, true
	default:
		return false, false
	}
}

func parseOptionalString(attrs map[string]any, key string) (string, bool) {
	raw, ok := attrs[key]
	if !ok {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		return v, true
	default:
		// Preserve compatibility for scalar connectors by stringifying.
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v), true
		}
		return strings.Trim(string(b), "\""), true
	}
}
