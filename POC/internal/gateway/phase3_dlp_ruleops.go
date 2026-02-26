package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

const dlpRuleOpsSignatureAlgorithm = "sha256-ruleops-v1"

type dlpRulesetState string

const (
	dlpRulesetStateDraft      dlpRulesetState = "draft"
	dlpRulesetStateValidated  dlpRulesetState = "validated"
	dlpRulesetStateApproved   dlpRulesetState = "approved"
	dlpRulesetStateSigned     dlpRulesetState = "signed"
	dlpRulesetStateCanary     dlpRulesetState = "canary"
	dlpRulesetStateActive     dlpRulesetState = "active"
	dlpRulesetStateSuperseded dlpRulesetState = "superseded"
	dlpRulesetStateRolledBack dlpRulesetState = "rolled_back"
)

type dlpRulesetRecord struct {
	RulesetID             string          `json:"ruleset_id"`
	Version               string          `json:"version"`
	Digest                string          `json:"digest"`
	Content               map[string]any  `json:"content,omitempty"`
	State                 dlpRulesetState `json:"state"`
	SignatureAlgorithm    string          `json:"signature_algorithm,omitempty"`
	Signature             string          `json:"signature,omitempty"`
	ExpectedSignature     string          `json:"expected_signature,omitempty"`
	ApprovedBy            string          `json:"approved_by,omitempty"`
	CreatedBy             string          `json:"created_by,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	ApprovedAt            time.Time       `json:"approved_at,omitempty"`
	SignedAt              time.Time       `json:"signed_at,omitempty"`
	CanaryAt              time.Time       `json:"canary_at,omitempty"`
	ActivatedAt           time.Time       `json:"activated_at,omitempty"`
	RolledBackAt          time.Time       `json:"rolled_back_at,omitempty"`
	PreviousActiveRuleset string          `json:"previous_active_ruleset,omitempty"`
	RolledBackToRuleset   string          `json:"rolled_back_to_ruleset,omitempty"`
	LastOperation         string          `json:"last_operation,omitempty"`
	LastReason            string          `json:"last_reason,omitempty"`
}

type dlpRuleOpsManager struct {
	mu sync.RWMutex

	activeScanner middleware.DLPScanner
	rulesets      map[string]*dlpRulesetRecord

	activeRulesetID         string
	previousActiveRulesetID string
	canaryRulesetID         string

	version string
	digest  string
}

func newDLPRuleOpsManager() (*dlpRuleOpsManager, middleware.DLPScanner, error) {
	scanner := middleware.NewBuiltInScanner()

	version, digest := "", ""
	if mp, ok := any(scanner).(middleware.DLPScannerMetadataProvider); ok {
		version, digest = mp.ActiveRulesetMetadata()
	}
	if version == "" {
		version = "builtin"
	}
	if digest == "" {
		// Digest is best-effort; absence should not break request handling.
		digest = "unknown"
	}
	now := time.Now().UTC()
	builtinID := "builtin/v1"
	base := &dlpRulesetRecord{
		RulesetID:          builtinID,
		Version:            version,
		Digest:             digest,
		State:              dlpRulesetStateActive,
		SignatureAlgorithm: dlpRuleOpsSignatureAlgorithm,
		ApprovedBy:         "system",
		CreatedBy:          "system",
		CreatedAt:          now,
		UpdatedAt:          now,
		ApprovedAt:         now,
		SignedAt:           now,
		ActivatedAt:        now,
		LastOperation:      "bootstrap",
		LastReason:         "built-in baseline ruleset",
	}
	base.ExpectedSignature = computeDLPExpectedSignature(base)
	base.Signature = base.ExpectedSignature

	mgr := &dlpRuleOpsManager{
		activeScanner: scanner,
		rulesets: map[string]*dlpRulesetRecord{
			builtinID: base,
		},
		activeRulesetID: builtinID,
		version:         version,
		digest:          digest,
	}

	// Basic sanity to prevent nil scanner wiring.
	if mgr.activeScanner == nil {
		return nil, nil, fmt.Errorf("dlp scanner is nil")
	}
	return mgr, scanner, nil
}

func (m *dlpRuleOpsManager) ActiveRuleset() (version string, digest string) {
	if m == nil {
		return "", ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version, m.digest
}

func (m *dlpRuleOpsManager) ActiveRecord() (dlpRulesetRecord, bool) {
	if m == nil {
		return dlpRulesetRecord{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.activeRulesetID == "" {
		return dlpRulesetRecord{}, false
	}
	rec, ok := m.rulesets[m.activeRulesetID]
	if !ok {
		return dlpRulesetRecord{}, false
	}
	return cloneDLPRulesetRecord(rec), true
}

func (m *dlpRuleOpsManager) CanaryRecord() (dlpRulesetRecord, bool) {
	if m == nil {
		return dlpRulesetRecord{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.canaryRulesetID == "" {
		return dlpRulesetRecord{}, false
	}
	rec, ok := m.rulesets[m.canaryRulesetID]
	if !ok {
		return dlpRulesetRecord{}, false
	}
	return cloneDLPRulesetRecord(rec), true
}

func (m *dlpRuleOpsManager) Status(rulesetID string) (dlpRulesetRecord, bool) {
	if m == nil {
		return dlpRulesetRecord{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.rulesets[strings.TrimSpace(rulesetID)]
	if !ok {
		return dlpRulesetRecord{}, false
	}
	return cloneDLPRulesetRecord(rec), true
}

func (m *dlpRuleOpsManager) Create(rulesetID string, content map[string]any, createdBy string) (dlpRulesetRecord, error) {
	if m == nil {
		return dlpRulesetRecord{}, fmt.Errorf("ruleops manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := strings.TrimSpace(rulesetID)
	if id == "" {
		return dlpRulesetRecord{}, fmt.Errorf("ruleset_id is required")
	}
	if _, exists := m.rulesets[id]; exists {
		return dlpRulesetRecord{}, fmt.Errorf("ruleset already exists")
	}
	now := time.Now().UTC()
	rec := &dlpRulesetRecord{
		RulesetID:          id,
		Version:            id,
		Digest:             computeDLPRulesetDigest(content),
		Content:            cloneMap(content),
		State:              dlpRulesetStateDraft,
		SignatureAlgorithm: dlpRuleOpsSignatureAlgorithm,
		CreatedBy:          strings.TrimSpace(createdBy),
		CreatedAt:          now,
		UpdatedAt:          now,
		LastOperation:      "create",
		LastReason:         "ruleset draft created",
	}
	m.rulesets[id] = rec
	return cloneDLPRulesetRecord(rec), nil
}

func (m *dlpRuleOpsManager) Validate(rulesetID string) (dlpRulesetRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.requireRulesetForTransition(rulesetID, dlpRulesetStateDraft, "validate")
	if err != nil {
		return dlpRulesetRecord{}, err
	}
	if len(rec.Content) == 0 {
		return dlpRulesetRecord{}, fmt.Errorf("ruleset content is required")
	}
	rec.State = dlpRulesetStateValidated
	rec.UpdatedAt = time.Now().UTC()
	rec.LastOperation = "validate"
	rec.LastReason = "ruleset validated"
	return cloneDLPRulesetRecord(rec), nil
}

func (m *dlpRuleOpsManager) Approve(rulesetID, approvedBy string) (dlpRulesetRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.requireRulesetForTransition(rulesetID, dlpRulesetStateValidated, "approve")
	if err != nil {
		return dlpRulesetRecord{}, err
	}
	by := strings.TrimSpace(approvedBy)
	if by == "" {
		return dlpRulesetRecord{}, fmt.Errorf("approved_by is required")
	}
	now := time.Now().UTC()
	rec.State = dlpRulesetStateApproved
	rec.ApprovedBy = by
	rec.ApprovedAt = now
	rec.ExpectedSignature = computeDLPExpectedSignature(rec)
	rec.UpdatedAt = now
	rec.LastOperation = "approve"
	rec.LastReason = "ruleset approved"
	return cloneDLPRulesetRecord(rec), nil
}

func (m *dlpRuleOpsManager) Sign(rulesetID, signature string) (dlpRulesetRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.requireRulesetForTransition(rulesetID, dlpRulesetStateApproved, "sign")
	if err != nil {
		return dlpRulesetRecord{}, err
	}
	sig := strings.TrimSpace(signature)
	if sig == "" {
		return dlpRulesetRecord{}, fmt.Errorf("signature is required")
	}
	if rec.ExpectedSignature == "" {
		rec.ExpectedSignature = computeDLPExpectedSignature(rec)
	}
	if sig != rec.ExpectedSignature {
		return dlpRulesetRecord{}, fmt.Errorf("signature mismatch")
	}
	now := time.Now().UTC()
	rec.State = dlpRulesetStateSigned
	rec.Signature = sig
	rec.SignedAt = now
	rec.UpdatedAt = now
	rec.LastOperation = "sign"
	rec.LastReason = "ruleset signed"
	return cloneDLPRulesetRecord(rec), nil
}

func (m *dlpRuleOpsManager) Promote(rulesetID, mode string) (dlpRulesetRecord, error) {
	if m == nil {
		return dlpRulesetRecord{}, fmt.Errorf("ruleops manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := strings.TrimSpace(rulesetID)
	rec, ok := m.rulesets[id]
	if !ok {
		return dlpRulesetRecord{}, fmt.Errorf("ruleset not found")
	}
	if err := enforceDLPPromotionConstraints(rec); err != nil {
		return dlpRulesetRecord{}, err
	}
	now := time.Now().UTC()
	targetMode := strings.ToLower(strings.TrimSpace(mode))
	if targetMode == "" {
		targetMode = "active"
	}

	switch targetMode {
	case "canary":
		if rec.State != dlpRulesetStateSigned {
			return dlpRulesetRecord{}, fmt.Errorf("invalid transition: %s -> canary", rec.State)
		}
		rec.State = dlpRulesetStateCanary
		rec.CanaryAt = now
		rec.UpdatedAt = now
		rec.LastOperation = "promote_canary"
		rec.LastReason = "ruleset promoted to canary"
		m.canaryRulesetID = id
		return cloneDLPRulesetRecord(rec), nil
	case "active":
		if rec.State != dlpRulesetStateSigned && rec.State != dlpRulesetStateCanary {
			return dlpRulesetRecord{}, fmt.Errorf("invalid transition: %s -> active", rec.State)
		}
		if m.activeRulesetID != "" && m.activeRulesetID != id {
			if prev, ok := m.rulesets[m.activeRulesetID]; ok {
				prev.State = dlpRulesetStateSuperseded
				prev.UpdatedAt = now
				prev.LastOperation = "supersede"
				prev.LastReason = "superseded by promoted ruleset"
			}
			m.previousActiveRulesetID = m.activeRulesetID
			rec.PreviousActiveRuleset = m.activeRulesetID
		}
		rec.State = dlpRulesetStateActive
		rec.ActivatedAt = now
		rec.UpdatedAt = now
		rec.LastOperation = "promote_active"
		rec.LastReason = "ruleset promoted to active"
		m.activeRulesetID = id
		m.canaryRulesetID = ""
		m.version = rec.Version
		m.digest = rec.Digest
		return cloneDLPRulesetRecord(rec), nil
	default:
		return dlpRulesetRecord{}, fmt.Errorf("invalid promote mode: %s", targetMode)
	}
}

func (m *dlpRuleOpsManager) Rollback(rulesetID string) (dlpRulesetRecord, error) {
	if m == nil {
		return dlpRulesetRecord{}, fmt.Errorf("ruleops manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	targetID := strings.TrimSpace(rulesetID)

	if targetID == "" && m.canaryRulesetID != "" {
		targetID = m.canaryRulesetID
	}
	if targetID != "" && targetID == m.canaryRulesetID {
		canary, ok := m.rulesets[targetID]
		if !ok {
			return dlpRulesetRecord{}, fmt.Errorf("ruleset not found")
		}
		canary.State = dlpRulesetStateRolledBack
		canary.RolledBackAt = now
		canary.RolledBackToRuleset = m.activeRulesetID
		canary.UpdatedAt = now
		canary.LastOperation = "rollback_canary"
		canary.LastReason = "canary rolled back"
		m.canaryRulesetID = ""
		return cloneDLPRulesetRecord(canary), nil
	}

	if targetID == "" {
		targetID = m.activeRulesetID
	}
	current, ok := m.rulesets[targetID]
	if !ok {
		return dlpRulesetRecord{}, fmt.Errorf("ruleset not found")
	}
	if current.State != dlpRulesetStateActive {
		return dlpRulesetRecord{}, fmt.Errorf("invalid transition: %s -> rolled_back", current.State)
	}
	if m.previousActiveRulesetID == "" {
		return dlpRulesetRecord{}, fmt.Errorf("no previous active ruleset available for rollback")
	}
	prev, ok := m.rulesets[m.previousActiveRulesetID]
	if !ok {
		return dlpRulesetRecord{}, fmt.Errorf("previous active ruleset not found")
	}

	current.State = dlpRulesetStateRolledBack
	current.RolledBackAt = now
	current.RolledBackToRuleset = prev.RulesetID
	current.UpdatedAt = now
	current.LastOperation = "rollback_active"
	current.LastReason = "active ruleset rolled back"

	prev.State = dlpRulesetStateActive
	prev.UpdatedAt = now
	prev.LastOperation = "restore_active"
	prev.LastReason = "restored by rollback"

	m.activeRulesetID = prev.RulesetID
	m.previousActiveRulesetID = ""
	m.canaryRulesetID = ""
	m.version = prev.Version
	m.digest = prev.Digest

	return cloneDLPRulesetRecord(current), nil
}

func (m *dlpRuleOpsManager) requireRulesetForTransition(rulesetID string, expected dlpRulesetState, target string) (*dlpRulesetRecord, error) {
	if m == nil {
		return nil, fmt.Errorf("ruleops manager unavailable")
	}
	rec, ok := m.rulesets[strings.TrimSpace(rulesetID)]
	if !ok {
		return nil, fmt.Errorf("ruleset not found")
	}
	if rec.State != expected {
		return nil, fmt.Errorf("invalid transition: %s -> %s", rec.State, target)
	}
	return rec, nil
}

func enforceDLPPromotionConstraints(rec *dlpRulesetRecord) error {
	if rec == nil {
		return fmt.Errorf("ruleset not found")
	}
	if strings.TrimSpace(rec.ApprovedBy) == "" || rec.ApprovedAt.IsZero() {
		return fmt.Errorf("approval required before promotion")
	}
	if strings.TrimSpace(rec.Signature) == "" {
		return fmt.Errorf("signature required before promotion")
	}
	expected := rec.ExpectedSignature
	if expected == "" {
		expected = computeDLPExpectedSignature(rec)
	}
	if rec.Signature != expected {
		return fmt.Errorf("signature invalid for promotion")
	}
	return nil
}

func computeDLPRulesetDigest(content map[string]any) string {
	payload := cloneMap(content)
	if payload == nil {
		payload = map[string]any{}
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func computeDLPExpectedSignature(rec *dlpRulesetRecord) string {
	if rec == nil {
		return ""
	}
	signedPayload := map[string]any{
		"algorithm":   dlpRuleOpsSignatureAlgorithm,
		"approved_at": rec.ApprovedAt.UTC().Format(time.RFC3339),
		"approved_by": strings.TrimSpace(rec.ApprovedBy),
		"digest":      strings.TrimSpace(rec.Digest),
		"ruleset_id":  strings.TrimSpace(rec.RulesetID),
	}
	raw, _ := json.Marshal(signedPayload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloneDLPRulesetRecord(in *dlpRulesetRecord) dlpRulesetRecord {
	if in == nil {
		return dlpRulesetRecord{}
	}
	out := *in
	out.Content = cloneMap(in.Content)
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}
