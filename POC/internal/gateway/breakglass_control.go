package gateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/google/uuid"
)

var (
	errBreakGlassNotFound       = errors.New("break-glass request not found")
	errBreakGlassInvalidState   = errors.New("break-glass request is not in a valid state for this operation")
	errBreakGlassDualAuthNeeded = errors.New("break-glass activation requires two distinct approvals")
)

type breakGlassStatus string

const (
	breakGlassStatusPending  breakGlassStatus = "pending"
	breakGlassStatusApproved breakGlassStatus = "approved"
	breakGlassStatusActive   breakGlassStatus = "active"
	breakGlassStatusReverted breakGlassStatus = "reverted"
	breakGlassStatusExpired  breakGlassStatus = "expired"
)

type breakGlassScope struct {
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	ActorSPIFFEID string `json:"actor_spiffe_id"`
}

type breakGlassRequestInput struct {
	IncidentID  string          `json:"incident_id"`
	Scope       breakGlassScope `json:"scope"`
	RequestedBy string          `json:"requested_by,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	TTLSeconds  int             `json:"ttl_seconds,omitempty"`
}

type breakGlassApprovalInput struct {
	RequestID  string `json:"request_id"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type breakGlassActivateInput struct {
	RequestID   string `json:"request_id"`
	ActivatedBy string `json:"activated_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type breakGlassRevertInput struct {
	RequestID  string `json:"request_id"`
	RevertedBy string `json:"reverted_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type breakGlassRecord struct {
	RequestID         string           `json:"request_id"`
	IncidentID        string           `json:"incident_id"`
	Status            breakGlassStatus `json:"status"`
	Scope             breakGlassScope  `json:"scope"`
	RequestedBy       string           `json:"requested_by,omitempty"`
	RequestedReason   string           `json:"requested_reason,omitempty"`
	RequestedAt       time.Time        `json:"requested_at"`
	TTLSeconds        int              `json:"ttl_seconds"`
	Approvers         []string         `json:"approvers,omitempty"`
	ApprovalReason    string           `json:"approval_reason,omitempty"`
	ActivatedBy       string           `json:"activated_by,omitempty"`
	ActivationReason  string           `json:"activation_reason,omitempty"`
	ActivatedAt       *time.Time       `json:"activated_at,omitempty"`
	ExpiresAt         *time.Time       `json:"expires_at,omitempty"`
	RevertedBy        string           `json:"reverted_by,omitempty"`
	RevertReason      string           `json:"revert_reason,omitempty"`
	RevertedAt        *time.Time       `json:"reverted_at,omitempty"`
	ElevatedAuditFlag bool             `json:"elevated_audit"`
}

type breakGlassManager struct {
	mu         sync.Mutex
	now        func() time.Time
	defaultTTL time.Duration
	maxTTL     time.Duration
	auditor    *middleware.Auditor

	requests    map[string]breakGlassRecord
	distributed breakGlassDistributedStore
}

func newBreakGlassManager(auditor *middleware.Auditor) *breakGlassManager {
	return &breakGlassManager{
		now:        time.Now,
		defaultTTL: 15 * time.Minute,
		maxTTL:     2 * time.Hour,
		auditor:    auditor,
		requests:   make(map[string]breakGlassRecord),
	}
}

func (m *breakGlassManager) enableDistributedState(store breakGlassDistributedStore) {
	m.distributed = store
}

func (m *breakGlassManager) request(input breakGlassRequestInput) (breakGlassRecord, error) {
	scope, err := normalizeBreakGlassScope(input.Scope)
	if err != nil {
		return breakGlassRecord{}, err
	}
	incidentID := strings.TrimSpace(input.IncidentID)
	if incidentID == "" {
		return breakGlassRecord{}, fmt.Errorf("incident_id is required")
	}
	requestedBy := strings.TrimSpace(input.RequestedBy)
	if requestedBy == "" {
		requestedBy = scope.ActorSPIFFEID
	}

	ttl := m.defaultTTL
	if input.TTLSeconds > 0 {
		ttl = time.Duration(input.TTLSeconds) * time.Second
	}
	if ttl <= 0 || ttl > m.maxTTL {
		return breakGlassRecord{}, fmt.Errorf("ttl_seconds must be between 1 and %d", int(m.maxTTL.Seconds()))
	}

	now := m.nowUTC()
	record := breakGlassRecord{
		RequestID:         "bg-" + uuid.NewString(),
		IncidentID:        incidentID,
		Status:            breakGlassStatusPending,
		Scope:             scope,
		RequestedBy:       requestedBy,
		RequestedReason:   strings.TrimSpace(input.Reason),
		RequestedAt:       now,
		TTLSeconds:        int(ttl.Seconds()),
		ElevatedAuditFlag: true,
	}

	if err := m.persistRecord(record); err != nil {
		return breakGlassRecord{}, err
	}

	m.logEvent("breakglass.request", record, fmt.Sprintf("incident_id=%s request_id=%s elevated_audit=true", record.IncidentID, record.RequestID), 200)
	return record, nil
}

func (m *breakGlassManager) approve(input breakGlassApprovalInput) (breakGlassRecord, error) {
	requestID := strings.TrimSpace(input.RequestID)
	approvedBy := strings.TrimSpace(input.ApprovedBy)
	if approvedBy == "" {
		return breakGlassRecord{}, fmt.Errorf("approved_by is required")
	}

	record, ok, err := m.loadRecord(requestID)
	if err != nil {
		return breakGlassRecord{}, err
	}
	if !ok {
		return breakGlassRecord{}, errBreakGlassNotFound
	}
	if record.Status == breakGlassStatusReverted || record.Status == breakGlassStatusExpired {
		return breakGlassRecord{}, errBreakGlassInvalidState
	}
	if record.Status == breakGlassStatusActive {
		return breakGlassRecord{}, errBreakGlassInvalidState
	}
	if !slices.Contains(record.Approvers, approvedBy) {
		record.Approvers = append(record.Approvers, approvedBy)
	}
	record.ApprovalReason = strings.TrimSpace(input.Reason)
	if len(record.Approvers) >= 2 {
		record.Status = breakGlassStatusApproved
	} else {
		record.Status = breakGlassStatusPending
	}
	if err := m.persistRecord(record); err != nil {
		return breakGlassRecord{}, err
	}

	m.logEvent("breakglass.approve", record, fmt.Sprintf("incident_id=%s request_id=%s approved_by=%s approval_count=%d elevated_audit=true", record.IncidentID, record.RequestID, approvedBy, len(record.Approvers)), 200)
	return cloneBreakGlassRecord(record), nil
}

func (m *breakGlassManager) activate(input breakGlassActivateInput) (breakGlassRecord, error) {
	requestID := strings.TrimSpace(input.RequestID)
	activatedBy := strings.TrimSpace(input.ActivatedBy)
	if activatedBy == "" {
		return breakGlassRecord{}, fmt.Errorf("activated_by is required")
	}

	now := m.nowUTC()

	record, ok, err := m.loadRecord(requestID)
	if err != nil {
		return breakGlassRecord{}, err
	}
	if !ok {
		return breakGlassRecord{}, errBreakGlassNotFound
	}
	if record.Status == breakGlassStatusActive {
		return cloneBreakGlassRecord(record), nil
	}
	if record.Status == breakGlassStatusReverted || record.Status == breakGlassStatusExpired {
		return breakGlassRecord{}, errBreakGlassInvalidState
	}
	if len(record.Approvers) < 2 {
		return breakGlassRecord{}, errBreakGlassDualAuthNeeded
	}

	activatedAt := now
	expiresAt := now.Add(time.Duration(record.TTLSeconds) * time.Second)
	record.Status = breakGlassStatusActive
	record.ActivatedBy = activatedBy
	record.ActivationReason = strings.TrimSpace(input.Reason)
	record.ActivatedAt = &activatedAt
	record.ExpiresAt = &expiresAt
	if err := m.persistRecord(record); err != nil {
		return breakGlassRecord{}, err
	}

	m.logEvent("breakglass.activate", record, fmt.Sprintf("incident_id=%s request_id=%s activated_by=%s expires_at=%s elevated_audit=true", record.IncidentID, record.RequestID, activatedBy, expiresAt.Format(time.RFC3339)), 200)
	return cloneBreakGlassRecord(record), nil
}

func (m *breakGlassManager) revert(input breakGlassRevertInput) (breakGlassRecord, error) {
	requestID := strings.TrimSpace(input.RequestID)
	revertedBy := strings.TrimSpace(input.RevertedBy)
	if revertedBy == "" {
		return breakGlassRecord{}, fmt.Errorf("reverted_by is required")
	}

	now := m.nowUTC()

	record, ok, err := m.loadRecord(requestID)
	if err != nil {
		return breakGlassRecord{}, err
	}
	if !ok {
		return breakGlassRecord{}, errBreakGlassNotFound
	}
	if record.Status != breakGlassStatusActive {
		return breakGlassRecord{}, errBreakGlassInvalidState
	}

	revertedAt := now
	record.Status = breakGlassStatusReverted
	record.RevertedBy = revertedBy
	record.RevertReason = strings.TrimSpace(input.Reason)
	record.RevertedAt = &revertedAt
	if err := m.persistRecord(record); err != nil {
		return breakGlassRecord{}, err
	}

	m.logEvent("breakglass.revert", record, fmt.Sprintf("incident_id=%s request_id=%s reverted_by=%s elevated_audit=true", record.IncidentID, record.RequestID, revertedBy), 200)
	return cloneBreakGlassRecord(record), nil
}

func (m *breakGlassManager) activeOverride(scope breakGlassScope) (breakGlassRecord, bool) {
	scope.Action = strings.TrimSpace(scope.Action)
	scope.Resource = strings.TrimSpace(scope.Resource)
	scope.ActorSPIFFEID = strings.TrimSpace(scope.ActorSPIFFEID)

	now := m.nowUTC()

	records, err := m.listRecords()
	if err != nil {
		return breakGlassRecord{}, false
	}
	for _, record := range records {
		if record.Status != breakGlassStatusActive {
			continue
		}
		if record.ExpiresAt != nil && now.After(*record.ExpiresAt) {
			record.Status = breakGlassStatusExpired
			_ = m.persistRecord(record)
			m.logEvent("breakglass.expire", record, fmt.Sprintf("incident_id=%s request_id=%s elevated_audit=true", record.IncidentID, record.RequestID), 410)
			continue
		}
		if breakGlassScopeMatches(record.Scope, scope) {
			return cloneBreakGlassRecord(record), true
		}
	}
	return breakGlassRecord{}, false
}

func (m *breakGlassManager) get(requestID string) (breakGlassRecord, bool) {
	record, ok, err := m.loadRecord(strings.TrimSpace(requestID))
	if err != nil {
		return breakGlassRecord{}, false
	}
	if !ok {
		return breakGlassRecord{}, false
	}
	return cloneBreakGlassRecord(record), true
}

func (m *breakGlassManager) list() []breakGlassRecord {
	records, err := m.listRecords()
	if err != nil {
		return nil
	}
	out := make([]breakGlassRecord, 0, len(records))
	for _, record := range records {
		out = append(out, cloneBreakGlassRecord(record))
	}
	slices.SortFunc(out, func(a, b breakGlassRecord) int {
		return a.RequestedAt.Compare(b.RequestedAt)
	})
	return out
}

func (m *breakGlassManager) nowUTC() time.Time {
	return m.now().UTC()
}

func (m *breakGlassManager) loadRecord(requestID string) (breakGlassRecord, bool, error) {
	if m.distributed != nil {
		return m.distributed.Get(context.Background(), strings.TrimSpace(requestID))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.requests[strings.TrimSpace(requestID)]
	if !ok {
		return breakGlassRecord{}, false, nil
	}
	return record, true, nil
}

func (m *breakGlassManager) persistRecord(record breakGlassRecord) error {
	if m.distributed != nil {
		return m.distributed.Put(context.Background(), record)
	}
	m.mu.Lock()
	m.requests[record.RequestID] = record
	m.mu.Unlock()
	return nil
}

func (m *breakGlassManager) listRecords() ([]breakGlassRecord, error) {
	if m.distributed != nil {
		return m.distributed.List(context.Background())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]breakGlassRecord, 0, len(m.requests))
	for _, record := range m.requests {
		out = append(out, cloneBreakGlassRecord(record))
	}
	return out, nil
}

func (m *breakGlassManager) logEvent(action string, record breakGlassRecord, result string, statusCode int) {
	if m == nil || m.auditor == nil {
		return
	}
	m.auditor.Log(middleware.AuditEvent{
		SessionID:  "",
		DecisionID: "",
		TraceID:    "",
		SPIFFEID:   record.Scope.ActorSPIFFEID,
		Action:     action,
		Result:     result,
		StatusCode: statusCode,
	})
}

func normalizeBreakGlassScope(scope breakGlassScope) (breakGlassScope, error) {
	scope.Action = strings.TrimSpace(scope.Action)
	scope.Resource = strings.TrimSpace(scope.Resource)
	scope.ActorSPIFFEID = strings.TrimSpace(scope.ActorSPIFFEID)
	if scope.Action == "" {
		return breakGlassScope{}, fmt.Errorf("scope.action is required")
	}
	if scope.Resource == "" {
		return breakGlassScope{}, fmt.Errorf("scope.resource is required")
	}
	if scope.ActorSPIFFEID == "" {
		return breakGlassScope{}, fmt.Errorf("scope.actor_spiffe_id is required")
	}
	return scope, nil
}

func breakGlassScopeMatches(configured, candidate breakGlassScope) bool {
	return scopeFieldMatches(configured.Action, candidate.Action) &&
		scopeFieldMatches(configured.Resource, candidate.Resource) &&
		scopeFieldMatches(configured.ActorSPIFFEID, candidate.ActorSPIFFEID)
}

func scopeFieldMatches(configured, actual string) bool {
	configured = strings.TrimSpace(configured)
	actual = strings.TrimSpace(actual)
	if configured == "*" {
		return true
	}
	return configured == actual
}

func cloneBreakGlassRecord(record breakGlassRecord) breakGlassRecord {
	out := record
	if record.Approvers != nil {
		out.Approvers = append([]string{}, record.Approvers...)
	}
	if record.ActivatedAt != nil {
		at := *record.ActivatedAt
		out.ActivatedAt = &at
	}
	if record.ExpiresAt != nil {
		exp := *record.ExpiresAt
		out.ExpiresAt = &exp
	}
	if record.RevertedAt != nil {
		rev := *record.RevertedAt
		out.RevertedAt = &rev
	}
	return out
}
