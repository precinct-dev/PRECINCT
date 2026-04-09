// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// MinApprovalSigningKeyLength defines the minimum key length required for
	// strict profile startup conformance checks.
	MinApprovalSigningKeyLength = 32
)

var (
	ErrApprovalRequestNotFound  = errors.New("approval request not found")
	ErrApprovalInvalidState     = errors.New("approval request is not in a valid state for this operation")
	ErrApprovalTokenInvalid     = errors.New("approval capability token is invalid")
	ErrApprovalTokenExpired     = errors.New("approval capability token is expired")
	ErrApprovalTokenConsumed    = errors.New("approval capability token already consumed")
	ErrApprovalScopeMismatch    = errors.New("approval capability scope mismatch")
	ErrApprovalIdentityMismatch = errors.New("approval capability identity mismatch")
)

type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusGranted  ApprovalStatus = "granted"
	ApprovalStatusDenied   ApprovalStatus = "denied"
	ApprovalStatusConsumed ApprovalStatus = "consumed"
	ApprovalStatusExpired  ApprovalStatus = "expired"
)

// ApprovalScope defines the identity and operation scope bound to a capability.
type ApprovalScope struct {
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	ActorSPIFFEID string `json:"actor_spiffe_id"`
	SessionID     string `json:"session_id"`
}

type ApprovalRequestInput struct {
	Scope       ApprovalScope `json:"scope"`
	RequestedBy string        `json:"requested_by,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	TTLSeconds  int           `json:"ttl_seconds,omitempty"`
}

type ApprovalGrantInput struct {
	RequestID  string `json:"request_id"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type ApprovalDenyInput struct {
	RequestID string `json:"request_id"`
	DeniedBy  string `json:"denied_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type ApprovalConsumeInput struct {
	Token string        `json:"capability_token"`
	Scope ApprovalScope `json:"scope"`
}

type ApprovalRequestRecord struct {
	RequestID      string         `json:"request_id"`
	Status         ApprovalStatus `json:"status"`
	Scope          ApprovalScope  `json:"scope"`
	RequestedBy    string         `json:"requested_by,omitempty"`
	RequestedAt    time.Time      `json:"requested_at"`
	Reason         string         `json:"reason,omitempty"`
	TTLSeconds     int            `json:"ttl_seconds"`
	ExpiresAt      time.Time      `json:"expires_at"`
	DecisionBy     string         `json:"decision_by,omitempty"`
	DecisionReason string         `json:"decision_reason,omitempty"`
	DecisionAt     *time.Time     `json:"decision_at,omitempty"`
	ConsumedAt     *time.Time     `json:"consumed_at,omitempty"`
	Nonce          string         `json:"nonce,omitempty"`
}

type ApprovalCapabilityClaims struct {
	RequestID     string    `json:"request_id"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource"`
	ActorSPIFFEID string    `json:"actor_spiffe_id"`
	SessionID     string    `json:"session_id"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Nonce         string    `json:"nonce"`
}

type ApprovalGrantResult struct {
	Record ApprovalRequestRecord    `json:"record"`
	Token  string                   `json:"capability_token"`
	Claims ApprovalCapabilityClaims `json:"claims"`
}

// ApprovalCapabilityVerifier is consumed by step-up gating so high-risk operations
// can validate and consume bounded approval tokens.
type ApprovalCapabilityVerifier interface {
	ValidateAndConsume(token string, expected ApprovalScope) (*ApprovalCapabilityClaims, error)
}

type approvalTokenPayload struct {
	Version       string `json:"v"`
	RequestID     string `json:"rid"`
	Action        string `json:"act"`
	Resource      string `json:"res"`
	ActorSPIFFEID string `json:"sub"`
	SessionID     string `json:"sid"`
	IssuedAtUnix  int64  `json:"iat"`
	ExpiresAtUnix int64  `json:"exp"`
	Nonce         string `json:"jti"`
}

// ApprovalCapabilityService issues and validates bounded approval capabilities.
// Tokens are signed (HMAC-SHA256), actor/session/action scoped, short-lived,
// and one-time consumable.
type ApprovalCapabilityService struct {
	mu         sync.Mutex
	signingKey []byte
	defaultTTL time.Duration
	maxTTL     time.Duration
	now        func() time.Time
	auditor    *Auditor

	requests      map[string]ApprovalRequestRecord
	consumedNonce map[string]time.Time
	distributed   approvalDistributedStore
}

var weakApprovalSigningKeyValues = map[string]struct{}{
	"changeme":                           {},
	"change-me":                          {},
	"default":                            {},
	"dev":                                {},
	"test":                               {},
	"poc-approval-signing-key-change-me": {},
	"poc_approval_signing_key_change_me": {},
}

// IsApprovalSigningKeyStrong applies baseline checks used by strict startup
// profile validation. Dev profiles may still run with generated ephemeral keys.
func IsApprovalSigningKeyStrong(signingKey string) bool {
	key := strings.TrimSpace(signingKey)
	if len(key) < MinApprovalSigningKeyLength {
		return false
	}
	if _, weak := weakApprovalSigningKeyValues[strings.ToLower(key)]; weak {
		return false
	}
	return true
}

func buildEphemeralApprovalSigningKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		return []byte(base64.RawURLEncoding.EncodeToString(key))
	}
	// Best-effort non-static fallback if entropy source is unavailable.
	return []byte(uuid.NewString() + uuid.NewString())
}

// ErrApprovalSigningKeyRequired is returned when NewApprovalCapabilityService
// is called with an empty signing key under a production enforcement profile.
var ErrApprovalSigningKeyRequired = errors.New("APPROVAL_SIGNING_KEY is required in production profiles")

// isProductionProfile returns true for enforcement profiles that require a
// pre-configured (non-ephemeral) approval signing key.
func isProductionProfile(profile string) bool {
	p := strings.ToLower(strings.TrimSpace(profile))
	return p == "prod" || p == "prod_standard" || p == "prod_regulated_hipaa"
}

func NewApprovalCapabilityService(signingKey string, defaultTTL, maxTTL time.Duration, auditor *Auditor, profile string) (*ApprovalCapabilityService, error) {
	key := strings.TrimSpace(signingKey)
	if key == "" {
		if isProductionProfile(profile) {
			return nil, fmt.Errorf("%w (profile=%s)", ErrApprovalSigningKeyRequired, strings.TrimSpace(profile))
		}
		// Dev-bounded fallback: generate an ephemeral process-local key rather
		// than using a static default.
		log.Printf("[WARN] Using ephemeral approval signing key -- tokens will not survive restart or work across instances")
		key = string(buildEphemeralApprovalSigningKey())
	}
	if defaultTTL <= 0 {
		defaultTTL = 10 * time.Minute
	}
	if maxTTL <= 0 {
		maxTTL = time.Hour
	}
	if defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}

	return &ApprovalCapabilityService{
		signingKey:    []byte(key),
		defaultTTL:    defaultTTL,
		maxTTL:        maxTTL,
		now:           time.Now,
		auditor:       auditor,
		requests:      make(map[string]ApprovalRequestRecord),
		consumedNonce: make(map[string]time.Time),
	}, nil
}

func (s *ApprovalCapabilityService) CreateRequest(input ApprovalRequestInput) (ApprovalRequestRecord, error) {
	scope, err := normalizeScope(input.Scope)
	if err != nil {
		return ApprovalRequestRecord{}, err
	}

	now := s.nowUTC()
	ttl := s.defaultTTL
	if input.TTLSeconds > 0 {
		ttl = time.Duration(input.TTLSeconds) * time.Second
	}
	if ttl <= 0 || ttl > s.maxTTL {
		return ApprovalRequestRecord{}, fmt.Errorf("ttl_seconds must be between 1 and %d", int(s.maxTTL.Seconds()))
	}

	record := ApprovalRequestRecord{
		RequestID:   "apr-" + uuid.NewString(),
		Status:      ApprovalStatusPending,
		Scope:       scope,
		RequestedBy: strings.TrimSpace(input.RequestedBy),
		RequestedAt: now,
		Reason:      strings.TrimSpace(input.Reason),
		TTLSeconds:  int(ttl.Seconds()),
		ExpiresAt:   now.Add(ttl),
	}

	if s.distributed != nil {
		if err := s.distributed.PutRequest(context.Background(), record); err != nil {
			return ApprovalRequestRecord{}, err
		}
	} else {
		s.mu.Lock()
		s.requests[record.RequestID] = record
		s.mu.Unlock()
	}

	s.logEvent("approval.request", record.Scope.SessionID, record.Scope.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s action=%s resource=%s requested_by=%s ttl_seconds=%d", record.RequestID, record.Scope.Action, record.Scope.Resource, record.RequestedBy, record.TTLSeconds), 200)
	return record, nil
}

func (s *ApprovalCapabilityService) GrantRequest(input ApprovalGrantInput) (ApprovalGrantResult, error) {
	requestID := strings.TrimSpace(input.RequestID)
	approvedBy := strings.TrimSpace(input.ApprovedBy)
	reason := strings.TrimSpace(input.Reason)

	record, ok, err := s.loadRequestRecord(requestID)
	if err != nil {
		return ApprovalGrantResult{}, err
	}
	if !ok {
		return ApprovalGrantResult{}, ErrApprovalRequestNotFound
	}
	if record.Status != ApprovalStatusPending {
		return ApprovalGrantResult{}, ErrApprovalInvalidState
	}

	now := s.nowUTC()
	if now.After(record.ExpiresAt) {
		record.Status = ApprovalStatusExpired
		if err := s.persistRequestRecord(record); err != nil {
			return ApprovalGrantResult{}, err
		}
		s.logEvent("approval.expire", record.Scope.SessionID, record.Scope.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s status=expired", record.RequestID), 410)
		return ApprovalGrantResult{}, ErrApprovalTokenExpired
	}

	tokenPayload := approvalTokenPayload{
		Version:       "ap1",
		RequestID:     record.RequestID,
		Action:        record.Scope.Action,
		Resource:      record.Scope.Resource,
		ActorSPIFFEID: record.Scope.ActorSPIFFEID,
		SessionID:     record.Scope.SessionID,
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: record.ExpiresAt.Unix(),
		Nonce:         uuid.NewString(),
	}
	token, err := s.mintToken(tokenPayload)
	if err != nil {
		return ApprovalGrantResult{}, err
	}

	record.Status = ApprovalStatusGranted
	record.DecisionBy = approvedBy
	record.DecisionReason = reason
	record.Nonce = tokenPayload.Nonce
	decisionAt := now
	record.DecisionAt = &decisionAt
	if err := s.persistRequestRecord(record); err != nil {
		return ApprovalGrantResult{}, err
	}

	claims := approvalTokenPayloadToClaims(tokenPayload)
	s.logEvent("approval.grant", record.Scope.SessionID, record.Scope.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s approved_by=%s reason=%s nonce=%s", record.RequestID, approvedBy, reason, tokenPayload.Nonce), 200)
	return ApprovalGrantResult{
		Record: cloneApprovalRecord(record),
		Token:  token,
		Claims: claims,
	}, nil
}

func (s *ApprovalCapabilityService) DenyRequest(input ApprovalDenyInput) (ApprovalRequestRecord, error) {
	requestID := strings.TrimSpace(input.RequestID)
	deniedBy := strings.TrimSpace(input.DeniedBy)
	reason := strings.TrimSpace(input.Reason)

	record, ok, err := s.loadRequestRecord(requestID)
	if err != nil {
		return ApprovalRequestRecord{}, err
	}
	if !ok {
		return ApprovalRequestRecord{}, ErrApprovalRequestNotFound
	}
	if record.Status != ApprovalStatusPending {
		return ApprovalRequestRecord{}, ErrApprovalInvalidState
	}

	now := s.nowUTC()
	if now.After(record.ExpiresAt) {
		record.Status = ApprovalStatusExpired
		if err := s.persistRequestRecord(record); err != nil {
			return ApprovalRequestRecord{}, err
		}
		s.logEvent("approval.expire", record.Scope.SessionID, record.Scope.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s status=expired", record.RequestID), 410)
		return ApprovalRequestRecord{}, ErrApprovalTokenExpired
	}

	record.Status = ApprovalStatusDenied
	record.DecisionBy = deniedBy
	record.DecisionReason = reason
	decisionAt := now
	record.DecisionAt = &decisionAt
	if err := s.persistRequestRecord(record); err != nil {
		return ApprovalRequestRecord{}, err
	}

	s.logEvent("approval.deny", record.Scope.SessionID, record.Scope.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s denied_by=%s reason=%s", record.RequestID, deniedBy, reason), 200)
	return cloneApprovalRecord(record), nil
}

func (s *ApprovalCapabilityService) GetRequest(requestID string) (ApprovalRequestRecord, bool) {
	record, ok, err := s.loadRequestRecord(strings.TrimSpace(requestID))
	if err != nil {
		return ApprovalRequestRecord{}, false
	}
	if !ok {
		return ApprovalRequestRecord{}, false
	}
	return cloneApprovalRecord(record), true
}

func (s *ApprovalCapabilityService) ValidateAndConsume(token string, expected ApprovalScope) (*ApprovalCapabilityClaims, error) {
	normalizedExpected, err := normalizePartialScope(expected)
	if err != nil {
		return nil, err
	}

	payload, err := s.parseAndVerifyToken(token)
	if err != nil {
		return nil, err
	}

	now := s.nowUTC()
	if now.Unix() > payload.ExpiresAtUnix {
		s.expireIfKnown(payload.RequestID)
		s.logEvent("approval.expire", payload.SessionID, payload.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s nonce=%s", payload.RequestID, payload.Nonce), 410)
		return nil, ErrApprovalTokenExpired
	}

	if normalizedExpected.Action != "" && normalizedExpected.Action != payload.Action {
		return nil, ErrApprovalScopeMismatch
	}
	if normalizedExpected.Resource != "" && normalizedExpected.Resource != payload.Resource {
		return nil, ErrApprovalScopeMismatch
	}
	if normalizedExpected.ActorSPIFFEID != "" && normalizedExpected.ActorSPIFFEID != payload.ActorSPIFFEID {
		return nil, ErrApprovalIdentityMismatch
	}
	if normalizedExpected.SessionID != "" && normalizedExpected.SessionID != payload.SessionID {
		return nil, ErrApprovalScopeMismatch
	}

	if s.distributed != nil {
		consumed, markErr := s.distributed.MarkNonceConsumed(context.Background(), payload.Nonce, time.Unix(payload.ExpiresAtUnix, 0).UTC())
		if markErr != nil {
			return nil, markErr
		}
		if !consumed {
			return nil, ErrApprovalTokenConsumed
		}
		record, ok, loadErr := s.loadRequestRecord(payload.RequestID)
		if loadErr != nil {
			return nil, loadErr
		}
		if ok {
			record.Status = ApprovalStatusConsumed
			consumedAt := now
			record.ConsumedAt = &consumedAt
			if persistErr := s.persistRequestRecord(record); persistErr != nil {
				return nil, persistErr
			}
		}
	} else {
		s.mu.Lock()
		if _, consumed := s.consumedNonce[payload.Nonce]; consumed {
			s.mu.Unlock()
			return nil, ErrApprovalTokenConsumed
		}
		s.consumedNonce[payload.Nonce] = now

		record, ok := s.requests[payload.RequestID]
		if ok {
			record.Status = ApprovalStatusConsumed
			consumedAt := now
			record.ConsumedAt = &consumedAt
			s.requests[payload.RequestID] = record
		}
		s.mu.Unlock()
	}

	claims := approvalTokenPayloadToClaims(payload)
	s.logEvent("approval.consume", payload.SessionID, payload.ActorSPIFFEID, "", fmt.Sprintf("request_id=%s action=%s resource=%s nonce=%s", payload.RequestID, payload.Action, payload.Resource, payload.Nonce), 200)
	return &claims, nil
}

func (s *ApprovalCapabilityService) mintToken(payload approvalTokenPayload) (string, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal approval token: %w", err)
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(rawPayload)
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte(payloadPart))
	signature := mac.Sum(nil)
	sigPart := base64.RawURLEncoding.EncodeToString(signature)
	return payloadPart + "." + sigPart, nil
}

func (s *ApprovalCapabilityService) parseAndVerifyToken(token string) (approvalTokenPayload, error) {
	raw := strings.TrimSpace(token)
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return approvalTokenPayload{}, ErrApprovalTokenInvalid
	}
	payloadPart := parts[0]
	sigPart := parts[1]

	gotSig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return approvalTokenPayload{}, ErrApprovalTokenInvalid
	}
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte(payloadPart))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(gotSig, expectedSig) {
		return approvalTokenPayload{}, ErrApprovalTokenInvalid
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return approvalTokenPayload{}, ErrApprovalTokenInvalid
	}
	var payload approvalTokenPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return approvalTokenPayload{}, ErrApprovalTokenInvalid
	}
	if payload.Version != "ap1" || strings.TrimSpace(payload.RequestID) == "" || strings.TrimSpace(payload.Nonce) == "" {
		return approvalTokenPayload{}, ErrApprovalTokenInvalid
	}
	return payload, nil
}

func (s *ApprovalCapabilityService) expireIfKnown(requestID string) {
	record, ok, err := s.loadRequestRecord(requestID)
	if err != nil || !ok {
		return
	}
	if record.Status == ApprovalStatusConsumed || record.Status == ApprovalStatusDenied {
		return
	}
	record.Status = ApprovalStatusExpired
	_ = s.persistRequestRecord(record)
}

func (s *ApprovalCapabilityService) loadRequestRecord(requestID string) (ApprovalRequestRecord, bool, error) {
	if s.distributed != nil {
		return s.distributed.GetRequest(context.Background(), strings.TrimSpace(requestID))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.requests[strings.TrimSpace(requestID)]
	if !ok {
		return ApprovalRequestRecord{}, false, nil
	}
	return record, true, nil
}

func (s *ApprovalCapabilityService) persistRequestRecord(record ApprovalRequestRecord) error {
	if s.distributed != nil {
		return s.distributed.PutRequest(context.Background(), record)
	}
	s.mu.Lock()
	s.requests[record.RequestID] = record
	s.mu.Unlock()
	return nil
}

func (s *ApprovalCapabilityService) logEvent(action, sessionID, spiffeID, decisionID, result string, statusCode int) {
	if s == nil || s.auditor == nil {
		return
	}
	s.auditor.Log(AuditEvent{
		SessionID:  sessionID,
		DecisionID: decisionID,
		TraceID:    "",
		SPIFFEID:   spiffeID,
		Action:     action,
		Result:     result,
		Method:     "",
		Path:       "",
		StatusCode: statusCode,
	})
}

func (s *ApprovalCapabilityService) nowUTC() time.Time {
	return s.now().UTC()
}

func normalizeScope(scope ApprovalScope) (ApprovalScope, error) {
	scope.Action = strings.TrimSpace(scope.Action)
	scope.Resource = strings.TrimSpace(scope.Resource)
	scope.ActorSPIFFEID = strings.TrimSpace(scope.ActorSPIFFEID)
	scope.SessionID = strings.TrimSpace(scope.SessionID)
	if scope.Action == "" {
		return ApprovalScope{}, fmt.Errorf("scope.action is required")
	}
	if scope.Resource == "" {
		return ApprovalScope{}, fmt.Errorf("scope.resource is required")
	}
	if scope.ActorSPIFFEID == "" {
		return ApprovalScope{}, fmt.Errorf("scope.actor_spiffe_id is required")
	}
	if scope.SessionID == "" {
		return ApprovalScope{}, fmt.Errorf("scope.session_id is required")
	}
	return scope, nil
}

func normalizePartialScope(scope ApprovalScope) (ApprovalScope, error) {
	scope.Action = strings.TrimSpace(scope.Action)
	scope.Resource = strings.TrimSpace(scope.Resource)
	scope.ActorSPIFFEID = strings.TrimSpace(scope.ActorSPIFFEID)
	scope.SessionID = strings.TrimSpace(scope.SessionID)
	return scope, nil
}

func approvalTokenPayloadToClaims(payload approvalTokenPayload) ApprovalCapabilityClaims {
	return ApprovalCapabilityClaims{
		RequestID:     payload.RequestID,
		Action:        payload.Action,
		Resource:      payload.Resource,
		ActorSPIFFEID: payload.ActorSPIFFEID,
		SessionID:     payload.SessionID,
		IssuedAt:      time.Unix(payload.IssuedAtUnix, 0).UTC(),
		ExpiresAt:     time.Unix(payload.ExpiresAtUnix, 0).UTC(),
		Nonce:         payload.Nonce,
	}
}

func cloneApprovalRecord(record ApprovalRequestRecord) ApprovalRequestRecord {
	out := record
	if record.DecisionAt != nil {
		decision := *record.DecisionAt
		out.DecisionAt = &decision
	}
	if record.ConsumedAt != nil {
		consumed := *record.ConsumedAt
		out.ConsumedAt = &consumed
	}
	return out
}
