// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ingressCanonicalEnvelope represents the structured envelope parsed from
// ingress plane attributes when connector_type, source_id, source_principal,
// event_id, nonce, event_timestamp, and payload are all present.
type ingressCanonicalEnvelope struct {
	ConnectorType   string
	SourceID        string
	SourcePrincipal string
	EventID         string
	Nonce           string
	EventTimestamp  time.Time
	Payload         any
	RequiresStepUp  bool
}

// ingressNonceRecord tracks when a composite nonce key was first observed.
type ingressNonceRecord struct {
	SeenAt time.Time
}

// ingressPlanePolicyEngine provides canonical connector envelope validation,
// source principal matching, SHA256 payload content-addressing, and structured
// replay detection with nonce TTL.
type ingressPlanePolicyEngine struct {
	mu         sync.Mutex
	nonceTTL   time.Duration
	freshness  time.Duration
	seenNonces map[string]ingressNonceRecord
}

// newIngressPlanePolicyEngine creates an engine with 30-minute nonce TTL and
// 10-minute freshness window (past and future).
func newIngressPlanePolicyEngine() *ingressPlanePolicyEngine {
	return &ingressPlanePolicyEngine{
		nonceTTL:   30 * time.Minute,
		freshness:  10 * time.Minute,
		seenNonces: make(map[string]ingressNonceRecord),
	}
}

// evaluate validates a canonical ingress envelope against the policy engine rules.
// Returns (Decision, ReasonCode, httpStatus, metadata).
//
// Evaluation order:
//  1. Schema validation (connector_type, source_id, source_principal, event_id, nonce, event_timestamp, payload)
//  2. Source principal authentication (must match ActorSPIFFEID)
//  3. Step-up requirement check
//  4. Freshness check (10min past/future window)
//  5. Replay detection (composite key with 30min TTL)
//  6. Allow with SHA256 payload content-addressing
func (p *ingressPlanePolicyEngine) evaluate(req PlaneRequestV2, now time.Time) (Decision, ReasonCode, int, map[string]any) {
	envelope, err := parseIngressCanonicalEnvelope(req.Policy.Attributes)
	if err != nil {
		return DecisionDeny, ReasonIngressSchemaInvalid, 400, map[string]any{
			"schema_error": err.Error(),
		}
	}

	// AC2: source_principal must match ActorSPIFFEID.
	if strings.TrimSpace(envelope.SourcePrincipal) != strings.TrimSpace(req.Envelope.ActorSPIFFEID) {
		return DecisionDeny, ReasonIngressSourceUnauth, 401, map[string]any{
			"source_principal": envelope.SourcePrincipal,
			"actor_spiffe_id":  req.Envelope.ActorSPIFFEID,
		}
	}

	// AC6: requires_step_up=true yields DecisionStepUp.
	if envelope.RequiresStepUp {
		return DecisionStepUp, ReasonIngressStepUpRequired, 202, map[string]any{
			"connector_type": envelope.ConnectorType,
			"source_id":      envelope.SourceID,
			"event_id":       envelope.EventID,
		}
	}

	// AC5: freshness window is 10min past and 10min future.
	if now.Sub(envelope.EventTimestamp) > p.freshness || envelope.EventTimestamp.Sub(now) > p.freshness {
		return DecisionQuarantine, ReasonIngressFreshnessStale, 202, map[string]any{
			"connector_type": envelope.ConnectorType,
			"event_id":       envelope.EventID,
			"event_time":     envelope.EventTimestamp.UTC().Format(time.RFC3339),
		}
	}

	// AC4: replay detection with composite key and 30min TTL.
	if p.isReplayAndRecord(req.Envelope.Tenant, envelope, now) {
		return DecisionDeny, ReasonIngressReplayDetected, 409, map[string]any{
			"connector_type": envelope.ConnectorType,
			"event_id":       envelope.EventID,
			"nonce":          envelope.Nonce,
		}
	}

	// AC3 + AC7: SHA256 content-addressing and allow metadata.
	payloadRef, payloadSize := ingressPayloadRef(envelope.Payload)
	return DecisionAllow, ReasonIngressAllow, 200, map[string]any{
		"connector_type":       envelope.ConnectorType,
		"source_id":            envelope.SourceID,
		"event_id":             envelope.EventID,
		"payload_ref":          payloadRef,
		"payload_size_bytes":   payloadSize,
		"raw_payload_stripped": true,
	}
}

// isReplayAndRecord checks whether the composite nonce key has been seen within
// the TTL window. If not, it records the key. Old entries are evicted on each call.
func (p *ingressPlanePolicyEngine) isReplayAndRecord(tenant string, envelope ingressCanonicalEnvelope, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Evict expired nonces.
	for key, rec := range p.seenNonces {
		if now.Sub(rec.SeenAt) > p.nonceTTL {
			delete(p.seenNonces, key)
		}
	}

	key := strings.Join([]string{
		tenant,
		envelope.ConnectorType,
		envelope.SourceID,
		envelope.EventID,
		envelope.Nonce,
	}, "|")
	if rec, ok := p.seenNonces[key]; ok {
		if now.Sub(rec.SeenAt) <= p.nonceTTL {
			return true
		}
	}
	p.seenNonces[key] = ingressNonceRecord{SeenAt: now}
	return false
}

// hasCanonicalEnvelopeFields returns true when the attributes contain the full
// set of fields required for canonical envelope parsing: connector_type, source_id,
// nonce, and payload. This is the detection heuristic used by handleIngressAdmit
// to decide whether to delegate to the policy engine.
func hasCanonicalEnvelopeFields(attrs map[string]any) bool {
	if attrs == nil {
		return false
	}
	for _, key := range []string{"connector_type", "source_id", "nonce", "payload"} {
		if _, ok := attrs[key]; !ok {
			return false
		}
	}
	return true
}

// parseIngressCanonicalEnvelope validates and extracts the structured envelope
// from ingress plane attributes. Returns an error when any required field is
// missing or malformed.
//
// Required fields: connector_type (webhook|queue), source_id, source_principal,
// event_id, nonce, event_timestamp (RFC3339 or unix seconds), payload.
// Optional: requires_step_up (bool, defaults to false).
func parseIngressCanonicalEnvelope(attrs map[string]any) (ingressCanonicalEnvelope, error) {
	if attrs == nil {
		return ingressCanonicalEnvelope{}, fmt.Errorf("attributes are required")
	}

	connector := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "connector_type", "")))
	if connector != "webhook" && connector != "queue" {
		return ingressCanonicalEnvelope{}, fmt.Errorf("connector_type must be webhook or queue")
	}

	sourceID := strings.TrimSpace(getStringAttr(attrs, "source_id", ""))
	if sourceID == "" {
		return ingressCanonicalEnvelope{}, fmt.Errorf("source_id is required")
	}
	sourcePrincipal := strings.TrimSpace(getStringAttr(attrs, "source_principal", ""))
	if sourcePrincipal == "" {
		return ingressCanonicalEnvelope{}, fmt.Errorf("source_principal is required")
	}
	eventID := strings.TrimSpace(getStringAttr(attrs, "event_id", ""))
	if eventID == "" {
		return ingressCanonicalEnvelope{}, fmt.Errorf("event_id is required")
	}
	nonce := strings.TrimSpace(getStringAttr(attrs, "nonce", ""))
	if nonce == "" {
		return ingressCanonicalEnvelope{}, fmt.Errorf("nonce is required")
	}

	eventTimestamp, err := parseIngressTimestamp(attrs["event_timestamp"])
	if err != nil {
		return ingressCanonicalEnvelope{}, err
	}

	payload, ok := attrs["payload"]
	if !ok {
		return ingressCanonicalEnvelope{}, fmt.Errorf("payload is required")
	}

	return ingressCanonicalEnvelope{
		ConnectorType:   connector,
		SourceID:        sourceID,
		SourcePrincipal: sourcePrincipal,
		EventID:         eventID,
		Nonce:           nonce,
		EventTimestamp:  eventTimestamp,
		Payload:         payload,
		RequiresStepUp:  getBoolAttr(attrs, "requires_step_up", false),
	}, nil
}

// parseIngressTimestamp parses event_timestamp from multiple formats:
// - RFC3339 string (e.g. "2024-01-15T10:30:00Z")
// - float64, int, int64 unix seconds (from JSON number deserialization)
// - Stringified unix timestamp for connector compatibility
func parseIngressTimestamp(raw any) (time.Time, error) {
	switch v := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return time.Time{}, fmt.Errorf("event_timestamp is required")
		}
		ts, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			return time.Time{}, fmt.Errorf("event_timestamp must be RFC3339: %w", err)
		}
		return ts.UTC(), nil
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	default:
		// Accept stringified unix timestamp for connector compatibility.
		s := strings.TrimSpace(fmt.Sprintf("%v", raw))
		if s == "" || s == "<nil>" {
			return time.Time{}, fmt.Errorf("event_timestamp is required")
		}
		sec, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("event_timestamp must be RFC3339 or unix seconds")
		}
		return time.Unix(sec, 0).UTC(), nil
	}
}

// ingressPayloadRef computes a deterministic SHA256 content-address for the
// payload, producing a reference in the form "ingress://payload/<hex>".
// Returns the reference string and the serialized size in bytes.
func ingressPayloadRef(payload any) (string, int) {
	raw, err := json.Marshal(payload)
	if err != nil {
		// If payload cannot be serialized, fall back to deterministic fmt string hash.
		fallback := []byte(fmt.Sprintf("%v", payload))
		sum := sha256.Sum256(fallback)
		return "ingress://payload/" + hex.EncodeToString(sum[:]), len(fallback)
	}
	sum := sha256.Sum256(raw)
	return "ingress://payload/" + hex.EncodeToString(sum[:]), len(raw)
}
