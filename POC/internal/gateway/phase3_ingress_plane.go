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

type ingressNonceRecord struct {
	SeenAt time.Time
}

type ingressPlanePolicyEngine struct {
	mu         sync.Mutex
	nonceTTL   time.Duration
	freshness  time.Duration
	seenNonces map[string]ingressNonceRecord
}

func newIngressPlanePolicyEngine() *ingressPlanePolicyEngine {
	return &ingressPlanePolicyEngine{
		nonceTTL:   30 * time.Minute,
		freshness:  10 * time.Minute,
		seenNonces: make(map[string]ingressNonceRecord),
	}
}

func (p *ingressPlanePolicyEngine) evaluate(req PlaneRequestV2, now time.Time) (Decision, ReasonCode, int, map[string]any) {
	envelope, err := parseIngressCanonicalEnvelope(req.Policy.Attributes)
	if err != nil {
		return DecisionDeny, ReasonIngressSchemaInvalid, 400, map[string]any{
			"schema_error": err.Error(),
		}
	}

	if strings.TrimSpace(envelope.SourcePrincipal) != strings.TrimSpace(req.Envelope.ActorSPIFFEID) {
		return DecisionDeny, ReasonIngressSourceUnauth, 401, map[string]any{
			"source_principal": envelope.SourcePrincipal,
			"actor_spiffe_id":  req.Envelope.ActorSPIFFEID,
		}
	}

	if envelope.RequiresStepUp {
		return DecisionStepUp, ReasonIngressStepUpRequired, 202, map[string]any{
			"connector_type": envelope.ConnectorType,
			"source_id":      envelope.SourceID,
			"event_id":       envelope.EventID,
		}
	}

	if now.Sub(envelope.EventTimestamp) > p.freshness || envelope.EventTimestamp.Sub(now) > p.freshness {
		return DecisionQuarantine, ReasonIngressFreshnessStale, 202, map[string]any{
			"connector_type": envelope.ConnectorType,
			"event_id":       envelope.EventID,
			"event_time":     envelope.EventTimestamp.UTC().Format(time.RFC3339),
		}
	}

	if p.isReplayAndRecord(req.Envelope.Tenant, envelope, now) {
		return DecisionDeny, ReasonIngressReplayDetected, 409, map[string]any{
			"connector_type": envelope.ConnectorType,
			"event_id":       envelope.EventID,
			"nonce":          envelope.Nonce,
		}
	}

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

func (p *ingressPlanePolicyEngine) isReplayAndRecord(tenant string, envelope ingressCanonicalEnvelope, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

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
