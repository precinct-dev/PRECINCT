// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xeipuuv/gojsonschema"
)

const ConnectorManifestSchemaVersion = "v1"
const ConnectorSignatureAlgorithm = "sha256-manifest-v1"

// connectorManifestSchemaV1 is the runtime validator contract used by CCA.
// The documented copy is published under contracts/v2.4/schemas.
const connectorManifestSchemaV1 = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Connector Manifest v1",
  "type": "object",
  "required": ["connector_id", "connector_type", "source_principal", "signature"],
  "properties": {
    "connector_id": {"type": "string", "minLength": 1},
    "connector_type": {"type": "string", "minLength": 1},
    "source_principal": {"type": "string", "minLength": 1},
    "version": {"type": "string"},
    "capabilities": {
      "type": "array",
      "items": {"type": "string"}
    },
    "signature": {
      "type": "object",
      "required": ["algorithm", "value"],
      "properties": {
        "algorithm": {"type": "string", "const": "sha256-manifest-v1"},
        "value": {"type": "string", "minLength": 1}
      },
      "additionalProperties": false
    },
    "metadata": {"type": "object"}
  },
  "additionalProperties": true
}`

type ConnectorState string

const (
	ConnectorStateRegistered ConnectorState = "registered"
	ConnectorStateValidated  ConnectorState = "validated"
	ConnectorStateApproved   ConnectorState = "approved"
	ConnectorStateActive     ConnectorState = "active"
	ConnectorStateRevoked    ConnectorState = "revoked"
)

type ConnectorManifestSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type ConnectorManifest struct {
	ConnectorID     string                     `json:"connector_id"`
	ConnectorType   string                     `json:"connector_type"`
	SourcePrincipal string                     `json:"source_principal"`
	Version         string                     `json:"version,omitempty"`
	Capabilities    []string                   `json:"capabilities,omitempty"`
	Signature       ConnectorManifestSignature `json:"signature"`
	Metadata        map[string]any             `json:"metadata,omitempty"`
}

type ConnectorRecord struct {
	ConnectorID     string            `json:"connector_id"`
	State           ConnectorState    `json:"state"`
	Manifest        ConnectorManifest `json:"manifest"`
	SchemaVersion   string            `json:"schema_version"`
	ExpectedSig     string            `json:"expected_signature"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	LastDecisionID  string            `json:"last_decision_id,omitempty"`
	LastTraceID     string            `json:"last_trace_id,omitempty"`
	LastReason      string            `json:"last_reason,omitempty"`
	LastOperation   string            `json:"last_operation,omitempty"`
	LastValidatedAt time.Time         `json:"last_validated_at,omitempty"`
}

type ConnectorConformanceAuthority struct {
	mu         sync.RWMutex
	connectors map[string]*ConnectorRecord
}

func NewConnectorConformanceAuthority() *ConnectorConformanceAuthority {
	return &ConnectorConformanceAuthority{connectors: map[string]*ConnectorRecord{}}
}

func ValidateConnectorManifestSchema(manifest ConnectorManifest) error {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	schemaLoader := gojsonschema.NewStringLoader(connectorManifestSchemaV1)
	docLoader := gojsonschema.NewBytesLoader(raw)
	result, err := gojsonschema.Validate(schemaLoader, docLoader)
	if err != nil {
		return fmt.Errorf("schema validate failed: %w", err)
	}
	if result.Valid() {
		return nil
	}
	errParts := make([]string, 0, len(result.Errors()))
	for _, e := range result.Errors() {
		errParts = append(errParts, e.String())
	}
	sort.Strings(errParts)
	return fmt.Errorf("schema invalid: %s", strings.Join(errParts, "; "))
}

func ComputeConnectorExpectedSignature(manifest ConnectorManifest) string {
	caps := append([]string(nil), manifest.Capabilities...)
	sort.Strings(caps)
	canon := map[string]any{
		"connector_id":     strings.TrimSpace(manifest.ConnectorID),
		"connector_type":   strings.TrimSpace(manifest.ConnectorType),
		"source_principal": strings.TrimSpace(manifest.SourcePrincipal),
		"version":          strings.TrimSpace(manifest.Version),
		"capabilities":     caps,
	}
	payload, _ := json.Marshal(canon)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func (c *ConnectorConformanceAuthority) Register(manifest ConnectorManifest) (ConnectorRecord, error) {
	if strings.TrimSpace(manifest.ConnectorID) == "" {
		return ConnectorRecord{}, fmt.Errorf("connector_id is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	expected := ComputeConnectorExpectedSignature(manifest)
	rec, ok := c.connectors[manifest.ConnectorID]
	if !ok {
		rec = &ConnectorRecord{
			ConnectorID:   manifest.ConnectorID,
			CreatedAt:     now,
			SchemaVersion: ConnectorManifestSchemaVersion,
		}
		c.connectors[manifest.ConnectorID] = rec
	}
	rec.Manifest = manifest
	rec.ExpectedSig = expected
	rec.State = ConnectorStateRegistered
	rec.UpdatedAt = now
	rec.LastOperation = "register"
	rec.LastReason = "connector registered"
	return *rec, nil
}

func (c *ConnectorConformanceAuthority) Validate(connectorID string) (ConnectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return ConnectorRecord{}, fmt.Errorf("connector not found")
	}
	if rec.State != ConnectorStateRegistered {
		return ConnectorRecord{}, fmt.Errorf("invalid transition: %s -> validated", rec.State)
	}
	if err := ValidateConnectorManifestSchema(rec.Manifest); err != nil {
		rec.LastOperation = "validate"
		rec.LastReason = err.Error()
		rec.UpdatedAt = time.Now().UTC()
		return ConnectorRecord{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(rec.Manifest.Signature.Algorithm), ConnectorSignatureAlgorithm) {
		rec.LastOperation = "validate"
		rec.LastReason = "invalid signature algorithm"
		rec.UpdatedAt = time.Now().UTC()
		return ConnectorRecord{}, fmt.Errorf("invalid signature algorithm")
	}
	expected := ComputeConnectorExpectedSignature(rec.Manifest)
	if rec.Manifest.Signature.Value != expected {
		rec.LastOperation = "validate"
		rec.LastReason = "signature mismatch"
		rec.UpdatedAt = time.Now().UTC()
		return ConnectorRecord{}, fmt.Errorf("signature mismatch")
	}
	rec.ExpectedSig = expected
	rec.State = ConnectorStateValidated
	rec.UpdatedAt = time.Now().UTC()
	rec.LastValidatedAt = rec.UpdatedAt
	rec.LastOperation = "validate"
	rec.LastReason = "connector validated"
	return *rec, nil
}

func (c *ConnectorConformanceAuthority) Approve(connectorID string) (ConnectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return ConnectorRecord{}, fmt.Errorf("connector not found")
	}
	if rec.State != ConnectorStateValidated {
		return ConnectorRecord{}, fmt.Errorf("invalid transition: %s -> approved", rec.State)
	}
	rec.State = ConnectorStateApproved
	rec.UpdatedAt = time.Now().UTC()
	rec.LastOperation = "approve"
	rec.LastReason = "connector approved"
	return *rec, nil
}

func (c *ConnectorConformanceAuthority) Activate(connectorID string) (ConnectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return ConnectorRecord{}, fmt.Errorf("connector not found")
	}
	if rec.State != ConnectorStateApproved {
		return ConnectorRecord{}, fmt.Errorf("invalid transition: %s -> active", rec.State)
	}
	rec.State = ConnectorStateActive
	rec.UpdatedAt = time.Now().UTC()
	rec.LastOperation = "activate"
	rec.LastReason = "connector active"
	return *rec, nil
}

func (c *ConnectorConformanceAuthority) Revoke(connectorID string) (ConnectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return ConnectorRecord{}, fmt.Errorf("connector not found")
	}
	switch rec.State {
	case ConnectorStateRegistered, ConnectorStateValidated, ConnectorStateApproved, ConnectorStateActive:
		rec.State = ConnectorStateRevoked
		rec.UpdatedAt = time.Now().UTC()
		rec.LastOperation = "revoke"
		rec.LastReason = "connector revoked"
		return *rec, nil
	default:
		return ConnectorRecord{}, fmt.Errorf("invalid transition: %s -> revoked", rec.State)
	}
}

func (c *ConnectorConformanceAuthority) Status(connectorID string) (ConnectorRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return ConnectorRecord{}, false
	}
	return *rec, true
}

func (c *ConnectorConformanceAuthority) UpdateAuditRef(connectorID, decisionID, traceID, reason, operation string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return
	}
	rec.LastDecisionID = decisionID
	rec.LastTraceID = traceID
	rec.LastReason = reason
	rec.LastOperation = operation
	rec.UpdatedAt = time.Now().UTC()
}

func (c *ConnectorConformanceAuthority) RuntimeCheck(connectorID, signature string) (bool, string, ConnectorRecord) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return false, "connector_not_registered", ConnectorRecord{}
	}
	if rec.State != ConnectorStateActive {
		return false, "connector_not_active", *rec
	}
	if strings.TrimSpace(signature) == "" {
		return false, "connector_signature_missing", *rec
	}
	if signature != rec.ExpectedSig {
		return false, "connector_signature_invalid", *rec
	}
	return true, "connector_active", *rec
}

func (c *ConnectorConformanceAuthority) ConformanceReport() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rows := make([]map[string]any, 0, len(c.connectors))
	for _, rec := range c.connectors {
		rows = append(rows, map[string]any{
			"connector_id":     rec.ConnectorID,
			"state":            rec.State,
			"schema_version":   rec.SchemaVersion,
			"last_operation":   rec.LastOperation,
			"last_reason":      rec.LastReason,
			"last_decision_id": rec.LastDecisionID,
			"last_trace_id":    rec.LastTraceID,
			"updated_at":       rec.UpdatedAt,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["connector_id"].(string) < rows[j]["connector_id"].(string)
	})
	return map[string]any{
		"report_type":    "connector_conformance_v1",
		"generated_at":   time.Now().UTC(),
		"schema_version": ConnectorManifestSchemaVersion,
		"connectors":     rows,
	}
}

func IsConnectorMutationPath(path string) bool {
	switch path {
	case "/v1/connectors/register",
		"/v1/connectors/validate",
		"/v1/connectors/approve",
		"/v1/connectors/activate",
		"/v1/connectors/revoke":
		return true
	default:
		return false
	}
}
