// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// AuditEvent represents a structured audit log event with hash chain
type AuditEvent struct {
	Timestamp      string         `json:"timestamp"`
	EventType      string         `json:"event_type,omitempty"` // RFA-j2d.8: UI event type (e.g., "ui.resource.read")
	Severity       string         `json:"severity,omitempty"`   // RFA-j2d.8: Info, Warning, High, Critical
	SessionID      string         `json:"session_id"`
	DecisionID     string         `json:"decision_id"`
	TraceID        string         `json:"trace_id"`
	SPIFFEID       string         `json:"spiffe_id"`
	PrincipalLevel int            `json:"principal_level"`          // OC-t7go: numeric authority level (0-5)
	PrincipalRole  string         `json:"principal_role,omitempty"` // OC-t7go: role string (system, owner, etc.)
	Action         string         `json:"action"`
	Result         string         `json:"result"`
	Method         string         `json:"method"`
	Path           string         `json:"path"`
	StatusCode     int            `json:"status_code,omitempty"`
	Security       *SecurityAudit `json:"security,omitempty"`
	Authorization  *AuthzAudit    `json:"authorization,omitempty"`
	UI             *UIAuditData   `json:"ui,omitempty"`         // RFA-j2d.8: UI-specific audit data
	AppDriven      *AppDrivenData `json:"app_driven,omitempty"` // RFA-j2d.8: app-driven tool invocation data
	PrevHash       string         `json:"prev_hash"`            // SHA-256 of previous event
	BundleDigest   string         `json:"bundle_digest"`        // SHA-256 of OPA policy bundle
	RegistryDigest string         `json:"registry_digest"`      // SHA-256 of tool registry config
}

// SecurityAudit contains security-related audit information
type SecurityAudit struct {
	ToolHashVerified      bool           `json:"tool_hash_verified"`
	SafeZoneFlags         []string       `json:"safezone_flags,omitempty"`
	FrameworkRefs         *FrameworkRefs `json:"framework_refs,omitempty"`
	ReversibilityScore    int            `json:"reversibility_score,omitempty"`    // OC-h4m7: 0-3 reversibility score
	ReversibilityCategory string         `json:"reversibility_category,omitempty"` // OC-h4m7: reversible/costly_reversible/partially_reversible/irreversible
	BackupRecommended     bool           `json:"backup_recommended,omitempty"`     // OC-lmzm: true when pre-action snapshot recommended (Score >= 2)
	EscalationScore       float64        `json:"escalation_score,omitempty"`       // OC-d77k: session cumulative escalation score
	EscalationState       string         `json:"escalation_state,omitempty"`       // OC-d77k: normal/warning/critical/emergency
}

// AuthzAudit contains authorization-related audit information
type AuthzAudit struct {
	OPADecisionID string `json:"opa_decision_id"`
	Allowed       bool   `json:"allowed"`
}

// Auditor handles audit logging with hash-chained integrity.
//
// RFA-lz1: Async audit logging. The hot path (hash chain computation) remains
// synchronous under a mutex, but file I/O and stdout logging are offloaded to
// a background goroutine via a buffered channel. This reduces per-request
// latency from ~4ms to near-zero while preserving hash chain integrity.
type Auditor struct {
	mu             sync.Mutex
	lastHash       string
	bundleDigest   string
	registryDigest string
	jsonlFile      *os.File
	jsonlPath      string

	// RFA-lz1: Async write infrastructure
	writeCh   chan []byte        // buffered channel for async file/stdout writes
	flushCh   chan chan struct{} // flush synchronization: caller sends done channel, writer closes it after draining
	done      chan struct{}      // signals the writer goroutine has finished draining
	quit      chan struct{}      // signals asyncWriter to stop accepting new events
	closeOnce sync.Once          // ensures Close() is idempotent
}

// NewAuditor creates a new auditor with hash chain support
// If jsonlPath is empty, only logs to stdout (backward compatible)
// bundlePath: path to OPA policy file (e.g., "config/opa/mcp_policy.rego")
// registryPath: path to tool registry config (e.g., "config/opa/tool_grants.yaml")
func NewAuditor(jsonlPath, bundlePath, registryPath string) (*Auditor, error) {
	// Compute bundle digest
	bundleDigest, err := computeFileDigest(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute bundle digest: %w", err)
	}

	// Compute registry digest
	registryDigest, err := computeFileDigest(registryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute registry digest: %w", err)
	}

	// Initialize with genesis hash (SHA-256 of empty string)
	genesisHash := sha256.Sum256([]byte(""))
	lastHash := hex.EncodeToString(genesisHash[:])

	auditor := &Auditor{
		lastHash:       lastHash,
		bundleDigest:   bundleDigest,
		registryDigest: registryDigest,
		jsonlPath:      jsonlPath,
		writeCh:        make(chan []byte, 4096), // RFA-lz1: buffer up to 4096 events
		flushCh:        make(chan chan struct{}, 1),
		done:           make(chan struct{}),
		quit:           make(chan struct{}),
	}

	// If jsonlPath provided, open file for appending
	if jsonlPath != "" {
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0700); err != nil {
			return nil, fmt.Errorf("failed to create audit directory: %w", err)
		}

		// Check if file exists and read last hash BEFORE opening for write
		var resumedHash string
		if info, err := os.Stat(jsonlPath); err == nil && info.Size() > 0 {
			if hash, err := readLastEventHash(jsonlPath); err == nil {
				resumedHash = hash
			}
		}

		file, err := os.OpenFile(jsonlPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit file: %w", err)
		}
		auditor.jsonlFile = file

		// Use resumed hash if we found one
		if resumedHash != "" {
			auditor.lastHash = resumedHash
		}
	}

	// RFA-lz1: Start background writer goroutine for async I/O
	go auditor.asyncWriter()

	return auditor, nil
}

// Close drains the async write channel and closes the audit file.
// It is safe to call Close() multiple times (idempotent).
func (a *Auditor) Close() error {
	var err error
	a.closeOnce.Do(func() {
		// Signal the writer goroutine to stop. The writer drains remaining
		// events from writeCh after seeing quit, then signals done.
		close(a.quit)
		// Wait for the writer goroutine to finish processing all queued events
		<-a.done
		// Now close the file
		if a.jsonlFile != nil {
			err = a.jsonlFile.Close()
		}
	})
	return err
}

// Flush blocks until all queued audit events have been written to disk.
// This is useful in tests or shutdown sequences where you need to verify
// file contents immediately after logging.
func (a *Auditor) Flush() {
	// Send a nil sentinel through the channel. When the writer processes it,
	// all events queued before Flush() have been written.
	// We use a done channel per flush to synchronize.
	flushDone := make(chan struct{})
	a.flushCh <- flushDone
	<-flushDone
}

// LastHash returns the current hash chain head under the mutex.
// This is the only safe way to read lastHash from concurrent goroutines.
func (a *Auditor) LastHash() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastHash
}

// Log emits a structured audit event with hash chain integrity.
//
// RFA-lz1: The hot path (JSON marshal + hash computation) remains synchronous
// under a mutex to preserve hash chain ordering. File I/O and stdout logging
// are offloaded to a background goroutine via a buffered channel, reducing
// per-request latency from ~4ms to near-zero.
func (a *Auditor) Log(event AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Set timestamp
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Set hash chain fields
	event.PrevHash = a.lastHash
	event.BundleDigest = a.bundleDigest
	event.RegistryDigest = a.registryDigest

	// Marshal to JSON (fast: ~1-2us)
	jsonBytes, err := json.Marshal(event)
	if err != nil {
		slog.Error("failed to marshal audit event", "error", err)
		return
	}

	// Update last hash for next event (fast: ~1us)
	// This MUST happen before releasing the mutex so the hash chain
	// remains consistent regardless of async write ordering.
	currentHash := sha256.Sum256(jsonBytes)
	a.lastHash = hex.EncodeToString(currentHash[:])

	// RFA-lz1: Send to async writer (non-blocking if channel has capacity).
	// Copy jsonBytes since the caller may reuse the underlying buffer.
	writeData := make([]byte, len(jsonBytes))
	copy(writeData, jsonBytes)

	// Use quit channel to detect if Close has been called, avoiding
	// a race between Log sending on writeCh and Close closing it.
	select {
	case <-a.quit:
		// Auditor is shutting down -- write synchronously
		a.syncWrite(writeData)
	case a.writeCh <- writeData:
		// Queued for async write
	default:
		// Channel full -- fall back to synchronous write to avoid data loss.
		a.syncWrite(writeData)
	}
}

// syncWrite performs a synchronous write to stdout and file.
// Used as fallback when the async channel is full, and by the async writer goroutine.
func (a *Auditor) syncWrite(jsonBytes []byte) {
	// Emit to stdout (backward compatible)
	log.Println(string(jsonBytes))

	// Write to JSONL file if configured
	if a.jsonlFile != nil {
		if _, err := a.jsonlFile.Write(append(jsonBytes, '\n')); err != nil {
			slog.Error("failed to write audit event to file", "error", err)
		} else {
			// Sync to disk immediately for durability
			if err := a.jsonlFile.Sync(); err != nil {
				slog.Error("failed to sync audit file", "error", err)
			}
		}
	}
}

// asyncWriter is the background goroutine that processes queued audit events.
// It reads from writeCh until quit is closed, drains remaining events from
// writeCh, then signals completion via the done channel.
func (a *Auditor) asyncWriter() {
	defer close(a.done)
	for {
		select {
		case jsonBytes := <-a.writeCh:
			a.syncWrite(jsonBytes)
		case flushDone := <-a.flushCh:
			// Drain all pending writes before signaling flush complete
			a.drainWriteCh()
			close(flushDone)
		case <-a.quit:
			// Drain remaining events from writeCh before exiting
			a.drainWriteCh()
			return
		}
	}
}

// drainWriteCh processes all currently buffered events in writeCh.
func (a *Auditor) drainWriteCh() {
	for {
		select {
		case jsonBytes := <-a.writeCh:
			a.syncWrite(jsonBytes)
		default:
			return
		}
	}
}

// computeFileDigest computes SHA-256 digest of a file
func computeFileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// readLastEventHash reads the hash of the last event from JSONL file
func readLastEventHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	var lastLine []byte
	scanner := bufio.NewScanner(file)

	// Read all lines, keeping track of the last one
	for scanner.Scan() {
		lastLine = make([]byte, len(scanner.Bytes()))
		copy(lastLine, scanner.Bytes())
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if len(lastLine) == 0 {
		return "", fmt.Errorf("no events in file")
	}

	// Compute hash of last event JSON
	hash := sha256.Sum256(lastLine)
	return hex.EncodeToString(hash[:]), nil
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(rw.ResponseWriter).Hijack()
}

func (rw *responseWriter) Flush() {
	_ = http.NewResponseController(rw.ResponseWriter).Flush()
}

// AuditLog middleware logs all requests with structured JSON
func AuditLog(next http.Handler, auditor *Auditor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for step 4
		ctx, span := tracer.Start(r.Context(), "gateway.audit_log",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 4),
				attribute.String("mcp.gateway.middleware", "audit_log"),
			),
		)
		defer span.End()

		// RFA-9i2: Create a mutable flags collector so downstream middleware
		// (DLP at step 7, deep scan at step 10) can propagate security flags
		// back to this audit middleware. Go's context.WithValue creates child
		// contexts invisible to parents, so we use a shared pointer instead.
		collector := &SecurityFlagsCollector{}
		ctx = WithFlagsCollector(ctx, collector)

		// OC-t7go: Create a mutable principal role collector so the
		// PrincipalHeaders middleware (step 3b) can propagate the resolved
		// role back to this audit middleware. Same upstream-propagation
		// pattern as SecurityFlagsCollector.
		principalCollector := &PrincipalRoleCollector{}
		ctx = WithPrincipalRoleCollector(ctx, principalCollector)

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// Build security audit info.
		// RFA-9i2: Read from collector (upstream-propagated) with fallback to
		// context value for backward compatibility with any middleware that
		// might set flags directly on the context passed to next.ServeHTTP.
		flags := collector.Flags
		if len(flags) == 0 {
			flags = GetSecurityFlags(ctx)
		}
		toolHashVerified := GetToolHashVerified(ctx)
		securityAudit := &SecurityAudit{
			ToolHashVerified: toolHashVerified,
			SafeZoneFlags:    flags,
			FrameworkRefs:    resolveFrameworkRefs(flags, toolHashVerified, wrapped.statusCode),
		}

		// Build authorization audit info
		var authzAudit *AuthzAudit
		opaDecisionID := GetOPADecisionID(ctx)
		if opaDecisionID != "" {
			authzAudit = &AuthzAudit{
				OPADecisionID: opaDecisionID,
				Allowed:       wrapped.statusCode < 400,
			}
		}

		// RFA-m6j.2: Set per-middleware span attributes
		sessionID := GetSessionID(ctx)
		decisionID := GetDecisionID(ctx)
		span.SetAttributes(
			attribute.String("mcp.session_id", sessionID),
			attribute.String("mcp.decision_id", decisionID),
			attribute.String("prev_hash", auditor.LastHash()),
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", "audit logged"),
		)

		// OC-t7go: Read principal role from the collector (upstream-propagated)
		// with fallback to context value for backward compatibility.
		var principal PrincipalRole
		if principalCollector.Role != nil {
			principal = *principalCollector.Role
		} else {
			principal = GetPrincipalRole(ctx)
		}

		auditor.Log(AuditEvent{
			SessionID:      sessionID,
			DecisionID:     decisionID,
			TraceID:        GetTraceID(ctx),
			SPIFFEID:       GetSPIFFEID(ctx),
			PrincipalLevel: principal.Level,
			PrincipalRole:  principal.Role,
			Action:         "mcp_request",
			Result:         "completed",
			Method:         r.Method,
			Path:           r.URL.Path,
			StatusCode:     wrapped.statusCode,
			Security:       securityAudit,
			Authorization:  authzAudit,
		})
	})
}
