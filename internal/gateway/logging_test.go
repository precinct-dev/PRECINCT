package gateway

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestInitLoggerJSON verifies that InitLogger in JSON mode produces valid JSON
// output with the expected structured fields (AC5).
func TestInitLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	initLoggerWithWriter(true, &buf)

	// Emit a test log line with structured key-value pairs
	slog.Info("test message", "key1", "value1", "key2", 42)

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty string")
	}

	// Parse as JSON to verify structured format
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry); err != nil {
		t.Fatalf("log output is not valid JSON: %v\noutput: %s", err, output)
	}

	// Verify required slog JSON fields
	requiredFields := []string{"time", "level", "msg"}
	for _, field := range requiredFields {
		if _, ok := logEntry[field]; !ok {
			t.Errorf("missing required JSON field %q in log output: %s", field, output)
		}
	}

	// Verify message content
	if msg, ok := logEntry["msg"].(string); !ok || msg != "test message" {
		t.Errorf("expected msg='test message', got %q", logEntry["msg"])
	}

	// Verify level
	if level, ok := logEntry["level"].(string); !ok || level != "INFO" {
		t.Errorf("expected level='INFO', got %q", logEntry["level"])
	}

	// Verify structured key-value pairs
	if v, ok := logEntry["key1"].(string); !ok || v != "value1" {
		t.Errorf("expected key1='value1', got %v", logEntry["key1"])
	}
	if v, ok := logEntry["key2"].(float64); !ok || v != 42 {
		t.Errorf("expected key2=42, got %v", logEntry["key2"])
	}
}

// TestInitLoggerText verifies that InitLogger in text mode produces
// human-readable output (not JSON).
func TestInitLoggerText(t *testing.T) {
	var buf bytes.Buffer
	initLoggerWithWriter(false, &buf)

	slog.Info("text mode test", "component", "gateway")

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty string")
	}

	// Text mode output should NOT be valid JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry); err == nil {
		t.Error("text mode should not produce valid JSON output")
	}

	// Should contain the message and key-value pairs
	if !strings.Contains(output, "text mode test") {
		t.Errorf("expected output to contain 'text mode test', got: %s", output)
	}
	if !strings.Contains(output, "component=gateway") {
		t.Errorf("expected output to contain 'component=gateway', got: %s", output)
	}
}

// TestInitLoggerJSONMultipleLines verifies multiple log entries are each
// valid JSON (one per line).
func TestInitLoggerJSONMultipleLines(t *testing.T) {
	var buf bytes.Buffer
	initLoggerWithWriter(true, &buf)

	slog.Info("first message", "seq", 1)
	slog.Warn("second message", "seq", 2)
	slog.Error("third message", "seq", 3)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 log lines, got %d", len(lines))
	}

	expectedLevels := []string{"INFO", "WARN", "ERROR"}
	for i, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v\nline: %s", i, err, line)
			continue
		}
		if level, ok := entry["level"].(string); !ok || level != expectedLevels[i] {
			t.Errorf("line %d: expected level=%s, got %q", i, expectedLevels[i], entry["level"])
		}
	}
}

// TestInitLoggerDefaultBehavior verifies that InitLogger(true) works without
// an explicit writer (uses stdout -- just ensures no panic).
func TestInitLoggerDefaultBehavior(t *testing.T) {
	// This should not panic
	InitLogger(true)

	// Restore default for other tests
	InitLogger(false)
}
