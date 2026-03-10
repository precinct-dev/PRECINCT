package gateway

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/PRECINCT/POC/internal/testutil"
)

// TestStructuredLogging_Integration verifies that structured log output is
// produced during real gateway request processing (AC6).
//
// This is an integration test: it creates a real gateway with a real OPA engine,
// tool registry, session context, and auditor -- no mocks. It captures slog
// output and verifies structured JSON fields are present.
func TestStructuredLogging_Integration(t *testing.T) {
	// Capture slog output during test
	var logBuf bytes.Buffer
	initLoggerWithWriter(true, &logBuf)
	defer func() {
		// Restore default logger
		slog.SetDefault(slog.Default())
	}()

	// Create a real upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`))
	}))
	defer upstream.Close()

	// Create a real gateway (no mocks -- real OPA, registry, auditor, session context)
	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer func() { _ = gw.Close() }()

	handler := gw.Handler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Send a real MCP tools/call request through the full middleware chain
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/test.txt"}}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Flush auditor so all async audit writes complete before reading log buffer
	gw.auditor.Flush()

	// Verify that structured log lines were produced
	logOutput := logBuf.String()
	if logOutput == "" {
		t.Fatal("expected structured log output during request processing, got none")
	}

	// Parse each log line as JSON and verify structure
	lines := strings.Split(strings.TrimSpace(logOutput), "\n")
	foundStructuredEntry := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Some lines may not be JSON (e.g., audit log.Println output
			// arrives as an slog.Info wrapping the JSON string).
			continue
		}

		// Verify slog JSON fields exist
		_, hasTime := entry["time"]
		_, hasLevel := entry["level"]
		_, hasMsg := entry["msg"]

		if hasTime && hasLevel && hasMsg {
			foundStructuredEntry = true
			// Verify level is a known slog level
			level, _ := entry["level"].(string)
			validLevels := map[string]bool{
				"DEBUG": true, "INFO": true, "WARN": true, "ERROR": true,
			}
			if !validLevels[level] {
				t.Errorf("unexpected log level %q in entry: %s", level, line)
			}
		}
	}

	if !foundStructuredEntry {
		t.Errorf("no structured JSON log entries with time/level/msg found in output (%d lines total)", len(lines))
		// Print first 5 lines for debugging
		for i, line := range lines {
			if i >= 5 {
				break
			}
			t.Logf("  line %d: %s", i, line)
		}
	}
}
