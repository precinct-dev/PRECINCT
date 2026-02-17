package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultWSURL      = "ws://localhost:9090/openclaw/ws"
	defaultSPIFFEID   = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	defaultProbePhase = "smoke"
	defaultTimeout    = 10 * time.Second
)

type wsRequestFrame struct {
	Type   string         `json:"type"`
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type wsErrorShape struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	ReasonCode string         `json:"reason_code,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type wsResponseFrame struct {
	Type    string         `json:"type"`
	ID      string         `json:"id"`
	OK      bool           `json:"ok"`
	Payload map[string]any `json:"payload,omitempty"`
	Error   *wsErrorShape  `json:"error,omitempty"`
}

type probeReport struct {
	SchemaVersion   string           `json:"schema_version"`
	Phase           string           `json:"phase"`
	Status          string           `json:"status"`
	URL             string           `json:"url"`
	SPIFFEID        string           `json:"spiffe_id"`
	HandshakeStatus int              `json:"handshake_status,omitempty"`
	StartedAt       string           `json:"started_at"`
	FinishedAt      string           `json:"finished_at"`
	DurationMS      int64            `json:"duration_ms"`
	ConnectResponse *wsResponseFrame `json:"connect_response,omitempty"`
	HealthResponse  *wsResponseFrame `json:"health_response,omitempty"`
	Error           string           `json:"error,omitempty"`
}

func main() {
	var (
		wsURL      string
		spiffeID   string
		phase      string
		timeoutRaw string
		outputPath string
	)

	flag.StringVar(&wsURL, "url", defaultWSURL, "websocket URL")
	flag.StringVar(&spiffeID, "spiffe-id", defaultSPIFFEID, "SPIFFE ID header value")
	flag.StringVar(&phase, "phase", defaultProbePhase, "probe phase label")
	flag.StringVar(&timeoutRaw, "timeout", defaultTimeout.String(), "probe timeout duration (for example: 10s)")
	flag.StringVar(&outputPath, "output", "", "optional output path for JSON report")
	flag.Parse()

	timeout, err := time.ParseDuration(timeoutRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid timeout %q: %v\n", timeoutRaw, err)
		os.Exit(2)
	}

	wsURL = strings.TrimSpace(wsURL)
	spiffeID = strings.TrimSpace(spiffeID)
	phase = strings.TrimSpace(phase)
	if wsURL == "" {
		fmt.Fprintln(os.Stderr, "url must not be empty")
		os.Exit(2)
	}
	if spiffeID == "" {
		fmt.Fprintln(os.Stderr, "spiffe-id must not be empty")
		os.Exit(2)
	}
	if phase == "" {
		phase = defaultProbePhase
	}

	report := probeReport{
		SchemaVersion: "openclaw_ws_smoke.v1",
		Phase:         phase,
		Status:        "fail",
		URL:           wsURL,
		SPIFFEID:      spiffeID,
		StartedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	started := time.Now()

	if runErr := executeProbe(&report, timeout); runErr != nil {
		report.Error = runErr.Error()
	} else {
		report.Status = "pass"
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.DurationMS = time.Since(started).Milliseconds()

	if err := writeReport(report, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		os.Exit(1)
	}
	if report.Status != "pass" {
		fmt.Fprintln(os.Stderr, report.Error)
		os.Exit(1)
	}
}

func executeProbe(report *probeReport, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
	}
	headers := http.Header{}
	headers.Set("X-SPIFFE-ID", report.SPIFFEID)

	conn, resp, err := dialer.DialContext(ctx, report.URL, headers)
	if err != nil {
		if resp != nil {
			report.HandshakeStatus = resp.StatusCode
		}
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	defer conn.Close()

	connectReq := wsRequestFrame{
		Type:   "req",
		ID:     "connect-1",
		Method: "connect",
		Params: map[string]any{
			"role":   "operator",
			"scopes": []string{"gateway:read", "device:ping"},
		},
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set write deadline (connect): %w", err)
	}
	if err := conn.WriteJSON(connectReq); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	var connectResp wsResponseFrame
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set read deadline (connect): %w", err)
	}
	if err := conn.ReadJSON(&connectResp); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}
	report.ConnectResponse = &connectResp
	if !connectResp.OK {
		return fmt.Errorf("connect response denied: reason=%s message=%s", reasonCode(connectResp.Error), errorMessage(connectResp.Error))
	}

	healthReq := wsRequestFrame{
		Type:   "req",
		ID:     "health-1",
		Method: "health",
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set write deadline (health): %w", err)
	}
	if err := conn.WriteJSON(healthReq); err != nil {
		return fmt.Errorf("write health request: %w", err)
	}

	var healthResp wsResponseFrame
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set read deadline (health): %w", err)
	}
	if err := conn.ReadJSON(&healthResp); err != nil {
		return fmt.Errorf("read health response: %w", err)
	}
	report.HealthResponse = &healthResp
	if !healthResp.OK {
		return fmt.Errorf("health response denied: reason=%s message=%s", reasonCode(healthResp.Error), errorMessage(healthResp.Error))
	}

	status, _ := healthResp.Payload["status"].(string)
	if strings.TrimSpace(status) != "ok" {
		return fmt.Errorf("unexpected health payload status: %q", status)
	}

	return nil
}

func writeReport(report probeReport, outputPath string) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	target := os.Stdout

	if strings.TrimSpace(outputPath) != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer file.Close()
		target = file
		encoder = json.NewEncoder(target)
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

func reasonCode(err *wsErrorShape) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.ReasonCode)
}

func errorMessage(err *wsErrorShape) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Message)
}
