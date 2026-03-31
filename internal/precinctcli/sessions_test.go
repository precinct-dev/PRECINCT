package precinctcli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestKeyDBListSessions_AllAndFiltered(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	spiffeA := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	spiffeB := "spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev"

	sessionValue := func(risk float64) string {
		b, _ := json.Marshal(map[string]interface{}{
			"ID":        "ignored",
			"SPIFFEID":  "ignored",
			"RiskScore": risk,
		})
		return string(b)
	}

	if err := mr.Set("session:"+spiffeA+":sid-a", sessionValue(0.62)); err != nil {
		t.Fatalf("seed session for %s: %v", spiffeA, err)
	}
	mr.SetTTL("session:"+spiffeA+":sid-a", 45*time.Minute)
	if _, err := mr.RPush("session:"+spiffeA+":sid-a:actions", `{"Tool":"read"}`, `{"Tool":"grep"}`); err != nil {
		t.Fatalf("seed actions for %s: %v", spiffeA, err)
	}
	mr.SetTTL("session:"+spiffeA+":sid-a:actions", 45*time.Minute)

	if err := mr.Set("session:"+spiffeB+":sid-b", sessionValue(0.21)); err != nil {
		t.Fatalf("seed session for %s: %v", spiffeB, err)
	}
	mr.SetTTL("session:"+spiffeB+":sid-b", 20*time.Minute)
	if _, err := mr.RPush("session:"+spiffeB+":sid-b:actions", `{"Tool":"read"}`); err != nil {
		t.Fatalf("seed actions for %s: %v", spiffeB, err)
	}
	mr.SetTTL("session:"+spiffeB+":sid-b:actions", 20*time.Minute)

	kdb, err := NewKeyDB(fmt.Sprintf("redis://%s", mr.Addr()))
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })

	ctx := context.Background()
	all, err := kdb.ListSessions(ctx, "")
	if err != nil {
		t.Fatalf("ListSessions(all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 sessions, got %d: %+v", len(all), all)
	}

	filtered, err := kdb.ListSessions(ctx, spiffeA)
	if err != nil {
		t.Fatalf("ListSessions(filtered): %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered session, got %d: %+v", len(filtered), filtered)
	}
	if filtered[0].SPIFFEID != spiffeA || filtered[0].SessionID != "sid-a" {
		t.Fatalf("unexpected filtered session: %+v", filtered[0])
	}
	if filtered[0].ToolsAccessed != 2 {
		t.Fatalf("expected tools_accessed=2, got %+v", filtered[0])
	}
	if filtered[0].RiskScore < 0.6 || filtered[0].RiskScore > 0.7 {
		t.Fatalf("expected risk_score around 0.62, got %f", filtered[0].RiskScore)
	}
	if filtered[0].TTLSeconds <= 0 {
		t.Fatalf("expected ttl_seconds > 0, got %+v", filtered[0])
	}
}

func TestRenderSessionsOutputs(t *testing.T) {
	out := SessionsOutput{
		Sessions: []SessionEntry{
			{SessionID: "s1", SPIFFEID: "spiffe://a", RiskScore: 0.12, ToolsAccessed: 1, TTLSeconds: 30},
			{SessionID: "s2", SPIFFEID: "spiffe://b", RiskScore: 0.55, ToolsAccessed: 2, TTLSeconds: 120},
			{SessionID: "s3", SPIFFEID: "spiffe://c", RiskScore: 0.80, ToolsAccessed: 3, TTLSeconds: 3700},
		},
	}

	b, err := RenderSessionsJSON(out)
	if err != nil {
		t.Fatalf("RenderSessionsJSON: %v", err)
	}
	var parsed SessionsOutput
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(parsed.Sessions) != 3 {
		t.Fatalf("unexpected parsed size: %+v", parsed)
	}

	table, err := RenderSessionsTable(out)
	if err != nil {
		t.Fatalf("RenderSessionsTable: %v", err)
	}
	for _, needle := range []string{"SESSION_ID", "SPIFFE_ID", "TOOLS_ACCESSED", "0m"} {
		if !strings.Contains(table, needle) {
			t.Fatalf("expected %q in table output:\n%s", needle, table)
		}
	}
	if !strings.Contains(table, "\033[1;33m0.55\033[0m") {
		t.Fatalf("expected yellow highlighting for 0.55 in table output:\n%s", table)
	}
	if !strings.Contains(table, "\033[0;31m0.80\033[0m") {
		t.Fatalf("expected red highlighting for 0.80 in table output:\n%s", table)
	}
}
