package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Helpers (session-specific) ---

// doDelete sends a DELETE / request with the given session header.
func doDelete(t *testing.T, ts *httptest.Server, sessionID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("new DELETE request: %v", err)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do DELETE request: %v", err)
	}
	return resp
}

// initAndActivate performs the full MCP handshake: initialize followed by
// notifications/initialized. Returns the session ID.
func initAndActivate(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	sid := initSession(t, ts)

	// Send notifications/initialized to transition to active state.
	resp := doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized: status %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	return sid
}

// newSessionTestServer creates a test server with a registered tool and
// common options for session tests.
func newSessionTestServer(opts ...Option) *Server {
	s := newTestServer("session-test", opts...)
	s.Tool("ping", "returns pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})
	return s
}

// --- 1. Session Creation ---

func TestSession_InitializeReturnsSessionID(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp := doPost(t, ts, rpcBody(t, 1, "initialize", nil), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize must return Mcp-Session-Id header")
	}
	resp.Body.Close()

	// Verify the session ID looks like a UUID (basic length/format check).
	if len(sid) < 32 {
		t.Errorf("session ID %q is too short to be a UUID", sid)
	}
}

func TestSession_InitializeCreatesSessionInCreatedState(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)

	// Session is in "created" state. tools/list should NOT work yet --
	// the session must be activated via notifications/initialized first.
	resp := doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/list in created state: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 2. Session Activation ---

func TestSession_ActivationViaNotificationsInitialized(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)

	// Send notifications/initialized to activate the session.
	resp := doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Now tools/list should work.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tools/list after activation: status = %d, want 200", resp.StatusCode)
	}
	body := readJSON(t, resp)
	if body["error"] != nil {
		t.Errorf("tools/list should succeed after activation, got error: %v", body["error"])
	}
}

func TestSession_ToolsCallWorksAfterActivation(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// tools/call should work on an active session.
	resp := doPost(t, ts, rpcBody(t, 3, "tools/call", map[string]any{"name": "ping"}), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call: status = %d, want 200", resp.StatusCode)
	}
	body := readJSON(t, resp)
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got: %v", body)
	}
	content := result["content"].([]any)
	item := content[0].(map[string]any)
	if item["text"] != "pong" {
		t.Errorf("text = %v, want %q", item["text"], "pong")
	}
}

// --- 3. Session Validation: missing header ---

func TestSession_MissingSessionIDReturns404(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	// tools/list without any session header.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for missing session ID", resp.StatusCode)
	}
	resp.Body.Close()

	// tools/call without any session header.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "ping"}), "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for missing session ID on tools/call", resp.StatusCode)
	}
	resp.Body.Close()

	// notifications/initialized without session header.
	resp = doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for missing session ID on notifications/initialized", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 4. Invalid Session ---

func TestSession_InvalidSessionIDReturns404(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Use a completely fabricated session ID.
	fakeID := "00000000-0000-0000-0000-000000000000"

	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), fakeID)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/list with invalid session: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "ping"}), fakeID)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/call with invalid session: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 5. Session Expiry ---

func TestSession_ExpiredSessionReturns404(t *testing.T) {
	// Use a very short session timeout so the session expires quickly.
	s := newSessionTestServer(WithSessionTimeout(50 * time.Millisecond))
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// Verify session works while fresh.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list on fresh session: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Wait for the session to expire.
	time.Sleep(100 * time.Millisecond)

	// Now the session should be expired -- next request returns 404.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/list on expired session: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSession_ExpiryResetsOnActivity(t *testing.T) {
	// Session timeout of 100ms. If we keep making requests every 50ms,
	// the session should stay alive.
	s := newSessionTestServer(WithSessionTimeout(100 * time.Millisecond))
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// Make requests at 50ms intervals -- each should refresh lastAccess.
	for i := range 5 {
		time.Sleep(50 * time.Millisecond)
		resp := doPost(t, ts, rpcBody(t, i+1, "tools/list", nil), sid)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (session should still be alive)", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Now wait for full expiry without activity.
	time.Sleep(150 * time.Millisecond)

	resp := doPost(t, ts, rpcBody(t, 100, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (session expired after inactivity)", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 6. Session Termination ---

func TestSession_DeleteTerminatesSession(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// Verify session is working.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list before DELETE: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// DELETE the session.
	resp = doDelete(t, ts, sid)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE /: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Subsequent requests on that session should get 404.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/list after DELETE: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSession_DeleteWithInvalidSessionReturns404(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	fakeID := "00000000-0000-0000-0000-000000000000"
	resp := doDelete(t, ts, fakeID)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE with invalid session: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSession_DeleteWithoutSessionIDReturns404(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp := doDelete(t, ts, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE without session ID: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 7. Multiple Sessions ---

func TestSession_MultipleSessions_Independent(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid1 := initAndActivate(t, ts)
	sid2 := initAndActivate(t, ts)

	if sid1 == sid2 {
		t.Fatal("two sessions must have different IDs")
	}

	// Both sessions should work independently.
	resp1 := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "ping"}), sid1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("session1 tools/call: status = %d, want 200", resp1.StatusCode)
	}
	body1 := readJSON(t, resp1)
	if body1["error"] != nil {
		t.Errorf("session1 tools/call error: %v", body1["error"])
	}

	resp2 := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "ping"}), sid2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("session2 tools/call: status = %d, want 200", resp2.StatusCode)
	}
	body2 := readJSON(t, resp2)
	if body2["error"] != nil {
		t.Errorf("session2 tools/call error: %v", body2["error"])
	}
}

func TestSession_TerminatingOneDoesNotAffectAnother(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid1 := initAndActivate(t, ts)
	sid2 := initAndActivate(t, ts)

	// Terminate session 1.
	resp := doDelete(t, ts, sid1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE session1: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Session 1 should be gone.
	resp = doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid1)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("session1 after DELETE: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Session 2 should still work.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid2)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("session2 after session1 DELETE: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 8. Cleanup ---

func TestSession_CleanupRemovesExpiredSessions(t *testing.T) {
	// Use a very short session timeout. The cleanup goroutine should
	// remove expired sessions from the store.
	s := newSessionTestServer(WithSessionTimeout(50 * time.Millisecond))
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// Verify session is alive.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list on fresh session: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Wait for expiry + cleanup interval to pass.
	time.Sleep(200 * time.Millisecond)

	// Session should be gone (cleaned up).
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/list on cleaned-up session: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSession_CleanupDoesNotRemoveActiveSessions(t *testing.T) {
	// Use a session timeout long enough that the session should NOT be
	// cleaned up during the test.
	s := newSessionTestServer(WithSessionTimeout(10 * time.Second))
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// Give any cleanup goroutine time to run.
	time.Sleep(100 * time.Millisecond)

	// Session should still be alive.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tools/list on active session: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- 9. Serial Execution ---

func TestSession_SerialExecution_ConcurrentCallsSerialized(t *testing.T) {
	s := newTestServer("serial-test", WithSerialExecution())

	// Track execution order with a channel to prove serialization.
	// Each call takes 20ms. If serialized, total time >= 40ms for 2 calls.
	// If concurrent, total time ~= 20ms.
	var execOrder []int
	var orderMu sync.Mutex

	s.Tool("slow", "slow tool", Schema{Type: "object"}, func(_ context.Context, args map[string]any) (any, error) {
		idx := int(args["idx"].(float64))
		time.Sleep(20 * time.Millisecond)
		orderMu.Lock()
		execOrder = append(execOrder, idx)
		orderMu.Unlock()
		return idx, nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	start := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
			"name":      "slow",
			"arguments": map[string]any{"idx": 1.0},
		}), sid)
		resp.Body.Close()
	}()

	go func() {
		defer wg.Done()
		resp := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{
			"name":      "slow",
			"arguments": map[string]any{"idx": 2.0},
		}), sid)
		resp.Body.Close()
	}()

	wg.Wait()
	elapsed := time.Since(start)

	// With serial execution, 2 calls of 20ms each should take >= 35ms
	// (allowing some scheduling slack).
	if elapsed < 35*time.Millisecond {
		t.Errorf("elapsed = %v, want >= 35ms (serial execution should serialize calls)", elapsed)
	}

	orderMu.Lock()
	defer orderMu.Unlock()
	if len(execOrder) != 2 {
		t.Errorf("expected 2 executions, got %d", len(execOrder))
	}
}

func TestSession_SerialExecution_DifferentSessionsConcurrent(t *testing.T) {
	s := newTestServer("serial-multi-session", WithSerialExecution())

	var concurrentCount atomic.Int32
	var maxConcurrent atomic.Int32

	s.Tool("slow", "slow tool", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		cur := concurrentCount.Add(1)
		// Track max concurrent executions.
		for {
			old := maxConcurrent.Load()
			if int32(cur) <= old || maxConcurrent.CompareAndSwap(old, int32(cur)) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		concurrentCount.Add(-1)
		return "done", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	// Create two independent sessions.
	sid1 := initAndActivate(t, ts)
	sid2 := initAndActivate(t, ts)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "slow"}), sid1)
		resp.Body.Close()
	}()

	go func() {
		defer wg.Done()
		resp := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "slow"}), sid2)
		resp.Body.Close()
	}()

	wg.Wait()

	// Different sessions should have executed concurrently, so max
	// concurrent should be 2.
	if maxConcurrent.Load() < 2 {
		t.Errorf("maxConcurrent = %d, want >= 2 (different sessions should run concurrently)", maxConcurrent.Load())
	}
}

func TestSession_WithoutSerialExecution_ConcurrentCallsAllowed(t *testing.T) {
	// Default: no serial execution. Concurrent calls on same session
	// should run concurrently.
	s := newTestServer("no-serial-test")

	var concurrentCount atomic.Int32
	var maxConcurrent atomic.Int32

	s.Tool("slow", "slow tool", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		cur := concurrentCount.Add(1)
		for {
			old := maxConcurrent.Load()
			if int32(cur) <= old || maxConcurrent.CompareAndSwap(old, int32(cur)) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		concurrentCount.Add(-1)
		return "done", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	var wg sync.WaitGroup
	wg.Add(3)

	for i := range 3 {
		go func(id int) {
			defer wg.Done()
			resp := doPost(t, ts, rpcBody(t, id+1, "tools/call", map[string]any{"name": "slow"}), sid)
			resp.Body.Close()
		}(i)
	}

	wg.Wait()

	// Without serial execution, concurrent calls should overlap.
	if maxConcurrent.Load() < 2 {
		t.Errorf("maxConcurrent = %d, want >= 2 (without serial execution, calls should run concurrently)", maxConcurrent.Load())
	}
}

// --- 10. State Machine ---

func TestSession_CannotToolsCallInCreatedState(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Initialize but do NOT send notifications/initialized.
	sid := initSession(t, ts)

	// tools/call should fail because session is in "created" state, not "active".
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "ping"}), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/call in created state: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSession_CannotToolsListInCreatedState(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Initialize but do NOT send notifications/initialized.
	sid := initSession(t, ts)

	// tools/list should fail because session is in "created" state.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tools/list in created state: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSession_CreatedToActiveTransition(t *testing.T) {
	s := newSessionTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)

	// In "created" state: tools/list returns 404.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("before activation: status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Send notifications/initialized to transition to "active".
	resp = doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// In "active" state: tools/list works.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("after activation: status = %d, want 200", resp.StatusCode)
	}
	body := readJSON(t, resp)
	if body["error"] != nil {
		t.Errorf("tools/list returned error after activation: %v", body["error"])
	}
}

// --- Options Unit Tests ---

func TestWithSessionTimeout_SetsTimeout(t *testing.T) {
	s := newTestServer("test", WithSessionTimeout(5*time.Minute))
	if s.sessionTimeout != 5*time.Minute {
		t.Errorf("sessionTimeout = %v, want 5m", s.sessionTimeout)
	}
}

func TestWithSerialExecution_EnablesFlag(t *testing.T) {
	s := newTestServer("test", WithSerialExecution())
	if !s.serialExecution {
		t.Error("serialExecution should be true")
	}
}

func TestWithSerialExecution_DefaultOff(t *testing.T) {
	s := newTestServer("test")
	if s.serialExecution {
		t.Error("serialExecution should default to false")
	}
}
