package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// TestDereferenceEndpointSuccess verifies successful handle dereference with matching SPIFFE ID
func TestDereferenceEndpointSuccess(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	spiffeID := "spiffe://poc.local/agents/test/dev"
	rawData := []byte(`{"transactions": [{"id": 1, "amount": 5000}]}`)

	ref, err := store.Store(rawData, spiffeID, "database_query")
	if err != nil {
		t.Fatalf("Failed to store: %v", err)
	}

	// Build the handler
	handler := buildDereferenceHandler(store)

	// Create request with matching SPIFFE ID
	reqBody, _ := json.Marshal(map[string]string{"handle_ref": ref})
	req := httptest.NewRequest("POST", "/data/dereference", bytes.NewBuffer(reqBody))
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Parse response
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp["view_type"] != "approved_view" {
		t.Errorf("Expected view_type 'approved_view', got %v", resp["view_type"])
	}
	if resp["tool"] != "database_query" {
		t.Errorf("Expected tool 'database_query', got %v", resp["tool"])
	}

	// Verify data is present in the approved view
	dataJSON, err := json.Marshal(resp["data"])
	if err != nil {
		t.Fatalf("Failed to marshal data: %v", err)
	}
	if !bytes.Contains(dataJSON, []byte("5000")) {
		t.Error("Expected approved view to contain the transaction data")
	}
}

// TestDereferenceEndpointExpired verifies that expired handles return HTTP 410 Gone
func TestDereferenceEndpointExpired(t *testing.T) {
	store := NewHandleStore(50 * time.Millisecond)
	defer store.Close()

	spiffeID := "spiffe://poc.local/agents/test/dev"
	ref, err := store.Store([]byte(`{"data": "expired"}`), spiffeID, "sensitive_tool")
	if err != nil {
		t.Fatalf("Failed to store: %v", err)
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	handler := buildDereferenceHandler(store)

	reqBody, _ := json.Marshal(map[string]string{"handle_ref": ref})
	req := httptest.NewRequest("POST", "/data/dereference", bytes.NewBuffer(reqBody))
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should return 410 Gone
	if rec.Code != http.StatusGone {
		t.Errorf("Expected 410 Gone, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp["error"] != "handle_expired_or_not_found" {
		t.Errorf("Expected error 'handle_expired_or_not_found', got %q", resp["error"])
	}
}

// TestDereferenceEndpointWrongSPIFFEID verifies that wrong SPIFFE ID returns HTTP 403
func TestDereferenceEndpointWrongSPIFFEID(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	originalSPIFFE := "spiffe://poc.local/agents/original/dev"
	ref, err := store.Store([]byte(`{"data": "secret"}`), originalSPIFFE, "sensitive_tool")
	if err != nil {
		t.Fatalf("Failed to store: %v", err)
	}

	handler := buildDereferenceHandler(store)

	// Attempt dereference with DIFFERENT SPIFFE ID
	differentSPIFFE := "spiffe://poc.local/agents/attacker/dev"
	reqBody, _ := json.Marshal(map[string]string{"handle_ref": ref})
	req := httptest.NewRequest("POST", "/data/dereference", bytes.NewBuffer(reqBody))
	req.Header.Set("X-SPIFFE-ID", differentSPIFFE)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should return 403 Forbidden
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp["error"] != "spiffe_id_mismatch" {
		t.Errorf("Expected error 'spiffe_id_mismatch', got %q", resp["error"])
	}
}

// TestDereferenceEndpointNonExistentHandle verifies that non-existent handles return HTTP 410
func TestDereferenceEndpointNonExistentHandle(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	handler := buildDereferenceHandler(store)

	reqBody, _ := json.Marshal(map[string]string{"handle_ref": "nonexistent_ref"})
	req := httptest.NewRequest("POST", "/data/dereference", bytes.NewBuffer(reqBody))
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Errorf("Expected 410 Gone, got %d", rec.Code)
	}
}

// TestDereferenceEndpointMissingRef verifies that missing handle_ref returns HTTP 400
func TestDereferenceEndpointMissingRef(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	handler := buildDereferenceHandler(store)

	reqBody, _ := json.Marshal(map[string]string{"handle_ref": ""})
	req := httptest.NewRequest("POST", "/data/dereference", bytes.NewBuffer(reqBody))
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

// TestDereferenceEndpointMethodNotAllowed verifies that GET returns 405
func TestDereferenceEndpointMethodNotAllowed(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	handler := buildDereferenceHandler(store)

	req := httptest.NewRequest("GET", "/data/dereference", nil)
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed, got %d", rec.Code)
	}
}

// TestDereferenceEndpointMissingSPIFFEID verifies that missing SPIFFE ID returns 401
func TestDereferenceEndpointMissingSPIFFEID(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	handler := buildDereferenceHandler(store)

	reqBody, _ := json.Marshal(map[string]string{"handle_ref": "some_ref"})
	req := httptest.NewRequest("POST", "/data/dereference", bytes.NewBuffer(reqBody))
	// No X-SPIFFE-ID header

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// SPIFFE auth middleware should reject with 401
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", rec.Code)
	}
}

// buildDereferenceHandler creates the dereference handler with SPIFFE auth for testing.
// This mirrors the actual gateway wiring in gateway.go.
func buildDereferenceHandler(store *HandleStore) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			HandleRef string `json:"handle_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.HandleRef == "" {
			http.Error(w, "Missing handle_ref", http.StatusBadRequest)
			return
		}

		entry := store.Get(req.HandleRef)
		if entry == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "handle_expired_or_not_found",
				"detail": "The data handle has expired or does not exist.",
			})
			return
		}

		callerSPIFFEID := middleware.GetSPIFFEID(r.Context())
		if callerSPIFFEID != entry.SPIFFEID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "spiffe_id_mismatch",
				"detail": "You are not authorized to dereference this handle.",
			})
			return
		}

		approvedView := map[string]interface{}{
			"view_type":  "approved_view",
			"tool":       entry.ToolName,
			"created_at": entry.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			"data":       json.RawMessage(entry.RawData),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(approvedView)
	})

	return middleware.SPIFFEAuth(inner, "dev")
}
