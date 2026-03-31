package compliance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadAuditFromOpenSearch_Success(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "_search") {
			t.Fatalf("expected _search endpoint, got %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Fatalf("expected basic auth header")
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
		if auth != wantAuth {
			t.Fatalf("unexpected auth header: %q", auth)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if int(body["size"].(float64)) != 2 {
			t.Fatalf("expected size=2, got %#v", body["size"])
		}

		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"evt-1","_source":{"decision_id":"d-1","timestamp":"2026-02-20T10:00:00Z"}}]}}`))
	}))
	defer srv.Close()

	entries, source, err := LoadAuditFromOpenSearch(OpenSearchAuditOptions{
		URL:                srv.URL,
		Index:              "precinct-audit-*",
		Username:           "admin",
		Password:           "secret",
		TimeWindow:         "24h",
		MaxEntries:         2,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("LoadAuditFromOpenSearch: %v", err)
	}
	if !strings.Contains(source, "opensearch:") {
		t.Fatalf("expected opensearch source descriptor, got %q", source)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["decision_id"] != "d-1" {
		t.Fatalf("unexpected entry payload: %+v", entries[0])
	}
	if entries[0]["_id"] != "evt-1" {
		t.Fatalf("expected _id injected from hit metadata, got %+v", entries[0])
	}
}

func TestLoadAuditFromOpenSearch_RejectsInsecureURL(t *testing.T) {
	t.Parallel()

	_, _, err := LoadAuditFromOpenSearch(OpenSearchAuditOptions{
		URL: "http://localhost:9200",
	})
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected https validation error, got %v", err)
	}
}

func TestCollectAuditEntriesWithOptions_InvalidSource(t *testing.T) {
	t.Parallel()

	_, _, err := CollectAuditEntriesWithOptions(".", AuditCollectionOptions{Source: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "invalid audit source") {
		t.Fatalf("expected invalid source error, got %v", err)
	}
}
