// Package main implements the content-scanner sidecar HTTP service.
// It serves as an extension protocol adapter for the PRECINCT gateway,
// validating content through a pluggable Scanner interface.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	version     = "1.0.0"
	serviceName = "content-scanner"
)

// ExtensionRequest is the inbound payload from the gateway extension slot system.
type ExtensionRequest struct {
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`
	Timestamp string `json:"timestamp"`
	Slot      string `json:"slot"`
	Request   struct {
		Method        string   `json:"method,omitempty"`
		ToolName      string   `json:"tool_name,omitempty"`
		Body          string   `json:"body,omitempty"` // base64-encoded
		SPIFFEID      string   `json:"spiffe_id,omitempty"`
		SecurityFlags []string `json:"security_flags,omitempty"`
	} `json:"request"`
}

// ExtensionResponse is the outbound payload returned to the gateway.
type ExtensionResponse struct {
	Version    string   `json:"version"`
	Decision   string   `json:"decision"`
	Flags      []string `json:"flags,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	ErrorCode  string   `json:"error_code,omitempty"`
}

// InfoResponse provides scanner metadata.
type InfoResponse struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	PatternCount int    `json:"pattern_count"`
}

// newMux builds an http.ServeMux wired to the given scanner.
func newMux(scanner Scanner, patternCount int) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ExtensionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			resp := ExtensionResponse{
				Version:    version,
				Decision:   "block",
				Reason:     fmt.Sprintf("invalid request body: %v", err),
				HTTPStatus: http.StatusBadRequest,
				ErrorCode:  "ext_content_scanner_bad_request",
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Base64-decode the body
		var content []byte
		if req.Request.Body != "" {
			var err error
			content, err = base64.StdEncoding.DecodeString(req.Request.Body)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				resp := ExtensionResponse{
					Version:    version,
					Decision:   "block",
					Reason:     fmt.Sprintf("invalid base64 body: %v", err),
					HTTPStatus: http.StatusBadRequest,
					ErrorCode:  "ext_content_scanner_bad_request",
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
		}

		metadata := ScanMetadata{
			Method:   req.Request.Method,
			ToolName: req.Request.ToolName,
			SPIFFEID: req.Request.SPIFFEID,
		}

		result, err := scanner.Scan(context.Background(), content, metadata)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			resp := ExtensionResponse{
				Version:    version,
				Decision:   "block",
				Reason:     fmt.Sprintf("scan error: %v", err),
				HTTPStatus: http.StatusInternalServerError,
				ErrorCode:  "ext_content_scanner_error",
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		resp := ExtensionResponse{
			Version:  version,
			Decision: result.Decision,
			Flags:    result.Flags,
			Reason:   result.Reason,
		}

		switch result.Decision {
		case "block":
			resp.HTTPStatus = http.StatusForbidden
			resp.ErrorCode = "ext_content_scanner_blocked"
		case "flag":
			// flagged content is allowed to proceed with annotations
		case "allow":
			// clean pass
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		info := InfoResponse{
			Name:         serviceName,
			Version:      version,
			PatternCount: patternCount,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(info)
	})

	return mux
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform a health check and exit 0/1")
	flag.Parse()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8085"
	}

	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1:" + port + "/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "healthcheck returned %d\n", resp.StatusCode)
			os.Exit(1)
		}
		os.Exit(0)
	}

	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())

	addr := ":" + port
	log.Printf("[content-scanner] listening on %s (%d patterns loaded)", addr, scanner.PatternCount())
	log.Fatal(http.ListenAndServe(addr, mux))
}
