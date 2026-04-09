// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"encoding/json"
	"net/http"
)

// healthResponse is the JSON body returned by GET /health.
type healthResponse struct {
	Status  string `json:"status"`
	Server  string `json:"server"`
	Version string `json:"version"`
}

// handleHealth responds to GET /health with server status information.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(healthResponse{
		Status:  "ok",
		Server:  s.name,
		Version: s.version,
	})
}
