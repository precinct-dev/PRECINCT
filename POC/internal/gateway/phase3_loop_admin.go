package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

type loopRunsAdminResponse struct {
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Run    *loopRunRecord  `json:"run,omitempty"`
	Runs   []loopRunRecord `json:"runs,omitempty"`
}

// adminLoopRunsHandler serves:
//   - GET /admin/loop/runs
//   - GET /admin/loop/runs/<run_id>
func (g *Gateway) adminLoopRunsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeLoopAdminJSON(w, http.StatusMethodNotAllowed, loopRunsAdminResponse{
			Status: "failed",
			Error:  "method not allowed",
		})
		return
	}

	if g.loopPolicy == nil {
		g.loopPolicy = newLoopPlanePolicyEngine()
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/loop/runs")
	path = strings.Trim(path, "/")
	if path == "" {
		writeLoopAdminJSON(w, http.StatusOK, loopRunsAdminResponse{
			Status: "ok",
			Runs:   g.loopPolicy.listRuns(),
		})
		return
	}

	run, ok := g.loopPolicy.getRun(path)
	if !ok {
		writeLoopAdminJSON(w, http.StatusNotFound, loopRunsAdminResponse{
			Status: "failed",
			Error:  "run not found",
		})
		return
	}
	writeLoopAdminJSON(w, http.StatusOK, loopRunsAdminResponse{
		Status: "ok",
		Run:    &run,
	})
}

func writeLoopAdminJSON(w http.ResponseWriter, status int, payload loopRunsAdminResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
