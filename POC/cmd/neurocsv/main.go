package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	nsadapter "github.com/example/agentic-security-poc/internal/integrations/neurosymbolic"
)

func main() {
	var (
		csvPath       string
		runID         string
		sessionID     string
		spiffeID      string
		source        string
		maxBytes      int
		modelEgress   bool
		memoryOp      string
		dlpClass      string
		includeReport bool
	)

	flag.StringVar(&csvPath, "csv", "", "path to CSV file")
	flag.StringVar(&runID, "run-id", "", "run identifier")
	flag.StringVar(&sessionID, "session-id", "", "session identifier")
	flag.StringVar(&spiffeID, "spiffe-id", "", "actor SPIFFE ID")
	flag.StringVar(&source, "source", "", "source URI for provenance")
	flag.IntVar(&maxBytes, "max-bytes", 256*1024, "max CSV bytes")
	flag.BoolVar(&modelEgress, "model-egress", true, "set model_egress attribute")
	flag.StringVar(&memoryOp, "memory-operation", "write", "memory operation attribute")
	flag.StringVar(&dlpClass, "dlp-classification", "clean", "dlp classification attribute")
	flag.BoolVar(&includeReport, "include-report", false, "include validation report in output")
	flag.Parse()

	if csvPath == "" || runID == "" || sessionID == "" || spiffeID == "" {
		fmt.Fprintln(os.Stderr, "required flags: --csv --run-id --session-id --spiffe-id")
		os.Exit(2)
	}

	csvContent, err := os.ReadFile(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read csv: %v\n", err)
		os.Exit(1)
	}

	request, report, err := nsadapter.BuildContextAdmissionRequestFromCSV(
		csvContent,
		source,
		nsadapter.CSVPolicy{MaxBytes: maxBytes},
		nsadapter.EnvelopeParams{
			RunID:     runID,
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "context",
		},
		nsadapter.AdmissionOptions{
			ModelEgress:       modelEgress,
			MemoryOperation:   memoryOp,
			DLPClassification: dlpClass,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if includeReport {
		_ = encoder.Encode(map[string]any{
			"request": reportRequest(request),
			"report":  report,
		})
		return
	}
	_ = encoder.Encode(reportRequest(request))
}

func reportRequest(request map[string]any) map[string]any {
	if request == nil {
		return map[string]any{}
	}
	return request
}
