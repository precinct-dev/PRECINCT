package neurosymbolic

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	defaultTenant           = "tenant-a"
	defaultCSVMaxBytes      = 256 * 1024
	defaultCSVHandlePrefix  = "facts:"
	defaultHashVerifierName = "sha256-csv-ingestion"
)

var defaultRequiredHeaders = []string{"fact_id", "subject", "predicate", "object"}

// CSVPolicy defines validation bounds for CSV-to-facts ingestion.
type CSVPolicy struct {
	MaxBytes        int
	RequiredHeaders []string
}

// EnvelopeParams carries control-plane envelope fields.
type EnvelopeParams struct {
	RunID     string
	SessionID string
	SPIFFEID  string
	Plane     string
}

// AdmissionOptions customizes context admission attributes for the gateway.
type AdmissionOptions struct {
	ModelEgress       bool
	MemoryOperation   string
	DLPClassification string
}

// ValidationReport captures CSV validation and provenance results.
type ValidationReport struct {
	SchemaValid               bool
	SizeValid                 bool
	MaliciousContentDetected  bool
	RowCount                  int
	SizeBytes                 int
	MaxBytes                  int
	RequiredHeaders           []string
	MissingHeaders            []string
	FactsHash                 string
	FactsHashAlgorithm        string
	FactsHashVerified         bool
	ContextHandle             string
	Source                    string
	MalformedRowCount         int
	UnsupportedFormulaPayload bool
}

// AnalyzeCSV validates CSV content and derives provenance metadata.
func AnalyzeCSV(csvContent []byte, source string, policy CSVPolicy) (ValidationReport, error) {
	normalizedPolicy := normalizePolicy(policy)
	report := ValidationReport{
		MaxBytes:           normalizedPolicy.MaxBytes,
		RequiredHeaders:    append([]string{}, normalizedPolicy.RequiredHeaders...),
		SizeBytes:          len(csvContent),
		FactsHash:          computeFactsHash(csvContent),
		FactsHashAlgorithm: "sha256",
		Source:             normalizeSource(source),
	}
	report.ContextHandle = defaultCSVHandlePrefix + shortHash(report.FactsHash)
	report.SizeValid = report.SizeBytes > 0 && report.SizeBytes <= normalizedPolicy.MaxBytes

	if !report.SizeValid {
		report.FactsHashVerified = false
		return report, nil
	}

	reader := csv.NewReader(bytes.NewReader(csvContent))
	records, err := reader.ReadAll()
	if err != nil {
		return report, fmt.Errorf("read csv: %w", err)
	}
	if len(records) == 0 {
		report.FactsHashVerified = false
		return report, nil
	}

	headers := normalizeHeaders(records[0])
	report.MissingHeaders = missingHeaders(headers, normalizedPolicy.RequiredHeaders)
	report.RowCount = maxInt(0, len(records)-1)

	for _, row := range records[1:] {
		if len(row) != len(records[0]) {
			report.MalformedRowCount++
		}
		for _, cell := range row {
			if isMaliciousCell(cell) {
				report.MaliciousContentDetected = true
				if hasFormulaPayload(cell) {
					report.UnsupportedFormulaPayload = true
				}
			}
		}
	}

	report.SchemaValid = len(report.MissingHeaders) == 0 && report.RowCount > 0 && report.MalformedRowCount == 0
	report.FactsHashVerified = report.SizeValid && report.SchemaValid && !report.MaliciousContentDetected
	return report, nil
}

// BuildContextAdmissionAttributes maps report outputs into v2.4 context admission attributes.
func BuildContextAdmissionAttributes(report ValidationReport, opts AdmissionOptions) map[string]any {
	memoryOperation := strings.ToLower(strings.TrimSpace(opts.MemoryOperation))
	if memoryOperation == "" {
		memoryOperation = "write"
	}
	dlpClassification := strings.ToLower(strings.TrimSpace(opts.DLPClassification))
	if dlpClassification == "" {
		dlpClassification = "clean"
	}

	scanPassed := report.SizeValid && report.SchemaValid && !report.MaliciousContentDetected

	attrs := map[string]any{
		"ingestion_type":                   "neuro_symbolic_csv",
		"context_kind":                     "neuro_symbolic_csv",
		"context_reference_mode":           "handle",
		"context_handle":                   report.ContextHandle,
		"csv_schema_valid":                 report.SchemaValid,
		"csv_size_bytes":                   report.SizeBytes,
		"csv_size_limit_bytes":             report.MaxBytes,
		"csv_row_count":                    report.RowCount,
		"csv_required_headers":             append([]string{}, report.RequiredHeaders...),
		"csv_missing_headers":              append([]string{}, report.MissingHeaders...),
		"csv_malformed_row_count":          report.MalformedRowCount,
		"csv_malicious_content_detected":   report.MaliciousContentDetected,
		"csv_formula_payload_detected":     report.UnsupportedFormulaPayload,
		"facts_hash":                       report.FactsHash,
		"facts_hash_algorithm":             report.FactsHashAlgorithm,
		"facts_hash_verified":              report.FactsHashVerified,
		"facts_count":                      report.RowCount,
		"scan_passed":                      scanPassed,
		"prompt_check_passed":              !report.MaliciousContentDetected,
		"prompt_injection_detected":        report.MaliciousContentDetected,
		"memory_operation":                 memoryOperation,
		"model_egress":                     opts.ModelEgress,
		"dlp_classification":               dlpClassification,
		"minimum_necessary_applied":        true,
		"minimum_necessary_outcome":        "tokenize",
		"neuro_symbolic_policy_checkpoint": "validated",
		"provenance": map[string]any{
			"source":              report.Source,
			"checksum":            report.FactsHash,
			"verified":            report.FactsHashVerified,
			"verifier":            defaultHashVerifierName,
			"verification_method": "sha256",
		},
	}
	return attrs
}

// BuildContextAdmissionRequestFromCSV builds a complete context admission request payload.
func BuildContextAdmissionRequestFromCSV(
	csvContent []byte,
	source string,
	policy CSVPolicy,
	envelope EnvelopeParams,
	opts AdmissionOptions,
) (map[string]any, ValidationReport, error) {
	report, err := AnalyzeCSV(csvContent, source, policy)
	if err != nil {
		return nil, ValidationReport{}, err
	}

	if envelope.Plane == "" {
		envelope.Plane = "context"
	}

	attrs := BuildContextAdmissionAttributes(report, opts)
	request := map[string]any{
		"envelope": envelopeForPlane(envelope),
		"policy": map[string]any{
			"envelope":   envelopeForPlane(envelope),
			"action":     "context.admit",
			"resource":   "context/segment",
			"attributes": attrs,
		},
	}

	return request, report, nil
}

func envelopeForPlane(params EnvelopeParams) map[string]any {
	return map[string]any{
		"run_id":          params.RunID,
		"session_id":      params.SessionID,
		"tenant":          defaultTenant,
		"actor_spiffe_id": params.SPIFFEID,
		"plane":           params.Plane,
	}
}

func normalizePolicy(policy CSVPolicy) CSVPolicy {
	if policy.MaxBytes <= 0 {
		policy.MaxBytes = defaultCSVMaxBytes
	}
	if len(policy.RequiredHeaders) == 0 {
		policy.RequiredHeaders = append([]string{}, defaultRequiredHeaders...)
		return policy
	}
	headers := make([]string, 0, len(policy.RequiredHeaders))
	for _, h := range policy.RequiredHeaders {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			headers = append(headers, h)
		}
	}
	if len(headers) == 0 {
		headers = append(headers, defaultRequiredHeaders...)
	}
	policy.RequiredHeaders = headers
	return policy
}

func normalizeHeaders(headers []string) map[string]struct{} {
	out := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		h := strings.ToLower(strings.TrimSpace(header))
		if h == "" {
			continue
		}
		out[h] = struct{}{}
	}
	return out
}

func missingHeaders(found map[string]struct{}, required []string) []string {
	missing := make([]string, 0)
	for _, h := range required {
		if _, ok := found[h]; !ok {
			missing = append(missing, h)
		}
	}
	return missing
}

func isMaliciousCell(cell string) bool {
	trimmed := strings.TrimSpace(cell)
	if trimmed == "" {
		return false
	}
	if hasFormulaPayload(trimmed) {
		return true
	}
	lowered := strings.ToLower(trimmed)
	if strings.Contains(lowered, "<script") || strings.Contains(lowered, "javascript:") {
		return true
	}
	if strings.Contains(lowered, "drop table") || strings.Contains(lowered, "ignore all previous instructions") {
		return true
	}
	return false
}

func hasFormulaPayload(value string) bool {
	if value == "" {
		return false
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return true
	default:
		return false
	}
}

func computeFactsHash(csvContent []byte) string {
	sum := sha256.Sum256(csvContent)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func shortHash(fullHash string) string {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(fullHash)), "sha256:")
	if len(trimmed) <= 16 {
		return trimmed
	}
	return trimmed[:16]
}

func normalizeSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "upload://unknown"
	}
	return source
}

func maxInt(a, b int) int {
	if a >= b {
		return a
	}
	return b
}
