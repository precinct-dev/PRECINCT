package neurosymbolic

import (
	"strings"
	"testing"
)

func TestAnalyzeCSV_ValidSchemaAndProvenanceHash(t *testing.T) {
	csv := []byte("fact_id,subject,predicate,object,confidence\nf1,cell_a,binds,cell_b,0.91\nf2,cell_b,inhibits,cell_c,0.77\n")
	report, err := AnalyzeCSV(csv, "upload://facts/valid.csv", CSVPolicy{})
	if err != nil {
		t.Fatalf("AnalyzeCSV returned error: %v", err)
	}

	if !report.SchemaValid {
		t.Fatal("expected schema_valid=true")
	}
	if !report.SizeValid {
		t.Fatal("expected size_valid=true")
	}
	if report.MaliciousContentDetected {
		t.Fatal("expected malicious_content_detected=false")
	}
	if report.RowCount != 2 {
		t.Fatalf("expected row_count=2, got %d", report.RowCount)
	}
	if !strings.HasPrefix(report.FactsHash, "sha256:") {
		t.Fatalf("expected sha256 hash prefix, got %q", report.FactsHash)
	}
	if !report.FactsHashVerified {
		t.Fatal("expected facts_hash_verified=true")
	}
	if !strings.HasPrefix(report.ContextHandle, "facts:") {
		t.Fatalf("expected facts handle prefix, got %q", report.ContextHandle)
	}
}

func TestAnalyzeCSV_DetectsMaliciousCells(t *testing.T) {
	csv := []byte("fact_id,subject,predicate,object\nf1,cell_a,binds,=cmd|' /C calc'!A0\n")
	report, err := AnalyzeCSV(csv, "upload://facts/malicious.csv", CSVPolicy{})
	if err != nil {
		t.Fatalf("AnalyzeCSV returned error: %v", err)
	}
	if !report.SchemaValid {
		t.Fatal("expected schema_valid=true for malicious fixture")
	}
	if !report.MaliciousContentDetected {
		t.Fatal("expected malicious content detection=true")
	}
	if !report.UnsupportedFormulaPayload {
		t.Fatal("expected formula payload detection=true")
	}
	if report.FactsHashVerified {
		t.Fatal("expected facts_hash_verified=false for malicious fixture")
	}
}

func TestAnalyzeCSV_ValidationFailures(t *testing.T) {
	t.Run("missing_required_header", func(t *testing.T) {
		csv := []byte("fact_id,subject,predicate\nf1,cell_a,binds\n")
		report, err := AnalyzeCSV(csv, "upload://facts/missing-header.csv", CSVPolicy{})
		if err != nil {
			t.Fatalf("AnalyzeCSV returned error: %v", err)
		}
		if report.SchemaValid {
			t.Fatal("expected schema_valid=false")
		}
		if len(report.MissingHeaders) == 0 {
			t.Fatal("expected missing headers to be reported")
		}
	})

	t.Run("size_limit_exceeded", func(t *testing.T) {
		csv := []byte("fact_id,subject,predicate,object\nf1,a,b,c\n")
		report, err := AnalyzeCSV(csv, "upload://facts/oversize.csv", CSVPolicy{MaxBytes: 16})
		if err != nil {
			t.Fatalf("AnalyzeCSV returned error: %v", err)
		}
		if report.SizeValid {
			t.Fatal("expected size_valid=false")
		}
		if report.FactsHashVerified {
			t.Fatal("expected facts_hash_verified=false when size validation fails")
		}
	})
}

func TestBuildContextAdmissionAttributes_ContainsProvenanceAndHandle(t *testing.T) {
	csv := []byte("fact_id,subject,predicate,object\nf1,a,binds,b\n")
	report, err := AnalyzeCSV(csv, "upload://facts/attrs.csv", CSVPolicy{})
	if err != nil {
		t.Fatalf("AnalyzeCSV returned error: %v", err)
	}

	attrs := BuildContextAdmissionAttributes(report, AdmissionOptions{
		ModelEgress:       true,
		MemoryOperation:   "write",
		DLPClassification: "clean",
	})

	if attrs["ingestion_type"] != "neuro_symbolic_csv" {
		t.Fatalf("expected ingestion_type=neuro_symbolic_csv, got %v", attrs["ingestion_type"])
	}
	if attrs["context_reference_mode"] != "handle" {
		t.Fatalf("expected context_reference_mode=handle, got %v", attrs["context_reference_mode"])
	}
	if attrs["context_handle"] != report.ContextHandle {
		t.Fatalf("expected context_handle=%q, got %v", report.ContextHandle, attrs["context_handle"])
	}
	if attrs["facts_hash"] != report.FactsHash {
		t.Fatalf("expected facts_hash=%q, got %v", report.FactsHash, attrs["facts_hash"])
	}
	provenance, ok := attrs["provenance"].(map[string]any)
	if !ok {
		t.Fatalf("expected provenance map, got %T", attrs["provenance"])
	}
	if provenance["checksum"] != report.FactsHash {
		t.Fatalf("expected provenance checksum=%q, got %v", report.FactsHash, provenance["checksum"])
	}
	if provenance["verified"] != report.FactsHashVerified {
		t.Fatalf("expected provenance verified=%v, got %v", report.FactsHashVerified, provenance["verified"])
	}
}
