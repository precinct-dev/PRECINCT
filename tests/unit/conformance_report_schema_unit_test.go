// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package unit

import (
	"testing"

	"github.com/precinct-dev/precinct/tests/conformance/harness"
)

func TestConformanceReportSchemaValidation(t *testing.T) {
	report, err := harness.Run(harness.DefaultRunOptions())
	if err != nil {
		t.Fatalf("run conformance harness: %v", err)
	}
	if report.SchemaVersion != harness.ReportSchemaVersion {
		t.Fatalf("expected schema version %q, got %q", harness.ReportSchemaVersion, report.SchemaVersion)
	}
	if err := harness.ValidateReportSchema(report, harness.DefaultReportSchemaPath()); err != nil {
		t.Fatalf("report should satisfy schema: %v", err)
	}
}

func TestConformanceReportSchemaRejectsInvalidVersion(t *testing.T) {
	report, err := harness.Run(harness.DefaultRunOptions())
	if err != nil {
		t.Fatalf("run conformance harness: %v", err)
	}
	report.SchemaVersion = "conformance.report.v0"
	if err := harness.ValidateReportSchema(report, harness.DefaultReportSchemaPath()); err == nil {
		t.Fatal("expected schema validation failure for invalid schema_version")
	}
}
