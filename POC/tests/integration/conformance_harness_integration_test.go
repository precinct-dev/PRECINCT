package integration

import (
	"testing"

	"github.com/example/agentic-security-poc/tests/conformance/harness"
)

func TestConformanceHarness_FixtureCoverageAndOutcomes(t *testing.T) {
	report, err := harness.Run(harness.DefaultRunOptions())
	if err != nil {
		t.Fatalf("run conformance harness: %v", err)
	}

	required := map[string]struct{}{
		"contracts":  {},
		"connectors": {},
		"ruleops":    {},
		"profiles":   {},
	}

	if len(report.Suites) != len(required) {
		t.Fatalf("expected %d suites, got %d", len(required), len(report.Suites))
	}

	for _, suite := range report.Suites {
		if _, ok := required[suite.Suite]; !ok {
			t.Fatalf("unexpected suite in report: %s", suite.Suite)
		}
		hasPassFixture := false
		hasFailFixture := false
		for _, check := range suite.Checks {
			if check.Expected == "pass" && check.Actual == "pass" {
				hasPassFixture = true
			}
			if check.Expected == "fail" && check.Actual == "fail" {
				hasFailFixture = true
			}
			if check.Status != "pass" {
				t.Fatalf("suite %s check %s should pass expectation mapping, got status=%s expected=%s actual=%s message=%s", suite.Suite, check.CaseID, check.Status, check.Expected, check.Actual, check.Message)
			}
		}
		if !hasPassFixture {
			t.Fatalf("suite %s missing pass fixture outcome", suite.Suite)
		}
		if !hasFailFixture {
			t.Fatalf("suite %s missing fail fixture outcome", suite.Suite)
		}
	}

	if report.Summary.SuiteFail != 0 || report.Summary.CheckFail != 0 {
		t.Fatalf("expected zero conformance mismatches, summary=%+v", report.Summary)
	}
}
