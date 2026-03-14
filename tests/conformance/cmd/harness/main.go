package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/precinct-dev/precinct/tests/conformance/harness"
)

func main() {
	opts := harness.DefaultRunOptions()
	fixtures := flag.String("fixtures", opts.FixtureDir, "Path to conformance fixture directory")
	output := flag.String("output", harness.DefaultReportOutputPath(), "Path to conformance JSON output artifact")
	schema := flag.String("schema", harness.DefaultReportSchemaPath(), "Path to conformance report schema")
	gatewayURL := flag.String("gateway-url", opts.GatewayURL, "Gateway URL for live suite execution")
	live := flag.Bool("live", false, "Run connector/ruleops suites against live gateway URL")
	validateSchema := flag.Bool("validate-schema", true, "Validate output report against report schema")
	spiffeID := flag.String("spiffe-id", opts.SPIFFEID, "SPIFFE ID to use for gateway requests")
	flag.Parse()

	runOpts := opts
	runOpts.FixtureDir = *fixtures
	runOpts.GatewayURL = *gatewayURL
	runOpts.Live = *live
	runOpts.SPIFFEID = *spiffeID

	report, err := harness.Run(runOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "conformance run failed: %v\n", err)
		os.Exit(1)
	}
	if *validateSchema {
		if err := harness.ValidateReportSchema(report, *schema); err != nil {
			fmt.Fprintf(os.Stderr, "report schema validation failed: %v\n", err)
			os.Exit(1)
		}
	}
	if err := harness.WriteReport(*output, report); err != nil {
		fmt.Fprintf(os.Stderr, "write report failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("conformance report: %s\n", *output)
	fmt.Printf("suites: total=%d pass=%d fail=%d\n", report.Summary.TotalSuites, report.Summary.SuitePass, report.Summary.SuiteFail)
	fmt.Printf("checks: total=%d pass=%d fail=%d\n", report.Summary.TotalChecks, report.Summary.CheckPass, report.Summary.CheckFail)

	if report.Summary.SuiteFail > 0 || report.Summary.CheckFail > 0 {
		os.Exit(1)
	}
}
