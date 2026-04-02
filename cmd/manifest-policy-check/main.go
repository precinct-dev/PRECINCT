package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/precinct-dev/precinct/internal/manifestpolicy"
)

func main() {
	result, err := manifestpolicy.CheckRepo(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "manifest policy check failed: %v\n", err)
		os.Exit(1)
	}
	if result.CheckedFiles == 0 {
		fmt.Fprintln(os.Stderr, "[FAIL] manifest policy check scanned zero Kubernetes manifest files")
		os.Exit(1)
	}

	if len(result.Violations) == 0 {
		fmt.Printf("[PASS] manifest policy check passed (checked_files=%d)\n", result.CheckedFiles)
		return
	}

	sort.Slice(result.Violations, func(i, j int) bool {
		if result.Violations[i].File == result.Violations[j].File {
			return result.Violations[i].Rule < result.Violations[j].Rule
		}
		return result.Violations[i].File < result.Violations[j].File
	})

	fmt.Fprintf(os.Stderr, "[FAIL] manifest policy violations detected (count=%d)\n", len(result.Violations))
	for _, v := range result.Violations {
		fmt.Fprintf(os.Stderr, " - [%s] %s: %s\n", v.Rule, v.File, v.Message)
	}
	os.Exit(1)
}
