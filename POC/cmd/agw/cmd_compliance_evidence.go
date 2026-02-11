package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/example/agentic-security-poc/internal/agw/compliance"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var complianceCollectControlEvidence = compliance.CollectControlEvidence

func newComplianceEvidenceCmd() *cobra.Command {
	var controlID string
	var auditLogPath string

	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Extract evidence for a single compliance control",
		RunE: func(cmd *cobra.Command, args []string) error {
			controlID = strings.TrimSpace(controlID)
			if controlID == "" {
				return fmt.Errorf("--control is required (e.g. --control GW-AUTH-001)")
			}

			out, err := complianceCollectControlEvidence(compliance.ControlEvidenceParams{
				ControlID:    controlID,
				AuditLogPath: auditLogPath,
			})
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := renderControlEvidenceTable(out)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), s)
			case "json":
				b, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return err
				}
				b = append(b, '\n')
				_, _ = cmd.OutOrStdout().Write(b)
			default:
				return fmt.Errorf("invalid --format %q (expected json|table)", format)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&controlID, "control", "", "Control ID (e.g. GW-AUTH-001)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "/tmp/audit.jsonl", "Local audit JSONL path")
	return cmd
}

func renderControlEvidenceTable(out compliance.ControlEvidenceResult) (string, error) {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "CONTROL: %s\n", out.ControlID)
	_, _ = fmt.Fprintf(&b, "NAME: %s\n", out.Name)
	_, _ = fmt.Fprintf(&b, "EVIDENCE_TYPE: %s\n", out.EvidenceType)
	_, _ = fmt.Fprintf(&b, "FRAMEWORKS: %s\n", strings.Join(out.Frameworks, ","))
	_, _ = fmt.Fprintf(&b, "AUDIT_SOURCE: %s\n", out.AuditSource)

	switch evidence := out.Evidence.(type) {
	case []map[string]any:
		_, _ = fmt.Fprintf(&b, "MATCHED_AUDIT_ENTRIES: %d\n", len(evidence))
	case map[string]any:
		keys := make([]string, 0, len(evidence))
		for k := range evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		_, _ = fmt.Fprintf(&b, "EVIDENCE_KEYS: %s\n", strings.Join(keys, ","))
	default:
		_, _ = fmt.Fprintf(&b, "EVIDENCE: %v\n", evidence)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}
