package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/precinct-dev/precinct/internal/agw/compliance"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var complianceCollectControlEvidence = compliance.CollectControlEvidence

func newComplianceEvidenceCmd() *cobra.Command {
	var controlID string
	var auditSource string
	var auditLogPath string
	var opensearchURL string
	var opensearchIndex string
	var opensearchUsername string
	var opensearchPasswordEnv string
	var opensearchCACert string
	var opensearchClientCert string
	var opensearchClientKey string
	var opensearchTimeWindow string
	var opensearchMaxEntries int
	var opensearchInsecureSkipVerify bool

	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Extract evidence for a single compliance control",
		RunE: func(cmd *cobra.Command, args []string) error {
			controlID = strings.TrimSpace(controlID)
			if controlID == "" {
				return fmt.Errorf("--control is required (e.g. --control GW-AUTH-001)")
			}
			src := strings.ToLower(strings.TrimSpace(auditSource))
			if src == "" {
				src = "auto"
			}

			var opensearchPassword string
			switch src {
			case "auto", "file", "docker":
				// valid sources with no additional requirements
			case "opensearch":
				opensearchPassword = strings.TrimSpace(os.Getenv(opensearchPasswordEnv))
				if strings.TrimSpace(opensearchUsername) == "" {
					return fmt.Errorf("--opensearch-username is required when --audit-source=opensearch")
				}
				if opensearchPassword == "" {
					return fmt.Errorf("%s environment variable is required when --audit-source=opensearch", opensearchPasswordEnv)
				}
				if strings.TrimSpace(opensearchCACert) == "" {
					return fmt.Errorf("--opensearch-ca-cert is required when --audit-source=opensearch")
				}
				if strings.TrimSpace(opensearchClientCert) == "" || strings.TrimSpace(opensearchClientKey) == "" {
					return fmt.Errorf("--opensearch-client-cert and --opensearch-client-key are required when --audit-source=opensearch")
				}
			default:
				return fmt.Errorf("invalid --audit-source %q (expected auto|file|docker|opensearch)", src)
			}

			out, err := complianceCollectControlEvidence(compliance.ControlEvidenceParams{
				ControlID:                    controlID,
				AuditSource:                  src,
				AuditLogPath:                 auditLogPath,
				OpenSearchURL:                opensearchURL,
				OpenSearchIndex:              opensearchIndex,
				OpenSearchUsername:           opensearchUsername,
				OpenSearchPassword:           opensearchPassword,
				OpenSearchCACertPath:         opensearchCACert,
				OpenSearchClientCertPath:     opensearchClientCert,
				OpenSearchClientKeyPath:      opensearchClientKey,
				OpenSearchTimeWindow:         opensearchTimeWindow,
				OpenSearchMaxEntries:         opensearchMaxEntries,
				OpenSearchInsecureSkipVerify: opensearchInsecureSkipVerify,
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
	cmd.Flags().StringVar(&auditSource, "audit-source", "auto", "Audit source: auto|file|docker|opensearch")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "/tmp/audit.jsonl", "Local audit JSONL path (used by --audit-source auto|file)")
	cmd.Flags().StringVar(&opensearchURL, "opensearch-url", "https://opensearch.observability.svc.cluster.local:9200", "OpenSearch base URL (used by --audit-source opensearch)")
	cmd.Flags().StringVar(&opensearchIndex, "opensearch-index", "precinct-audit-*", "OpenSearch index or index pattern (used by --audit-source opensearch)")
	cmd.Flags().StringVar(&opensearchUsername, "opensearch-username", "admin", "OpenSearch username (used by --audit-source opensearch)")
	cmd.Flags().StringVar(&opensearchPasswordEnv, "opensearch-password-env", "PRECINCT_OPENSEARCH_PASSWORD", "Environment variable containing OpenSearch password")
	cmd.Flags().StringVar(&opensearchCACert, "opensearch-ca-cert", "", "Path to OpenSearch CA certificate (required for --audit-source opensearch)")
	cmd.Flags().StringVar(&opensearchClientCert, "opensearch-client-cert", "", "Path to OpenSearch client certificate (required for --audit-source opensearch)")
	cmd.Flags().StringVar(&opensearchClientKey, "opensearch-client-key", "", "Path to OpenSearch client private key (required for --audit-source opensearch)")
	cmd.Flags().StringVar(&opensearchTimeWindow, "opensearch-time-window", "168h", "OpenSearch query lookback window (e.g. 24h, 7d)")
	cmd.Flags().IntVar(&opensearchMaxEntries, "opensearch-max-entries", 5000, "Maximum OpenSearch audit entries to collect")
	cmd.Flags().BoolVar(&opensearchInsecureSkipVerify, "opensearch-insecure-skip-verify", false, "Disable OpenSearch server certificate verification (not recommended)")
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
