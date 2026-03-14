package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/precinct-dev/precinct/internal/agw/compliance"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var complianceCollectEvidencePackage = compliance.CollectEvidencePackage
var complianceSignEvidencePackage = compliance.SignEvidencePackage

func newComplianceCollectCmd() *cobra.Command {
	var framework string
	var outputDir string
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
	var sign bool
	var cosignKey string

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect evidence into a timestamped package directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			fw := strings.ToLower(strings.TrimSpace(framework))
			if fw == "" {
				return fmt.Errorf("--framework is required (e.g. --framework soc2)")
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

			// Reuse the gateway URL config (root flag/env) so callers can keep
			// one consistent config surface. (Not required for collection logic,
			// but used by integration tests and future subcommands.)
			_ = viper.GetString(cfgGatewayURL)

			res, err := complianceCollectEvidencePackage(compliance.CollectParams{
				Framework:                    fw,
				OutputDir:                    outputDir,
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

			if sign {
				signRes, err := complianceSignEvidencePackage(compliance.SignParams{
					EvidenceDir: res.EvidenceDir,
					CosignKey:   cosignKey,
				})
				if err != nil {
					return err
				}
				if signRes.Skipped {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s\n", signRes.SkipReason)
				} else {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Signed evidence package: %s\n", signRes.SignaturePath)
				}
			}

			// AC9: demoable. Print the created evidence directory path.
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), res.EvidenceDir)
			return nil
		},
	}

	cmd.Flags().StringVar(&framework, "framework", "", "Framework to collect evidence for (e.g. soc2)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "reports", "Base output directory (timestamped evidence dir created inside)")
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
	cmd.Flags().BoolVar(&sign, "sign", false, "Sign the evidence package with cosign")
	cmd.Flags().StringVar(&cosignKey, "cosign-key", ".cosign/cosign.key", "Path to cosign private key (used with --sign)")
	return cmd
}
