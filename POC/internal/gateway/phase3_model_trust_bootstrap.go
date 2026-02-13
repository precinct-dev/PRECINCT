package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

func verifyGuardArtifactIntegrity(cfg *Config, profileName string, auditor *middleware.Auditor) error {
	if cfg == nil {
		return nil
	}
	path := strings.TrimSpace(cfg.GuardArtifactPath)
	if path == "" {
		return nil
	}

	strict := strings.TrimSpace(profileName) != enforcementProfileDev
	expectedDigest := strings.ToLower(strings.TrimSpace(cfg.GuardArtifactSHA256))
	content, err := os.ReadFile(path)
	if err != nil {
		logGuardArtifactAudit(auditor, "fail", profileName, path, expectedDigest, "", false, "read_error")
		return fmt.Errorf("guard artifact verification failed (path=%s): %w", path, err)
	}
	sum := sha256.Sum256(content)
	actualDigest := hex.EncodeToString(sum[:])

	if expectedDigest == "" {
		if strict {
			logGuardArtifactAudit(auditor, "fail", profileName, path, expectedDigest, actualDigest, false, "missing_expected_digest")
			return fmt.Errorf("guard artifact verification failed: GUARD_ARTIFACT_SHA256 required for profile %s", profileName)
		}
		logGuardArtifactAudit(auditor, "warn", profileName, path, expectedDigest, actualDigest, false, "missing_expected_digest")
		return nil
	}
	if actualDigest != expectedDigest {
		if strict {
			logGuardArtifactAudit(auditor, "fail", profileName, path, expectedDigest, actualDigest, false, "digest_mismatch")
			return fmt.Errorf("guard artifact digest mismatch: expected=%s actual=%s", expectedDigest, actualDigest)
		}
		logGuardArtifactAudit(auditor, "warn", profileName, path, expectedDigest, actualDigest, false, "digest_mismatch")
		return nil
	}

	signatureVerified := false
	if strings.TrimSpace(cfg.GuardArtifactPublicKey) != "" {
		sigPath := strings.TrimSpace(cfg.GuardArtifactSignaturePath)
		if sigPath == "" {
			sigPath = path + ".sig"
		}
		if err := verifyBlobSignature(content, sigPath, cfg.GuardArtifactPublicKey); err != nil {
			if strict {
				logGuardArtifactAudit(auditor, "fail", profileName, path, expectedDigest, actualDigest, false, "signature_verification_failed")
				return fmt.Errorf("guard artifact signature verification failed: %w", err)
			}
			logGuardArtifactAudit(auditor, "warn", profileName, path, expectedDigest, actualDigest, false, "signature_verification_failed")
			return nil
		}
		signatureVerified = true
	}

	logGuardArtifactAudit(auditor, "pass", profileName, path, expectedDigest, actualDigest, signatureVerified, "verified")
	return nil
}

func verifyBlobSignature(content []byte, signaturePath string, publicKeyPath string) error {
	pubPEM, err := os.ReadFile(strings.TrimSpace(publicKeyPath))
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return fmt.Errorf("decode PEM public key")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	edKey, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not Ed25519")
	}

	sigRaw, err := os.ReadFile(strings.TrimSpace(signaturePath))
	if err != nil {
		return fmt.Errorf("read signature file: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(edKey, content, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func logGuardArtifactAudit(auditor *middleware.Auditor, status string, profileName string, path string, expected string, actual string, signatureVerified bool, detail string) {
	if auditor == nil {
		return
	}
	auditor.Log(middleware.AuditEvent{
		Action: "model.guard_artifact.verify",
		Result: fmt.Sprintf(
			"status=%s profile=%s path=%s expected_digest=%s actual_digest=%s signature_verified=%t detail=%s",
			status,
			profileName,
			path,
			expected,
			actual,
			signatureVerified,
			detail,
		),
	})
}
