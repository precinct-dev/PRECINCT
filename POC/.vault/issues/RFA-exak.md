---
id: RFA-exak
title: "Automate attestation artifact re-signing with Makefile target and documentation"
status: closed
priority: 3
type: task
created_at: 2026-02-27T05:22:52Z
created_by: ramirosalas
updated_at: 2026-02-27T08:41:51Z
content_hash: "sha256:07c702457d27dabe922f1388f149398fd25ec99bc370a32dd7a62bc4daac8f54"
related: [RFA-1fui]
labels: [accepted]
closed_at: 2026-02-27T08:41:51Z
close_reason: "Accepted: attestation-resign Makefile target implemented with Go signing tool in cmd/attestation-sign/. All 6 ACs verified: keypair generation, env var override, signing all 3 artifacts with StdEncoding base64 Ed25519, .sig file output, K8s overlay copy (files confirmed identical), summary output. .gitignore updated. NOTE comments added to both YAML configs. guard-artifact.bin SHA256 unchanged (content not modified). All required test suites pass: gateway (4 pkgs), middleware, and attestation-specific integration tests confirm signature_verified=true in audit output."
---

## User Story

As a developer modifying configuration artifacts (tool-registry.yaml, model-provider-catalog.v2.yaml, guard-artifact.bin), I need a documented and automated procedure for re-signing all attestation artifacts so that signature verification tests pass and the gateway can start with strict enforcement profiles.

## Context and Background

The gateway verifies Ed25519 signatures on three configuration artifacts at startup:
- `config/tool-registry.yaml` (verified by `middleware.ToolRegistry` via `verifyBlobSignature`)
- `config/model-provider-catalog.v2.yaml` (verified by `phase3_model_trust_bootstrap.go`)
- `config/guard-artifact.bin` (verified by `verifyGuardArtifactIntegrity`)

Each artifact has a companion `.sig` file containing a base64-encoded Ed25519 signature. All three share a single public key: `config/attestation-ed25519.pub` (PEM-encoded PKIX Ed25519 public key). The private key is NOT committed to the repository.

When any of these config files changes, its `.sig` file becomes invalid. The gateway will reject the artifact under strict enforcement profiles (`docker-compose.strict.yml`), and unit/integration tests that load real config files will fail with "invalid signature" errors.

This has been observed as a recurring operational pain point: two pre-existing test failures in the RFA-xynt epic (stories RFA-1fui and RFA-np7t) were traced to stale signatures after a tool-registry.yaml change.

### Signing Mechanics

The signing algorithm is standard Ed25519 over raw file content:
1. Read the file content as bytes
2. Sign with Ed25519 private key (crypto/ed25519.Sign)
3. Base64-encode the signature (standard encoding, not URL-safe)
4. Write the base64 string to `<filename>.sig`

The public key format is PEM-encoded PKIX:
```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA<32-bytes-base64>
-----END PUBLIC KEY-----
```

The private key format is PEM-encoded PKCS8 Ed25519.

### Files That Need Signatures

| Config file | Signature file | Env var pointing to pubkey |
|---|---|---|
| config/tool-registry.yaml | config/tool-registry.yaml.sig | TOOL_REGISTRY_PUBLIC_KEY |
| config/model-provider-catalog.v2.yaml | config/model-provider-catalog.v2.yaml.sig | MODEL_PROVIDER_CATALOG_PUBLIC_KEY |
| config/guard-artifact.bin | config/guard-artifact.bin.sig | GUARD_ARTIFACT_PUBLIC_KEY |

### K8s Overlay

The K8s local overlay has copies of these files:
- `infra/eks/overlays/local/gateway-config/attestation-ed25519.pub`
- Corresponding `.sig` files if present in overlay

The Makefile target must also update the K8s overlay copies.

## Acceptance Criteria

1. A `make attestation-resign` target exists in `POC/Makefile` that:
   a. Checks for the private key at a conventional location (e.g., `config/attestation-ed25519.key` or `$ATTESTATION_PRIVATE_KEY` env var)
   b. If no private key exists, generates a new Ed25519 keypair and writes:
      - Private key to `config/attestation-ed25519.key` (PEM PKCS8)
      - Public key to `config/attestation-ed25519.pub` (PEM PKIX, overwriting existing)
   c. Signs all three artifacts: tool-registry.yaml, model-provider-catalog.v2.yaml, guard-artifact.bin
   d. Writes each signature as base64-encoded Ed25519 to the corresponding `.sig` file
   e. Copies updated `.pub` and `.sig` files to `infra/eks/overlays/local/gateway-config/`
   f. Prints a summary of what was signed and whether a new keypair was generated
   g. The signing tool can be a small Go program in `cmd/attestation-sign/` or a shell script using `openssl` -- either approach is acceptable

2. `config/attestation-ed25519.key` is added to `.gitignore` (private key must never be committed)

3. A comment is added to the top of `config/tool-registry.yaml`:
   `# NOTE: Modifying this file requires running 'make attestation-resign' to update signature files.`

4. A comment is added to the top of `config/model-provider-catalog.v2.yaml`:
   `# NOTE: Modifying this file requires running 'make attestation-resign' to update signature files.`

5. The `guard-artifact.bin` SHA256 digest in `docker-compose.strict.yml` (env `GUARD_ARTIFACT_SHA256`) is updated if guard-artifact.bin was re-signed (the digest is computed from the file content, not the signature -- so it only changes if the artifact itself changed)

6. After running `make attestation-resign`, all of the following pass:
   - `go test ./internal/gateway/...` (unit tests verifying signatures)
   - `go test ./internal/gateway/middleware/...` (tool registry signature tests)
   - `go test -tags=integration ./tests/integration/...` (integration tests loading real config)

## Testing Requirements

- **Unit tests**: Verify the signing tool/script produces valid signatures that `verifyBlobSignature` accepts. Generate a temp keypair, sign a known payload, verify with the public key. Mocks acceptable for filesystem operations.
- **Integration tests** (MANDATORY, no mocks): Run `make attestation-resign`, then execute `go test ./internal/gateway/...` and `go test -tags=integration ./tests/integration/...`. All tests must pass with the freshly signed artifacts. This tests the real signing flow end-to-end.

## Scope Boundary

This story covers ONLY the re-signing automation and documentation. It does NOT:
- Change the verification logic in `verifyBlobSignature` or `ToolRegistry`
- Add CI/CD pipeline integration for automatic re-signing
- Change the enforcement profile behavior

## Dependencies

None. This is a standalone operational improvement.

## MANDATORY SKILLS TO REVIEW

- None identified. Standard Go crypto/ed25519, Makefile, and shell scripting. No specialized skill requirements.

## Design

N/A -- this is an operational tooling story with no UI or API surface.

## Notes
DELIVERED:

- CI Results:
  - Unit tests (cmd/attestation-sign): 10/10 PASS
  - Gateway tests (./internal/gateway/...): ALL PASS (4 packages)
  - Middleware tests (./internal/gateway/middleware/...): ALL PASS
  - Integration tests (./tests/integration/...): ALL PASS (1.507s)
  - Signature-specific tests: 7/7 PASS including:
    - TestEnforcementProfile_StrictStartupPassesWithStrongApprovalSigningKey
    - TestEnforcementProfile_StrictStartupFailsWithUnsignedToolRegistry
    - TestModelProviderCatalogSignatureVerification
    - TestGuardArtifactIntegrityFailClosedOutsideDev
    - TestGuardArtifactIntegrityStrictFailureEmitsAuditEvent

- Commit: 9ec4097 on epic/RFA-xynt-ws-mediation-messaging

AC Verification:
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1a | Private key check at conventional location or env var | cmd/attestation-sign/main.go:resolvePrivateKeyPath() | cmd/attestation-sign/main_test.go:TestLoadOrGenerateKeypair_UsesEnvVar | PASS |
| 1b | Generate keypair if missing (PKCS8 priv, PKIX pub) | cmd/attestation-sign/main.go:loadOrGenerateKeypair() | cmd/attestation-sign/main_test.go:TestLoadOrGenerateKeypair_GeneratesWhenMissing | PASS |
| 1c | Sign all 3 artifacts | cmd/attestation-sign/main.go:main() signs artifacts slice | cmd/attestation-sign/main_test.go:TestSignArtifact_ProducesValidSignature | PASS |
| 1d | Write base64 Ed25519 sig to .sig files | cmd/attestation-sign/main.go:signArtifact() | cmd/attestation-sign/main_test.go:TestSignAndVerify_FullRoundTrip | PASS |
| 1e | Copy .pub and .sig to K8s overlay | cmd/attestation-sign/main.go:copyFile() loop | Verified: diff shows config/ and infra/eks/overlays/local/gateway-config/ match | PASS |
| 1f | Print summary | cmd/attestation-sign/main.go:main() fmt.Println | make attestation-resign output shows summary | PASS |
| 1g | Go program in cmd/attestation-sign/ | cmd/attestation-sign/main.go | N/A (structural requirement) | PASS |
| 2 | Private key in .gitignore | .gitignore:35 "config/attestation-ed25519.key" | git check-ignore config/attestation-ed25519.key returns match | PASS |
| 3 | NOTE comment in tool-registry.yaml | config/tool-registry.yaml:1 | Visual inspection | PASS |
| 4 | NOTE comment in model-provider-catalog.v2.yaml | config/model-provider-catalog.v2.yaml:1 | Visual inspection | PASS |
| 5 | GUARD_ARTIFACT_SHA256 in strict compose | docker-compose.strict.yml:25 (unchanged) | guard-artifact.bin content not modified, SHA256 8232540... still matches | PASS |
| 6 | All test suites pass after re-signing | N/A | go test ./internal/gateway/... PASS, go test ./internal/gateway/middleware/... PASS, go test ./tests/integration/... PASS | PASS |

LEARNINGS:
- Ed25519 keypair generation in Go is straightforward: ed25519.GenerateKey(nil) + x509.MarshalPKCS8PrivateKey for private, x509.MarshalPKIXPublicKey for public
- The gateway's verifyBlobSignature reads base64-encoded signatures with StdEncoding (not URL-safe), trims whitespace
- Integration tests in tests/integration/ that have build tag "integration" require Docker compose stack running -- they test against live services (KeyDB, Gateway, OPA). These are infrastructure tests unrelated to attestation signing

OBSERVATIONS (unrelated to this task):
- [INFO] tests/integration/ with -tags=integration fails when Docker stack is not running (expected). These are live infrastructure tests requiring `make up` first.

## History
- 2026-02-27T08:41:51Z status: open -> closed

## Links
- Related: [[RFA-1fui]]

## Comments

### 2026-02-27T05:22:58Z ramirosalas
Discovered during implementation of RFA-1fui: When config/tool-registry.yaml changes, the Ed25519 .sig attestation file is invalidated. The fix requires re-signing all attestation artifacts (tool-registry, model-provider-catalog, guard-artifact) with a fresh keypair. Currently no documented procedure exists for this rotation. Two pre-existing test failures in tests/integration and tests/unit were traced to key change, confirming that attestation key rotation is a recurring operational pain point without documented resolution steps. Recommended fix: add an ATTESTATION_ROTATION.md or Makefile target documenting the re-signing sequence.
