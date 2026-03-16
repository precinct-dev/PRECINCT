# Container Image Signing with Cosign

Story: RFA-9fv.6

## Overview

This project uses [cosign](https://docs.sigstore.dev/cosign/overview/) for container
image signing. We use **keyless signing** with OIDC identity, which means:

- No private keys to manage or rotate
- Signatures are bound to the identity that created them (GitHub Actions OIDC token)
- Verification uses the Sigstore transparency log (Rekor) and certificate authority (Fulcio)

## GitHub Actions (CI/CD)

In CI, cosign signs images automatically using the GitHub Actions OIDC token. This is
configured in `.github/workflows/ci.yaml` with:

```yaml
permissions:
  id-token: write  # Required for OIDC token
```

The signing step:

```bash
cosign sign --yes <registry>/<image>@<digest>
```

The `--yes` flag is required for non-interactive (CI) mode. The `COSIGN_EXPERIMENTAL=1`
environment variable enables keyless signing.

## Verifying Signatures

To verify a signed image from this repository:

```bash
# Verify image was signed by this GitHub Actions workflow
cosign verify \
  --certificate-identity-regexp="https://github.com/OWNER/REPO/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/OWNER/precinct/precinct-gateway:dev
```

Replace `OWNER/REPO` with the actual GitHub repository path.

## Local Signing (Development)

For local development, you can sign images using your own identity:

```bash
# Sign (opens browser for OIDC authentication)
cosign sign --yes ghcr.io/OWNER/precinct/precinct-gateway:dev

# Verify
cosign verify \
  --certificate-identity="your-email@example.com" \
  --certificate-oidc-issuer="https://accounts.google.com" \
  ghcr.io/OWNER/precinct/precinct-gateway:dev
```

## Promotion Verification

Before promoting images between environments (dev -> staging -> prod), the
`promote.yaml` workflow verifies the source image signature:

```bash
cosign verify \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  <source-image>
```

Only images with valid signatures from GitHub Actions can be promoted.

## SBOM Attachment

SBOMs are generated with [syft](https://github.com/anchore/syft) and attached to
the signed image using cosign:

```bash
cosign attach sbom --sbom sbom.spdx.json <image>@<digest>
```

## Installing Cosign

```bash
# macOS
brew install cosign

# Linux (via go install)
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Or download from releases
# https://github.com/sigstore/cosign/releases
```
