# Prerequisites

This document outlines the prerequisites for running the Agentic Reference Architecture.

## Required Tools

### Docker Compose Deployment

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Docker | 25.0+ | Container runtime |
| Docker Compose | 2.24+ | Multi-container orchestration |
| Go | 1.23+ | Building gateway and services |
| Bash | 4.0+ | Setup scripts |

### Local Kubernetes Deployment

All of the above, plus:

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| kubectl | 1.28+ | Kubernetes CLI |
| kustomize | 5.0+ | Kubernetes manifest templating |
| Docker Desktop | Latest | Local Kubernetes cluster |

**Minimum Hardware (K8s):**
- 4 CPU cores
- 8GB RAM allocated to Docker Desktop

## Optional Tools

These tools enable additional security features but are not required for basic operation:

| Tool | Purpose | Degradation if Missing |
|------|---------|------------------------|
| gosec | Go source code security scanning | Go security vulnerabilities undetected |
| trivy | Container image and filesystem CVE scanning | Dependency vulnerabilities undetected |
| cosign | Container image signature verification | Image signing disabled |
| syft | SBOM generation | Supply chain transparency reduced |
| opa | Policy testing | Policy tests skipped in CI |

The setup wizard (`make setup`) will detect which optional tools are installed and report the security posture accordingly.

### Installing Optional Tools

**gosec** -- Static analysis tool for Go source code that detects security vulnerabilities (SQL injection, hardcoded credentials, insecure crypto, etc.):

```bash
# Install via go install
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Verify installation
gosec --version
```

For alternative installation methods, see: https://github.com/securego/gosec#install

**trivy** -- Comprehensive vulnerability scanner for container images, filesystems, and git repositories. Detects CVEs in OS packages and application dependencies:

```bash
# macOS (Homebrew)
brew install trivy

# Linux (apt)
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy

# Verify installation
trivy --version
```

For additional platforms and methods, see: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

**cosign** -- Signs and verifies container images using Sigstore:

```bash
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
```

**syft** -- Generates Software Bill of Materials (SBOM) for container images:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

**opa** -- Open Policy Agent for policy testing and evaluation:

```bash
# macOS (Homebrew)
brew install opa

# Linux
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod 755 opa && sudo mv opa /usr/local/bin/
```

## 30-Minute Setup Claim

**BUSINESS.MD O1** states:

> A new user can clone the repository and have the full security stack operational in under 30 minutes.

### What's Included in Timing

The 30-minute threshold includes:

1. Running `make setup` (interactive wizard)
2. Starting services (`docker compose up -d` or `make k8s-local-up`)
3. Waiting for all services to be healthy
4. Sending the first E2E request through the full middleware chain

### What's Excluded from Timing

**Container image pulls are excluded** from the 30-minute threshold because:

- Image pull time is network-dependent and varies significantly by location and connection speed
- Pre-pulling images via `docker compose pull` or `make build-images` is recommended
- The validation script (`tests/e2e/validate_setup_time.sh`) pre-pulls images before starting the timer

### Validating the Setup Time Claim

To validate the 30-minute claim for your environment:

```bash
# Docker Compose mode
make validate-setup-time MODE=compose

# Local Kubernetes mode
make validate-setup-time MODE=k8s
```

The validation script will:

1. Pre-pull all container images (excluded from timing)
2. Start the timer
3. Run `make setup` with default inputs
4. Start services
5. Wait for health checks to pass
6. Send a test request through the gateway
7. Stop the timer and report PASS/FAIL

**Dry-run mode** is available to validate configuration without actually starting services:

```bash
bash tests/e2e/validate_setup_time.sh compose --dry-run
bash tests/e2e/validate_setup_time.sh k8s --dry-run
```

## Quick Start

After installing the required tools:

```bash
# Clone the repository
git clone <repo-url>
cd POC

# Run the setup wizard (press Enter at each prompt for secure defaults)
make setup

# Start services (Docker Compose)
make up

# Verify the stack is running
curl -s http://localhost:9090/health
```

For detailed setup instructions, see the [Setup Guide](./setup-guide.md) (TODO).
