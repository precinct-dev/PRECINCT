# Supply Chain Security: Hardened Base Images

**Last Updated**: 2026-02-05
**Context**: PRECINCT

## Executive Summary

This document defines the approved base images for all containerized services in the reference implementation, with a focus on minimizing attack surface through hardened, distroless, or minimal images. All images are pinned by digest to ensure supply chain integrity.

## Research Summary (2025-2026 Best Practices)

Based on current industry standards and security research:

### Docker Hardened Images Initiative
- Docker made 1,000+ hardened images freely available under Apache 2.0 license (Dec 2025)
- Reduces vulnerabilities by up to 95% compared to traditional community images
- Includes complete SBOM and SLSA Build Level 3 provenance
- Uses distroless runtime to minimize attack surface
- Source: [Docker Hardened Images Announcement](https://www.docker.com/blog/docker-hardened-images-for-every-developer/)

### Distroless Approach
- Google's distroless images contain only application runtime dependencies
- No shells, package managers, or OS utilities
- Smallest distroless image ~2MB (~50% of Alpine, <2% of Debian)
- Reduces vulnerabilities by 60-90% compared to full images
- Source: [Chainguard Distroless Guide](https://edu.chainguard.dev/chainguard/chainguard-images/about/getting-started-distroless/)

### Go-Specific Best Practices
- Multi-stage builds: builder stage with full toolchain, runtime stage with distroless
- Static linking required: `CGO_ENABLED=0` for distroless compatibility
- Security scanning shows 70%+ vulnerability reduction with distroless
- Source: [Go Multi-Stage Builds](https://oneuptime.com/blog/post/2026-01-07-go-docker-multi-stage/view)

### Python-Specific Best Practices
- Multi-stage builds: install dependencies in builder, copy to slim runtime
- Python distroless requires special handling (no pip in runtime)
- 90% size reduction and fewer CVEs with distroless vs standard python:3.x
- Source: [Python Distroless Containers](https://dev.to/docker/docker-just-made-hardened-images-free-for-everyone-lets-check-them-out-499h)

## Approved Base Images

### Go Services (PRECINCT Gateway, precinct CLI, Context Fetcher)

**Builder Stage:**
```dockerfile
FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f
```
- **Rationale**: Official Go image with Alpine base, minimal toolchain
- **Security**: Regular security updates, minimal dependencies
- **Size**: Smaller builder reduces build cache size
- **Note**: Update digest monthly or when security advisories are published
- **Digest Date**: 2026-02-05

**Runtime Stage (Recommended):**
```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot@sha256:cba10d7abd3e203428e86f5b2d7fd5eb7d8987c387864ae4996cf97191b33764
```
- **Rationale**: Google distroless static image (no libc), runs as non-root user
- **Security**: No shell, no package manager, minimal attack surface
- **Requirements**: Requires `CGO_ENABLED=0` for static linking
- **User**: Runs as UID 65532 (nonroot)
- **Size**: ~2MB runtime image
- **Digest Date**: 2026-02-05

**Runtime Stage (Alternative - if CGO needed):**
```dockerfile
FROM gcr.io/distroless/base-debian12:nonroot@sha256:[DIGEST]
```
- **Rationale**: Includes glibc for CGO dependencies
- **Security**: Still distroless (no shell/package manager), non-root
- **Size**: ~20MB runtime image

### Python Agents (DSPy, PydanticAI)

**Builder Stage:**
```dockerfile
FROM python:3.12-slim-bookworm@sha256:73dbd1a2ad74137451593a8ac30f7bdd0f5010fc05fb34644190cffa7696bbf3
```
- **Rationale**: Official Python slim image based on Debian Bookworm
- **Security**: Debian security updates, minimal system packages
- **Size**: ~120MB (vs ~900MB for full python:3.12)
- **Note**: Update digest monthly
- **Digest Date**: 2026-02-05

**Runtime Stage (Recommended):**
```dockerfile
FROM python:3.12-slim-bookworm@sha256:73dbd1a2ad74137451593a8ac30f7bdd0f5010fc05fb34644190cffa7696bbf3
```
- **Rationale**: Currently, Python distroless is challenging for AI agents with many dependencies
- **Security**: Slim variant removes most unnecessary packages
- **Future**: Migrate to `gcr.io/distroless/python3-debian12:nonroot` when dependency footprint is finalized
- **User**: Create non-root user in Dockerfile (UID 1000)

**Runtime Stage (Future Distroless):**
```dockerfile
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:[DIGEST]
```
- **Rationale**: True distroless for maximum security
- **Requirements**: All dependencies must be installed in builder and copied
- **Challenge**: Complex dependency trees may require custom distroless build
- **Size**: ~50MB runtime image

## Image Pinning Strategy

All images MUST be pinned by digest, not just tag:

**WRONG:**
```dockerfile
FROM golang:1.23-alpine
```

**CORRECT:**
```dockerfile
FROM golang:1.23-alpine@sha256:abc123...
```

### Digest Update Policy
1. **Monthly**: Check for updated base image digests
2. **Security advisories**: Update immediately when CVEs are published
3. **Automated**: Use Renovate Bot or Dependabot to track digest updates
4. **Verification**: Always verify digest with `docker pull` before updating

### Getting Current Digests

```bash
# Pull image and get digest
docker pull golang:1.23-alpine
docker inspect golang:1.23-alpine --format='{{.RepoDigests}}'

# Or use crane (recommended for CI/CD)
crane digest golang:1.23-alpine
```

## Multi-Stage Build Pattern

All Dockerfiles MUST use multi-stage builds to:
1. Separate build-time dependencies from runtime
2. Minimize final image size
3. Reduce attack surface (no build tools in production)
4. Enable layer caching for faster builds

See template Dockerfiles:
- `deploy/compose/Dockerfile.go-service` - Go services template
- `deploy/compose/Dockerfile.python-agent` - Python agents template

## Docker Ignore

The `.dockerignore` file prevents unnecessary files from being included in build context:
- Reduces build context size (faster uploads)
- Prevents secrets from being copied into images
- Improves layer caching

## Security Scanning

All images MUST be scanned before deployment:

```bash
# Trivy (recommended)
trivy image <image-name>:latest

# Docker Scout
docker scout cves <image-name>:latest

# Grype
grype <image-name>:latest
```

**Acceptance Criteria:**
- CRITICAL: 0 vulnerabilities
- HIGH: 0 vulnerabilities
- MEDIUM: Review and document exceptions
- LOW: Acceptable with documentation

## Image Registry Strategy

**Development:**
- Local builds: `localhost/<service>:latest`
- No registry push required

**Production:**
- Private registry (e.g., GitHub Container Registry, AWS ECR)
- Image signing with cosign (SLSA provenance)
- Vulnerability scanning gates

## References

1. [Docker Hardened Images](https://www.docker.com/blog/docker-hardened-images-for-every-developer/)
2. [Chainguard Distroless Guide](https://edu.chainguard.dev/chainguard/chainguard-images/about/getting-started-distroless/)
3. [Go Multi-Stage Builds](https://oneuptime.com/blog/post/2026-01-07-go-docker-multi-stage/view)
4. [Dockerfile Security Best Practices](https://sysdig.com/blog/dockerfile-best-practices/)
5. [Multi-Stage Builds and Distroless](https://dev.to/suzuki0430/optimizing-docker-images-with-multi-stage-builds-and-distroless-approach-h0l)
6. [Python Distroless Containers](https://alex-moss.medium.com/creating-an-up-to-date-python-distroless-container-image-e3da728d7a80)

## Maintenance Schedule

- **Weekly**: Monitor security advisories
- **Monthly**: Update base image digests
- **Quarterly**: Review and update this document
- **On CVE**: Immediate digest updates and rebuilds

## Contact

For questions or exceptions to this policy, contact the security team or open an issue in the project repository.
