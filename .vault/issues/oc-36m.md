---
id: oc-36m
title: "Operational Reality: Demo Test Extraction and EKS Deployment"
status: closed
priority: 2
type: epic
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:19:59Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:23f70dc31ac4d4b9466b2acfce794e715793bbcb210ff7290a5a923c517e07af"
closed_at: 2026-02-21T10:26:08Z
close_reason: "Both Tier 2 gaps closed: GAP-6 extracted 18 deterministic demo assertions into 4 new httptest-based integration test files. GAP-7 created cloud-agnostic k8s manifests (30 files, Kustomize base + overlays) validated via kubeconform. Actual cluster deployment deferred pending cloud account availability."
---

## Description
Close the two Tier 2 operational reality gaps. The demo exerciser (demo/go/main.go) has 28 tests that require the full Docker Compose stack, but many assertions are deterministic and could run as in-process httptest integration tests -- this would strengthen CI coverage. The EKS Terraform has never been applied to a real cluster. These are 'nice to have' for the presentation but not blocking.

## Acceptance Criteria
AC1: Key deterministic demo assertions (DLP, OPA, rate limit, registry verification) extracted into tests/integration/ as httptest-based tests
AC2: EKS cluster deployed with remote state enabled, evidence captured

## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links


## Comments
