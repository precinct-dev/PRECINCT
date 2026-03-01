---
id: RFA-ezzf
title: "Bug: messaging-sim healthcheck missing CMD prefix breaks docker compose config"
status: closed
priority: 1
type: bug
parent: RFA-xynt
created_at: 2026-02-27T07:33:36Z
created_by: ramirosalas
updated_at: 2026-02-27T07:34:25Z
content_hash: "sha256:ab14f90c76b3a5f7d0c27fa7059a464365e57a058681303f9c95170ae377b014"
closed_at: 2026-02-27T07:34:25Z
---

## Description

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T07:34:25Z status: open -> closed

## Links
- Parent: [[RFA-xynt]]

## Comments

### 2026-02-27T07:33:41Z ramirosalas
Root cause: docker-compose.yml line 522 has test: ["/messaging-sim", "-healthcheck"] but Docker requires CMD prefix: ["CMD", "/messaging-sim", "-healthcheck"]. Introduced by RFA-ncf1 (messaging simulator). Blocks ALL Compose demos (compose-verify fails on docker compose config --format json). One-line fix.

### 2026-02-27T07:34:22Z ramirosalas
DISPOSITION [2026-02-26]: Close without story. This is a mechanical one-line fix -- adding the missing "CMD" prefix to the messaging-sim healthcheck array in docker-compose.yml line 522. Every other healthcheck (7/8) already has the CMD prefix; this was an oversight in RFA-ncf1. No architectural decision, no design, no new tests needed. The existing demo suite validates the fix (docker compose config --format json now parses cleanly). Precedent: RFA-iqij closed identically. Resolution: direct commit.
