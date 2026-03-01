---
id: RFA-9tyg
title: "Bug: Dockerfile.messaging-sim FROM references missing digest pins"
status: closed
priority: 1
type: bug
parent: RFA-xynt
created_at: 2026-02-27T07:37:53Z
created_by: ramirosalas
updated_at: 2026-02-27T07:39:10Z
content_hash: "sha256:ab14f90c76b3a5f7d0c27fa7059a464365e57a058681303f9c95170ae377b014"
---

## Description

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T07:39:10Z status: open -> closed

## Links
- Parent: [[RFA-xynt]]

## Comments

### 2026-02-27T07:37:56Z ramirosalas
Dockerfile.messaging-sim lines 4 and 11 use unpinned golang:1.24-alpine and gcr.io/distroless/static-debian12. compose-verify rejects the stack. One-line-each fix matching convention in other Dockerfiles. Precedent: RFA-iqij, RFA-ezzf closed as trivial.
