---
id: RFA-iqij
title: "Discovered: untracked compiled binary 'messaging-sim' not covered by .gitignore in POC directory"
status: closed
priority: 3
type: bug
parent: RFA-xynt
created_at: 2026-02-27T05:53:24Z
created_by: ramirosalas
updated_at: 2026-02-27T06:53:09Z
content_hash: "sha256:54da654457010cb290ce52a20083390a6d9c452275d0720f4dd6768ab9c4be7f"
related: [RFA-cweb]
closed_at: 2026-02-27T06:53:09Z
---

## Description

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T06:53:09Z status: open -> closed

## Links
- Parent: [[RFA-xynt]]
- Related: [[RFA-cweb]]

## Comments

### 2026-02-27T05:53:31Z ramirosalas
Discovered during review of RFA-cweb: A compiled binary named 'messaging-sim' exists at /Users/ramirosalas/workspace/agentic_reference_architecture/POC/messaging-sim. It is not covered by .gitignore. The .gitignore already covers 'gateway', '*.exe', and '*.out' (per project memory), but 'messaging-sim' is a named binary outside those patterns. Fix: add 'messaging-sim' to POC/.gitignore to prevent accidental commit of the compiled binary.

### 2026-02-27T06:53:03Z ramirosalas
DISPOSITION [2026-02-26]: Close without story. This is a one-line .gitignore edit (add /messaging-sim to the compiled binaries section). No architectural decision, no design requirement, no integration test scope. The .gitignore already lists 10+ named Go binaries in this pattern. Resolution: add '/messaging-sim' to POC/.gitignore under the 'Compiled Go binaries' header. This should be done as a direct commit, not a tracked story.
