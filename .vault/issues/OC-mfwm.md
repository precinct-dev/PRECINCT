---
id: OC-mfwm
title: "Documentation, Site, and Agents of Chaos Response"
status: closed
priority: 1
type: epic
created_at: 2026-03-08T02:33:46Z
created_by: ramirosalas
updated_at: 2026-03-08T17:35:04Z
content_hash: "sha256:a7abbceafa9c544d5eee94aa434640535543dc0f9727536f747195fa089f8959"
labels: [agents-of-chaos, documentation]
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## Business Context

The 'Agents of Chaos' paper (Shapira et al., 2026, arXiv:2602.20021v1) provides independent, third-party validation of the threat model that PRECINCT was built to defend against. The paper's 16 case studies across 20 researchers and a 2-week red-teaming exercise provide concrete evidence that every middleware layer in PRECINCT's 13-layer chain serves a real purpose. This epic updates all documentation and the PRECINCT website to reflect the new capabilities implemented in Epics 1-5, cite the paper, and position PRECINCT's comprehensive response to each documented threat.

## Problem Being Solved

After implementing Epics 1-5, the documentation and website will be out of date. The new capabilities (communication channel mediation, data source integrity, escalation detection, principal hierarchy, irreversibility classification) need to be documented in: the static site (site/), the reference architecture document (precinct-reference-architecture.md), the POC technical docs (POC/docs/), and the security/compliance documentation. Without this update, evaluators and auditors cannot understand the full scope of PRECINCT's defenses.

## Target State

Complete documentation coverage of all new capabilities:
- New site page dedicated to the 'Agents of Chaos' response
- Updated architecture, capabilities, and gateway site pages
- Updated reference architecture document
- Updated POC technical docs (ARCHITECTURE.md, api-reference.md, configuration-reference.md)
- Updated security and compliance documentation
- Site navigation updated to include new page

## Architecture Integration

Static site: site/ directory with 19 pages, custom CSS (site/css/style.css) with dark/light theme, vanilla JS (site/js/main.js). Pages: site/pages/*.html. Navigation structure in site/index.html and shared across pages.

POC docs: POC/docs/ with ARCHITECTURE.md, DESIGN.md, api-reference.md (v2.4.0), security/ directory, compliance/ directory, operations/ directory.

Reference architecture: precinct-reference-architecture.md at project root.

Security docs: precinct-security-review.md, precinct-stride-pasta-assurance.md, POC/docs/security/framework-taxonomy-signal-mappings.md, POC/docs/security/baseline.md.

Error code catalog: 25 codes in internal/gateway/middleware/error_codes.go, documented in api-reference.md.

Existing headers: X-SPIFFE-ID, X-Session-ID.

## Acceptance Criteria

1. New site page at site/pages/agents-of-chaos.html with paper summary, threat taxonomy table, and per-threat defense explanation
2. Architecture, capabilities, and gateway site pages updated with new capabilities
3. Reference architecture document updated with new sections
4. POC technical docs updated with new adapters, endpoints, headers, error codes, and configuration
5. Security and compliance documentation updated with new controls and paper citation
6. Site navigation includes new page, responsive design verified

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:04Z status: open -> closed

## Links


## Comments
