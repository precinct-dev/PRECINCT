---
id: OC-jyva
title: "New Site Page -- Threat Defense: Agents of Chaos"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, documentation, delivered]
parent: OC-mfwm
created_at: 2026-03-08T02:45:36Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:a80a6e9b9f253eb5d529f8d6a1489ffc71d7ed6ba857c118f9065776792cf8a3"
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a security evaluator visiting the PRECINCT website, I need a dedicated page explaining how PRECINCT defends against the threats documented in the 'Agents of Chaos' paper so that I can understand the mapping between documented threats and PRECINCT's middleware defenses.

## Context

The PRECINCT static site lives in site/ with 19 pages, custom CSS (site/css/style.css) supporting dark/light theme, vanilla JS (site/js/main.js). Pages are in site/pages/*.html. Navigation is shared across pages.

The paper (Shapira et al., 2026, arXiv:2602.20021v1) documents 16 case studies from a 2-week red-teaming exercise with 20 researchers against autonomous LLM agents deployed with Discord, email, shell access, and persistent memory. The agents used an OpenClaw-based deployment.

PRECINCT's 13-layer middleware chain (steps 0-13 plus Response Firewall) provides defense against these threats. The mapping:
- Identity spoofing (#8) -> SPIFFE/SPIRE (step 3)
- Non-owner compliance (#2) -> OPA policy (step 6) + Principal Hierarchy (new)
- Sensitive info disclosure (#3) -> DLP (step 7) + Email adapter mediation (new)
- Resource looping (#4) -> Rate limiting (step 11) + Discord adapter mediation (new)
- DoS (#5) -> Request size limit (step 1) + Rate limiting (step 11)
- Provider bias (#6) -> Audit logging (step 4) + Model egress governance
- Social pressure (#7) -> Concession accumulator + Escalation detection (new)
- Agent corruption (#10) -> Data source integrity registry (new) + Deep scan (step 10)
- Libelous broadcasts (#11) -> Principal hierarchy (new) + Email adapter mass-send step-up
- Prompt injection (#12) -> Deep scan (step 10) + DLP (step 7)

## Implementation

Create site/pages/agents-of-chaos.html with:

1. Page header and introduction:
   - Title: "Threat Defense: Agents of Chaos"
   - Paper citation: Shapira et al., 2026, arXiv:2602.20021v1
   - Brief summary: 16 case studies, 20 researchers, 2-week red-teaming exercise

2. Threat taxonomy table:
   - Columns: Case Study #, Threat Category, Description, Severity, PRECINCT Coverage
   - All 16 case studies listed
   - Coverage status: Fully Defended, Partially Defended (now upgraded), New Defense

3. Per-threat defense explanation:
   - For each threat category: which middleware layer(s) defend against it
   - Architecture references: which steps in the 13-layer chain apply
   - New capabilities: channel mediation, data source integrity, escalation detection, principal hierarchy, irreversibility

4. Architecture diagram section:
   - Show where each defense applies in the 13-layer chain
   - Visual mapping of threats to middleware steps

5. "Boundary vs. Cognition" section:
   - Explain what infrastructure-level controls CAN solve (mediation, policy, detection)
   - Explain what they CANNOT solve (agent reasoning, instruction following, long-term memory coherence)
   - Position PRECINCT as infrastructure defense, not cognitive defense

6. Links to relevant pages: architecture.html, capabilities.html, gateway.html, and adapter documentation

Styling: consistent with existing site pages. Use site/css/style.css classes. Dark/light theme support. Responsive design.

## Key Files

- site/pages/agents-of-chaos.html (create)

## Testing

- Visual verification: page renders correctly in both dark and light themes
- All internal links resolve to existing pages
- Responsive design verified at mobile and desktop widths
- Paper citation is accurate (arXiv:2602.20021v1)

## Acceptance Criteria

1. site/pages/agents-of-chaos.html created with consistent site styling
2. Paper summary with accurate citation (Shapira et al., 2026, arXiv:2602.20021v1)
3. Threat taxonomy table covering all 16 case studies with coverage status
4. Per-threat defense explanation mapping to specific middleware layers
5. Architecture diagram showing threat-to-defense mapping
6. "Boundary vs. Cognition" section explaining infrastructure vs. cognitive defense limits
7. Links to related pages (architecture, capabilities, gateway)
8. Dark/light theme rendering verified
9. Responsive design at mobile and desktop widths

## Scope Boundary

This story creates the new page content ONLY. Navigation integration is story OC-mfwm-6.6. Updates to existing pages are stories 6.2-6.5.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:04Z dep_removed: no_longer_blocks OC-74k5

## Links
- Parent: [[OC-mfwm]]

## Comments
