
---

## [Added from Epic RFA-a2y retro - 2026-02-06]

### Document POC vs Production boundaries explicitly

**Priority:** Important

**Context:** Both stories in the SPIKE Nexus epic surfaced POC limitations discovered during implementation rather than documented upfront:
- Token ownership is per-request (stateless), not server-tracked
- Token expiry isn't enforced when IssuedAt=0
- Docker Compose uses InsecureSkipVerify for dev convenience

**Recommendation:** When creating POC-scoped stories:
1. **Sr. PM MUST explicitly list POC boundaries** in the story description (e.g., "POC Limitations: token ownership is per-request, not persistent")
2. ARCHITECTURE.md should have a "POC vs Production" section listing known shortcuts
3. Milestone demo scripts should note "POC limitation" when showing behavior that wouldn't be production-ready

**Applies to:** All POC-scoped epics, especially security-critical features

**Source stories:** RFA-a2y.1, RFA-a2y.2

