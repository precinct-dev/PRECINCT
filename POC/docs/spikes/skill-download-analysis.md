# Spike: Skill Download and Security Analysis (skulto Integration)

**Story:** RFA-5c8
**Priority:** P3 (Strategic / Exploratory for Phase 2)
**Date:** 2026-02-06
**Status:** Recommendation Complete

---

## 1. Executive Summary

This spike investigates how downloaded agent skills should be security-scanned before
they are permitted to interact with the PRECINCT Gateway, and whether skulto
(an open-source skill management tool) is a viable integration point.

**Recommendation: GO for Phase 2 design work, with a phased approach.**

Integrate skulto's scan output as a pre-registration gate for the existing tool registry
(ADR-006). Do NOT embed skulto into the gateway runtime. Instead, treat skulto as an
offline supply-chain tool that feeds into the signed tool registry YAML that the gateway
already consumes. This preserves the gateway's security invariants (no new runtime
dependencies) while adding skill-level supply-chain verification.

---

## 2. Research: skulto Current State and API Surface

### 2.1 What Is skulto?

[skulto](https://github.com/asteroid-belt/skulto) is an MIT-licensed, Go-based CLI tool
for managing AI coding assistant skills across 30+ platforms. Key characteristics:

| Attribute        | Value                                          |
|------------------|------------------------------------------------|
| Language         | Go 1.25+                                       |
| License          | MIT                                            |
| Architecture     | CLI (Cobra) + SQLite FTS5 + Bubble Tea TUI     |
| Install          | Homebrew, source build                         |
| Data store       | `~/.skulto/skulto.db` (SQLite)                 |
| MCP integration  | Built-in MCP server (`skulto-mcp`)             |
| Platforms        | Claude Code, Cursor, Windsurf, Copilot, 29+    |

### 2.2 skulto Security Scanner

skulto includes a built-in security scanner invoked via `skulto scan`. It performs:

1. **Prompt injection detection** in frontmatter, references, and script blocks
2. **Dangerous code pattern** identification (shell commands, data exfiltration)
3. **Threat level classification**: CRITICAL, HIGH, MEDIUM, LOW
4. **Filtering**: scan all skills, specific skills, pending items, or by repository

The scanner operates offline after initial repository sync (no cloud API calls for
scanning, unlike mcp-scan which sends tool descriptions to Invariant Labs).

### 2.3 skulto CLI Commands (Relevant to Integration)

| Command                | Purpose                                  |
|------------------------|------------------------------------------|
| `skulto install <repo>`| Download and install a skill             |
| `skulto pull`          | Sync all repositories                    |
| `skulto scan`          | Run security analysis                    |
| `skulto scan --format json` | Machine-readable scan output       |
| `skulto update`        | Combined pull + scan                     |

### 2.4 skulto MCP Server (`skulto-mcp`)

skulto ships an MCP server that exposes tools for:
- Semantic skill search
- Skill retrieval with metadata
- Installation/uninstallation management
- Tag browsing and statistics

This is relevant because agents could use the MCP server to discover and request
skill installation, which would then need to pass through security scanning before
the skill's tools are registered in the gateway.

### 2.5 Limitations and Gaps

| Gap                          | Impact                                          |
|------------------------------|------------------------------------------------|
| No cryptographic signing     | Skills are identified by repository, not by     |
|                              | signature. No author verification.              |
| Regex-based scanning only    | Similar to our DLP scanner -- effective for     |
|                              | known patterns, blind to novel attacks.         |
| No sandbox execution         | Skills are scanned statically only. No          |
|                              | behavioral analysis in an isolated environment. |
| No SBOM generation           | Cannot produce a dependency graph for skills    |
|                              | that reference external packages.               |
| Early maturity               | The tool is relatively new. API surface may     |
|                              | change.                                         |

---

## 3. Threat Model for Skill Downloads

### 3.1 The Emerging Threat Landscape

Recent research (Snyk ToxicSkills study, February 2026) auditing 3,984 AI agent skills
on ClawHub found:

- **13.4% of all skills** contain at least one critical-level security issue
- **36.82%** have at least one security flaw
- **100% of confirmed malicious skills** contain malicious code patterns
- **91% simultaneously employ prompt injection** alongside malware
- **10.9% contain hardcoded secrets** (API keys, credentials)

The academic literature (arXiv:2601.17548) reports that prompt injection attacks on
agentic coding assistants achieve **85%+ success rates** against state-of-the-art
defenses. Supply chain attacks via skills are a demonstrated, active threat.

### 3.2 Attack Vectors Relevant to Our Gateway

| Attack Vector              | Description                                    | Gateway Impact                                    |
|----------------------------|------------------------------------------------|--------------------------------------------------|
| **Tool poisoning**         | Malicious instructions embedded in tool         | Detected by existing poisoning patterns (step 5)  |
|                            | descriptions                                    | but only for registered tools                     |
| **Rug-pull attacks**       | Skill behavior changes after initial approval   | Detected by hash verification (step 5) and        |
|                            |                                                | hot-reload attestation (ADR-006)                  |
| **Prompt injection**       | Hidden directives in skill markdown             | Partially detected by DLP (step 7) and deep scan  |
|                            |                                                | (step 10), but skills load pre-gateway            |
| **Dependency hijacking**   | Skills reference malicious external packages    | NOT detected -- skills execute outside gateway    |
| **Credential harvesting**  | Skills instruct agents to read sensitive files  | Detected by DLP (step 7) on response path and     |
|                            |                                                | OPA policy (step 6) on tool access                |
| **Memory poisoning**       | Skills modify agent memory/configuration files  | NOT detected by gateway (agent-side concern)      |
| **Typosquatting**          | Deceptively named skills mimicking trusted ones | NOT detected -- requires registry-level defense   |

### 3.3 Trust Boundaries

```
                  UNTRUSTED                    TRUST BOUNDARY                   TRUSTED
              +----------------+          +---------------------+         +------------------+
              |                |          |                     |         |                  |
              | Skill          |  scan    | Pre-Registration    | signed  | Tool Registry    |
              | Repositories   | -------> | Security Gate       | ------> | (tool-registry   |
              | (GitHub, etc.) |          | (skulto + custom    |  YAML   |  .yaml + .sig)   |
              |                |          |  analysis)          |         |                  |
              +----------------+          +---------------------+         +------------------+
                                                                                |
                                                                                | runtime
                                                                                v
                                                                         +------------------+
                                                                         | Gateway          |
                                                                         | Middleware Chain  |
                                                                         | (13 steps)       |
                                                                         +------------------+
```

The critical insight: **skills must be validated BEFORE they reach the tool registry,
not at the gateway runtime.** The gateway trusts the signed registry (ADR-006). The
security gate must operate upstream of the registry.

---

## 4. Scanning Approaches

### 4.1 Static Analysis

Static analysis examines skill content without execution. This is what skulto and
mcp-scan currently provide.

**What it catches:**
- Prompt injection patterns (regex-based and LLM-based)
- Known malicious code patterns (shell commands, data exfiltration)
- Credential leakage (hardcoded API keys, secrets)
- Suspicious external references (URLs, package names)
- Tool description poisoning (hidden instructions)

**What it misses:**
- Obfuscated payloads (base64, Unicode tricks, word splitting)
- Novel attack patterns not in the pattern database
- Time-delayed behavior (behaves normally during scan, attacks later)
- Dependency chain attacks (the skill is clean, its dependencies are not)

**Recommended tools:**

| Tool                  | Approach              | Offline? | License      | Maturity  |
|---------------------- |---------------------- |----------|------------- |---------- |
| skulto scan           | Regex patterns        | Yes      | MIT          | Early     |
| mcp-scan (Invariant)  | API-based + local     | Partial  | Open source  | Moderate  |
| safedep/vet           | Behavioral analysis   | Yes      | Open source  | Early     |
| Our existing DLP      | Regex (credentials)   | Yes      | N/A (ours)   | Proven    |

### 4.2 Signature Verification

Cryptographic verification of skill provenance. Currently no standard exists for
skill signing, but the pattern is well-established in the container ecosystem:

**Proposed approach: cosign-blob for skill manifests.**

The gateway already uses cosign-blob for registry hot-reload (ADR-006, RFA-lo1.4).
Extending this to skill manifests is architecturally consistent:

1. Skill author signs the skill manifest with `cosign sign-blob`
2. Signature accompanies the skill in the repository
3. Pre-registration gate verifies signature before allowing registry update
4. Unsigned skills require explicit override (with audit trail)

**Gap:** No ecosystem-wide skill signing standard exists yet. skulto does not
support signature verification. This would need to be our own convention.

### 4.3 Sandbox Execution

Run the skill in an isolated environment to observe runtime behavior before
approving it for production use.

**Approaches by isolation strength:**

| Isolation Level       | Technology                | Startup Time | Security   |
|---------------------- |--------------------------|------------- |----------- |
| Process isolation     | Linux namespaces          | ~10ms        | Low        |
| Container isolation   | Docker / Podman           | ~500ms       | Medium     |
| MicroVM isolation     | Firecracker / gVisor      | ~125ms       | High       |
| Full VM isolation     | QEMU / VirtualBox         | ~5s          | Highest    |

**Recommended for Phase 2 design:** Container isolation via Docker. We already
require Docker for the development stack. Running a skill in a disposable container with:
- No network access (or allowlisted egress only)
- Read-only filesystem
- No access to host credentials or agent memory
- Time-limited execution (kill after N seconds)

**What sandbox testing would cover:**
- Does the skill attempt network egress to unexpected destinations?
- Does it attempt to read sensitive files outside its declared scope?
- Does it attempt to modify configuration files?
- Does it behave consistently across multiple runs? (rug-pull detection)

**Gap:** This is Phase 3 complexity. The infrastructure exists (Docker), but building
the sandbox orchestrator, behavioral analysis engine, and approval workflow is
non-trivial. For Phase 2, static analysis + signature verification is sufficient.

---

## 5. Integration Point Recommendation

### 5.1 Options Evaluated

| Option                          | Description                                       | Pros                                | Cons                                      |
|-------------------------------- |--------------------------------------------------|-------------------------------------|------------------------------------------ |
| **A. Gateway middleware**       | New middleware step between steps 5-6              | Real-time enforcement               | Adds latency, runtime dependency on       |
|                                 | that scans skill content on every request          |                                     | scanner, breaks middleware chain design    |
| **B. Tool registry gate**      | Offline scan before skill is added to              | Preserves runtime performance,      | Not real-time (scan happens at             |
|                                 | tool-registry.yaml                                 | uses existing attestation (ADR-006) | registration time, not request time)       |
| **C. Separate service**        | Standalone scan service (API) that the             | Decoupled, scalable, can run LLM-   | New service dependency, operational        |
|                                 | gateway or registry calls                          | based analysis                      | complexity, needs its own security         |

### 5.2 Recommendation: Option B -- Pre-Registration Gate (Tool Registry Level)

**Rationale:**

1. **Aligns with existing architecture.** The gateway already trusts the signed tool
   registry (ADR-006). Adding a pre-registration scan extends the supply chain
   without modifying the runtime middleware chain.

2. **No runtime latency impact.** Scanning happens once at registration time, not on
   every request. The gateway's 13-step chain is a security invariant (ARCHITECTURE.md
   Section 3.2); adding a 14th step for skill scanning would violate this.

3. **Cosign attestation already exists.** RFA-lo1.4 implemented Ed25519 signature
   verification for registry hot-reload. The same mechanism gates skill registration:
   skills pass scanning, their tools are added to registry YAML, the YAML is signed.

4. **Composable.** skulto's scan output (JSON) can be consumed by a script that
   generates tool registry entries. This script can also run our existing DLP patterns
   and the poisoning pattern detector from tool_registry.go.

5. **Defense in depth.** Even if a skill passes pre-registration scanning, the gateway
   still enforces:
   - Hash verification (step 5) -- detects post-registration tampering
   - Poisoning pattern detection (step 5) -- catches embedded instructions
   - DLP scanning (step 7) -- catches credential leakage at runtime
   - Deep scan (step 10) -- LLM-based prompt injection detection
   - OPA policy (step 6) -- authorization bounds
   - Token substitution (step 13) -- secrets never reach the agent

### 5.3 Proposed Architecture

```
                                        OFFLINE (registration time)
+------------------+    +-------------------+    +--------------------+    +-------------------+
| 1. skulto pull   | -> | 2. skulto scan    | -> | 3. Custom          | -> | 4. Sign + update  |
|    (download     |    |    (prompt inject, |    |    analysis:       |    |    tool-registry   |
|     skill repos) |    |     code patterns) |    |    - DLP patterns  |    |    .yaml + .sig    |
|                  |    |                    |    |    - hash compute  |    |                   |
|                  |    |    + mcp-scan      |    |    - dep check     |    |                   |
|                  |    |    (optional:      |    |    - policy check  |    |                   |
|                  |    |     tool poisoning)|    |                    |    |                   |
+------------------+    +-------------------+    +--------------------+    +-------------------+
                                                                                  |
                                                                          cosign sign-blob
                                                                                  |
                                                                                  v
                                                                         +-------------------+
                                                                         | 5. Gateway loads  |
                                                                         |    signed registry|
                                                                         |    via hot-reload |
                                                                         |    (ADR-006)      |
                                                                         +-------------------+
```

**Step-by-step flow:**

1. **Download:** `skulto pull` syncs skill repositories to local storage.

2. **Scan (skulto):** `skulto scan --format json` produces machine-readable
   security analysis with threat levels per skill.

3. **Custom analysis pipeline:**
   - Run our existing `containsPoisoningPattern()` logic against skill descriptions
   - Compute SHA-256 hashes (`ComputeHash()` from tool_registry.go)
   - Check for credential patterns (reuse DLP scanner regex)
   - Verify skill declares only approved allowed_destinations
   - (Optional) Run mcp-scan for additional coverage

4. **Generate and sign registry:** If all checks pass, generate tool registry YAML
   entries for the skill's tools and sign with `cosign sign-blob --key <key>`.

5. **Gateway hot-reload:** The gateway's existing Watch() + attestation mechanism
   (RFA-lo1.4) picks up the signed update automatically.

### 5.4 Why NOT Gateway Middleware (Option A)

- The middleware chain is a security invariant. Each step has a defined purpose.
  Adding a "skill scan" step conflates supply-chain verification (a registration-time
  concern) with runtime request processing.
- Scanning is computationally expensive (regex matching, potentially LLM calls).
  Running it per-request adds unacceptable latency.
- The gateway trusts its own registry. Runtime re-scanning of already-registered
  tools is redundant and indicates a trust model failure.

### 5.5 Why NOT Separate Service (Option C)

- Adds a new service to the Docker Compose stack. Phase 2 already adds SPIKE Nexus,
  KeyDB, spike-bootstrap, and OTel Collector. Operational complexity is a concern
  (BUSINESS.md Risk #6: resource-constrained laptops).
- The scan service itself becomes an attack surface. Who authenticates scan requests?
  What if the scan service is compromised?
- Overkill for Phase 2. A separate service makes sense at enterprise scale with
  hundreds of skills being registered per day. For a reference implementation,
  an offline pipeline is sufficient and more transparent.

---

## 6. Security Considerations

### 6.1 What This Architecture Protects Against

| Threat                           | Protection Layer                                |
|----------------------------------|------------------------------------------------|
| Prompt injection in skill desc   | skulto scan + our poisoning patterns + deep scan|
| Malicious code in skill scripts  | skulto scan (code pattern detection)            |
| Credential leakage in skills     | DLP patterns at scan time + runtime DLP (step 7)|
| Tool description tampering       | SHA-256 hash verification (step 5)              |
| Registry tampering               | cosign-blob attestation (ADR-006)               |
| Rug-pull (post-approval change)  | Hash mismatch detection (step 5)                |
| Unauthorized skill registration  | Signed registry (only holders of signing key    |
|                                  | can update)                                     |

### 6.2 What This Architecture Does NOT Protect Against

| Threat                           | Why Not                                         | Mitigation Path (Phase 3+)         |
|----------------------------------|------------------------------------------------|-------------------------------------|
| Novel/obfuscated attacks         | Regex-based scanning has known blind spots      | LLM-based deep scan of skills       |
| Dependency chain attacks         | No SBOM or transitive dependency analysis       | SBOM generation + vulnerability DB  |
| Time-delayed rug-pulls           | Static scan sees current state only             | Periodic re-scan + behavioral       |
|                                  |                                                | sandbox (Section 4.3)               |
| Zero-day exploits in skill code  | No sandbox execution in Phase 2                 | Firecracker-based sandbox           |
| Compromised signing key          | Key management is an operational concern         | HSM-backed keys, key rotation       |
| Social engineering (trusted      | Can pass all scans while being malicious in      | Human review + AI-BOM visibility    |
| author turns malicious)          | subtle ways                                      |                                     |

### 6.3 SPIFFE Identity for Skill Sources

If skills are registered with their source identity (e.g., the SPIFFE ID of the
registration workflow), the audit trail can track which entity approved each skill.
This connects to the existing audit logging (step 4) and compliance framework
(BUSINESS.md Section 7, GW-SC controls).

### 6.4 Compliance Implications

Adding skill download scanning maps to existing compliance controls:

| Framework       | Requirement                    | How Skill Scanning Helps          |
|-----------------|--------------------------------|-----------------------------------|
| SOC 2 Type II   | CC7.1 Detection                | Pre-registration scan is a        |
|                 |                                | detective control                 |
| ISO 27001       | A.14.2.7 Outsourced development| Skills are outsourced code;       |
|                 |                                | scanning proves due diligence     |
| SOC 2 Type II   | CC6.1 Logical access           | Only signed, scanned skills enter |
|                 |                                | the trusted registry              |
| GDPR            | Art. 28 Processor obligations  | Skills that process data are      |
|                 |                                | vetted before deployment          |

---

## 7. Implementation Phases

### Phase 2 (Current -- Design Only)

- Document the pre-registration gate architecture (this spike)
- No code implementation required
- Validate that skulto's JSON output format is stable enough to parse
- Confirm that our existing `containsPoisoningPattern()` and `ComputeHash()` functions
  can be reused in a standalone pipeline script

### Phase 2.5 (If Time Allows)

- Create `scripts/skill-register.sh` that orchestrates:
  1. `skulto scan --format json` on a skill
  2. Custom analysis (poisoning patterns, DLP, hash computation)
  3. YAML generation for tool-registry.yaml
  4. `cosign sign-blob` on the updated YAML
- Add a `make skill-register SKILL=<repo>` target
- Integration test: register a known-good skill, verify it appears in gateway

### Phase 3 (Future)

- Container-based sandbox for behavioral analysis
- LLM-based deep scan of skill content (reuse Groq Prompt Guard 2 infrastructure)
- SBOM generation for skill dependency chains
- Automated periodic re-scan of registered skills
- skulto-mcp integration for agent-driven skill discovery (with human-in-the-loop
  approval gate)

---

## 8. Alternative Tools Evaluated

| Tool                 | Approach                          | Offline | License       | Verdict                         |
|----------------------|-----------------------------------|---------|---------------|---------------------------------|
| **skulto**           | CLI, regex scanning, multi-platform| Yes    | MIT           | **Use for download + basic scan**|
| **mcp-scan**         | API-based + local checks          | Partial | Open source   | Optional supplement; sends data |
|                      | (Invariant Labs)                  |         |               | to external API                 |
| **Proximity**        | MCP server scanner                | Yes     | Open source   | Similar to mcp-scan, less mature|
| **safedep/vet**      | Behavioral analysis               | Yes     | Open source   | Promising but early             |
| **Snyk Evo**         | Runtime + scan                    | No      | Commercial    | Not open source; out of scope   |
|                      |                                   |         |               | for reference architecture      |

**Why skulto over alternatives:**
- MIT license (BUSINESS.md Section 5.1: enterprise-safe licensing)
- Go-based (same language as our gateway; could share code in Phase 3)
- Offline-first (BUSINESS.md Section 5.5: air-gapped capability)
- Built-in MCP server (future integration path for agent-driven discovery)
- Active development with security as a first-class concern

**Why NOT solely mcp-scan:**
- Sends tool descriptions to Invariant Labs API for analysis. This conflicts with
  our air-gapped requirement (BUSINESS.md Section 5.5) and introduces a third-party
  data flow that would need GDPR assessment.
- Can be used as an optional supplement in environments where external API access
  is acceptable.

---

## 9. Go/No-Go Recommendation

### GO -- With Conditions

**Proceed with Phase 2 design work** for the pre-registration gate architecture.
The approach integrates cleanly with our existing tool registry attestation
mechanism (ADR-006) without modifying the gateway runtime.

**Conditions for proceeding to implementation (Phase 2.5+):**

1. **skulto JSON output format must be documented and stable.** If the format is
   unstable, we add a thin adapter layer rather than coupling directly.

2. **No new runtime dependencies.** The gateway must NOT import or call skulto at
   request time. Skill scanning is strictly an offline, registration-time activity.

3. **Signing key management must be defined.** Who holds the key to sign the
   registry after skill registration? This is an operational decision that must be
   documented before implementation.

4. **The pipeline must be a script, not a service.** Keep it simple (Unix philosophy).
   A `make` target that shells out to skulto, runs custom analysis, and signs the
   result. No daemon, no API, no new container.

5. **Phase 3 sandbox design should be spiked separately.** Behavioral sandbox
   analysis is a significant engineering effort that deserves its own spike with
   a clear threat model and cost-benefit analysis.

---

## 10. References

- [skulto repository](https://github.com/asteroid-belt/skulto) -- MIT license, Go
- [mcp-scan (Invariant Labs)](https://github.com/invariantlabs-ai/mcp-scan) -- MCP security scanner
- [Snyk ToxicSkills study (Feb 2026)](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) -- 36.82% of skills have security flaws
- [Snyk: SKILL.md to Shell Access](https://snyk.io/articles/skill-md-shell-access/) -- Threat model for agent skills
- [safedep Agent Skills Threat Model](https://safedep.io/agent-skills-threat-model/) -- 10 attack vectors, defense layers
- [arXiv:2601.17548 -- Prompt Injection on Agentic Coding Assistants](https://arxiv.org/html/2601.17548v1) -- 85%+ attack success rate
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) -- Official MCP security guidance
- BUSINESS.md P2-4: Security scanning of downloaded skills
- ARCHITECTURE.md ADR-006: Registry hot-reload with attestation
- `internal/gateway/middleware/tool_registry.go`: Existing hash verification and poisoning detection

---

*This spike documents a recommendation for Phase 2 planning. No code changes are
required. Implementation stories should be created by the Sr. PM when skill
download security enters the active backlog.*
