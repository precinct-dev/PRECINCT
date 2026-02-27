# Retrospective: Epic RFA-xynt -- WS Mediation via HTTP-Only Egress

**Date:** 2026-02-26
**Stories completed:** 9 (RFA-1fui, RFA-ncf1, RFA-np7t, RFA-zxnh, RFA-cweb, RFA-mbmr, RFA-ajf6, RFA-yt63, RFA-xzj6)
**P3 discovered issues:** 2 (RFA-exak attestation doc gap, RFA-iqij untracked binary)
**Stories rejected:** 1 (RFA-yt63, rejected 3 times before acceptance on 4th attempt)
**Stories accepted first try:** 8/9 (89%)

---

## Summary

This epic proved that WebSocket frames can be mediated through the full 13-step gateway middleware
chain via HTTP-only egress. All outbound messaging (WhatsApp, Telegram, Slack) is forced through
the tool plane as regular HTTP POSTs -- no WS dial-out. Inbound webhooks enter via the ingress plane
with connector conformance. The epic also established per-message SPIKE token resolution (distinct
from upgrade-time token substitution) and an internal loopback architecture for inbound webhook
middleware traversal.

The walking skeleton pattern worked well: RFA-1fui established the vertical slice, then 7 parallel
stories extended and hardened it. Two parallelism layers were executed cleanly (Layer 1:
RFA-zxnh + RFA-cweb in parallel; Layer 2: RFA-mbmr + RFA-ajf6 in parallel).

The major process failure was RFA-yt63 requiring 4 review cycles. The root cause was consistent:
t.Logf used where t.Errorf/t.Fatalf was required, making tests pass unconditionally regardless of
outcome. This is a systemic pattern that has appeared in previous epics.

---

## Raw Learnings Extracted

### From RFA-1fui (walking skeleton)

- Modifying config/tool-registry.yaml invalidates the Ed25519 .sig file; all attestation artifacts
  (tool-registry, model-provider-catalog, guard-artifact) must be re-signed with a fresh keypair.
- Docker Compose seeder unit tests parse docker-compose.yml with strict type enforcement: Environment
  MUST be in list form ("- KEY=VALUE"), not map form (KEY: "VALUE").
- The PortGatewayServices compile-time check (var _ PortGatewayServices = (*Gateway)(nil)) catches
  interface violations immediately at build time.
- [Observation] Two test failures in tests/integration and tests/unit were pre-existing after
  attestation key change, confirming attestation keypair rotation lacks a documented procedure.

**First delivery gap:** SPIKE token resolution (auth_ref passed verbatim as Bearer header without
calling the redeemer). WS integration test absent (smoke script only curled HTTP endpoints directly,
never exercised the WS-to-egress path).

### From RFA-ncf1 (messaging simulator extension)

- Go 1.22+ ServeMux performs prefix matching ONLY when the pattern ends with '/'. A handler
  registered at "/bot" matches ONLY the exact path "/bot", NOT "/botMYTOKEN/sendMessage".
- Telegram's API path format (/bot<token>/sendMessage) cannot be expressed as a clean Go ServeMux
  pattern without using a catch-all dispatcher.
- Unit tests calling handler functions directly bypass the mux entirely. A routing bug can be
  present in production while all unit tests pass, because the tests never exercise the real HTTP
  server mux routing.
- Fix: extract newMux() for testability; add an httptest.NewServer test against the actual mux
  routing (not direct handler invocations) as the regression gate.

### From RFA-np7t (OPA/config/exfiltration rules)

- OPA test package naming convention: the test package for package "mcp.exfiltration" should be
  "mcp.exfiltration_test" (mirroring Go's _test package convention).
- Tool registry changes require attestation re-signing (same as RFA-1fui observation).
- No rejections; clean first delivery.

### From RFA-zxnh (hardened egress)

- HTTPS enforcement outside local development requires explicit check: non-local + non-single-label
  hostnames must use https. The isSingleLabelHostname helper (single-label = internal network) is
  the correct discriminator.
- Integration tests for unit-scope stories should be explicitly deferred to the integration test
  story (RFA-yt63) and documented in the story text. Sr. PM must document infeasibility if that
  deferral is to be accepted by PM-Acceptor.
- Clean first delivery.

### From RFA-cweb (webhook receiver)

- Internal loopback (POST to own /v1/ingress/submit) is the correct architecture for webhooks that
  must traverse the full middleware chain. Direct PlaneRequestV2 evaluation bypasses DLP, rate
  limiting, and audit.
- Two-layer defense: (1) webhook handler checks connector conformance fast path; (2) loopback POST
  goes through full middleware chain including connector check in handleIngressAdmit.
- InsecureSkipVerify is required for internal loopback to the gateway's own self-signed TLS cert.
  This is a POC-scoped shortcut and must be documented.
- [Discovered issue] Compiled binary 'messaging-sim' was present in POC root directory, not covered
  by .gitignore. Developer noticed and raised as P3 bug RFA-iqij.

### From RFA-mbmr (WS handler extensions)

- Per-message SPIKE token resolution is architecturally distinct from upgrade-time token
  substitution. Middleware runs once at HTTP upgrade. The adapter must resolve SPIKE refs per WS
  frame by calling the redeemer directly.
- Extracting resolveSPIKERef as a reusable Adapter method enables testability and reuse across
  message.send and future methods.
- The SecretRedeemer must be accessible via PortGatewayServices or constructor injection; it cannot
  be reached from inside WS frame handlers without this explicit exposure.
- Clean first delivery.

### From RFA-ajf6 (SPIKE secret seeding)

- When prior stories (RFA-mbmr in this case) already implement the required functionality and the
  code is compatible, a story can be accepted without code changes. Verify what was already delivered
  before writing new code.
- POCSecretRedeemer's generic pattern (returns "secret-value-for-<ref>") covers any new SPIKE
  reference without modification. New secrets only need to be seeded; no redeemer code changes.
- Clean first delivery (no code changes needed).

### From RFA-yt63 (integration tests -- 4 review cycles)

**Rejection 1:** Three required scenarios (DLP, exfiltration, OPA) were silently dropped and
replaced with extra platform/status/register WS tests. No service readiness patterns. Weak
assertions on Tests 8 (webhook middleware traversal) and 9 (unregistered connector).

**Rejection 2:** Audit log check (Test 8) and OPA check (Test 4) used t.Logf throughout.
Tests passed unconditionally regardless of outcome. The developer used t.Logf even on paths
that were supposed to be blocking assertions.

**Rejection 3:** Same issue -- developer kept using t.Logf where hard assertions were required.
Gap A: audit log present but missing ingress entries logged as warning, not failure. Gap B:
OPA response structure not asserted (t.Logf only), test cannot distinguish working OPA from
broken OPA.

**Acceptance on 4th attempt:** Gap A fixed with t.Errorf when audit log present but missing
ingress entries. Gap B fixed with t.Fatalf on invalid HTTP status, non-JSON response, or missing
decision field.

**Pattern:** t.Logf is not an assertion. A test body that uses only t.Logf is a logging exercise,
not a test. PM-Acceptor correctly identified this pattern across 3 consecutive rejections.

### From RFA-xzj6 (E2E scenarios)

- ws-e2e-client must be a standalone CLI binary (package main, func main), NOT a Go test wrapper.
  E2E scripts must use external tools (curl, CLI binaries) and must NOT call go test -tags=integration.
- The distinction between integration tests (RFA-yt63) and E2E scripts (RFA-xzj6) is:
  integration tests verify detailed behavioral assertions; E2E scripts prove the system works from
  the outside as an operator would use it.
- The ws-e2e-client exits 0 if response ok==true, 1 otherwise. This makes it composable with
  bash set -euo pipefail scripts.
- Build binary to build/ (ephemeral) in the script itself, not as a pre-built artifact.
- Clean first delivery.

---

## Patterns Identified

1. **t.Logf masquerading as assertions** (seen in RFA-yt63, 3 consecutive rejections)
   The developer consistently used t.Logf where t.Errorf/t.Fatalf was required. This creates tests
   that always pass regardless of the actual outcome.

2. **Mux-level routing bugs hidden by direct handler tests** (seen in RFA-ncf1)
   Tests calling handler functions directly bypass the HTTP mux. Routing bugs are invisible until
   the real server is exercised. A mux-level integration test (httptest.NewServer + mux) would have
   caught the Telegram routing bug immediately.

3. **Config changes invalidate attestation artifacts** (seen in RFA-1fui, RFA-np7t)
   Modifying tool-registry.yaml triggers attestation re-signing. This is a recurring operational
   friction point with no documented rotation procedure. Two pre-existing test failures were caused
   by this exact issue (RFA-exak).

4. **Middleware-level vs adapter-level credential resolution** (seen in RFA-1fui, RFA-mbmr, RFA-ajf6)
   The walking skeleton's first delivery passed auth_ref verbatim without resolving it through the
   redeemer. The architectural distinction (upgrade-time middleware vs per-frame adapter) is subtle
   and was only caught by PM-Acceptor inspection of the code path.

5. **Prior story delivery covers subsequent story scope** (seen in RFA-ajf6)
   RFA-ajf6 was accepted with zero new code because RFA-mbmr already delivered the required
   capability. Explicitly verifying what prior stories delivered before writing new code saves
   implementation time.

6. **Walking skeleton + parallel extension layers work** (process positive)
   RFA-1fui established the vertical slice. Layer 1 (RFA-zxnh + RFA-cweb) and Layer 2
   (RFA-mbmr + RFA-ajf6) ran in parallel cleanly. No merge conflicts, no coordination failures.

---

## Actionable Insights

### [TESTING] t.Logf is not an assertion -- enforce at review

**Priority:** Critical

**Context:** RFA-yt63 was rejected 3 times consecutively because t.Logf was used instead of
t.Errorf/t.Fatalf on paths that should fail the test. The developer understood the code logic but
misunderstood Go's testing semantics: t.Logf only appends to the log buffer; it does not mark the
test as failed. A test body using only t.Logf passes unconditionally.

**Recommendation:**
1. PM-Acceptor must check any test that "passes always" -- if a test never calls t.Fatal, t.Error,
   require.*, or assert.* (testify), it is a logging exercise, not a test.
2. For security-critical assertions (audit log present, connector rejected, OPA decision exists),
   the PM-Acceptor checklist should explicitly verify: "does test X actually FAIL when the condition
   is not met?"
3. Developer agents should be instructed: "t.Logf is for diagnostics. Use t.Errorf for non-fatal
   assertion failures, t.Fatalf for fatal assertion failures. t.Logf NEVER makes a test fail."
4. A linter rule (e.g., thelper, noctx) or code review check can flag test functions that contain
   no t.Error/t.Fatal calls.

**Applies to:** All integration and unit test stories

**Source stories:** RFA-yt63 (rejected 3 times)

---

### [TESTING] HTTP mux routing must be tested at the mux level, not via direct handler calls

**Priority:** Important

**Context:** RFA-ncf1 delivered a Telegram routing handler registered at "/bot" in Go 1.22+
ServeMux. The actual Telegram path format is "/botMYTOKEN/sendMessage", which the "/bot" pattern
does NOT match (Go 1.22 ServeMux requires patterns ending with '/' for prefix matching). All 10
unit tests passed because they called the handler function directly, bypassing the mux. The live
server returned 404 for every real Telegram request.

**Recommendation:**
1. For any server that uses path-based routing, include at least one test that exercises the REAL
   mux (via httptest.NewServer with the actual mux, not direct handler calls).
2. Go 1.22+ ServeMux: prefix matching requires trailing '/'. If a path segment varies (e.g.,
   /bot<token>/sendMessage), use a catch-all "/" handler with prefix dispatch inside.
3. The mux-level regression test (httptest.NewServer + mux + real HTTP request) should be
   considered a mandatory additional test case whenever a new HTTP path is registered.

**Applies to:** All stories registering new HTTP routes, especially with dynamic path segments

**Source stories:** RFA-ncf1 (rejected once for routing bug)

---

### [ARCHITECTURE] Attestation artifact re-signing procedure must be documented and automated

**Priority:** Important

**Context:** Config/tool-registry.yaml changes invalidate the Ed25519 .sig attestation files.
Two pre-existing integration test failures were traced to this (RFA-exak). The re-signing sequence
is known but undocumented: re-sign tool-registry, model-provider-catalog, and guard-artifact with
a fresh keypair. Without documentation, every developer who touches tool-registry.yaml will hit
the same test failures and spend debugging time before finding the cause.

**Recommendation:**
1. Create a Makefile target (e.g., make attestation-resign) that runs the re-signing sequence
   for all three artifacts.
2. Add a comment to config/tool-registry.yaml: "Modifying this file requires running
   make attestation-resign to update signature files."
3. The attestation re-signing sequence should be documented in ATTESTATION_ROTATION.md or
   equivalent, covering: which artifacts, which command, what keypair format, and where to
   store the new keypair.
4. CI should run tests/integration after any change to config/*.yaml to catch key mismatches early.

**Applies to:** All stories that modify config/tool-registry.yaml, config/opa/tool_registry.yaml,
or any attested configuration artifact

**Source stories:** RFA-1fui, RFA-np7t, RFA-exak (P3 issue)

---

### [ARCHITECTURE] Per-message SPIKE resolution is distinct from upgrade-time token substitution

**Priority:** Critical

**Context:** The HTTP middleware chain runs ONCE on the WS upgrade request. Token substitution
(step 13) processes the HTTP Authorization header at upgrade time. Per-message credentials carried
in WS frame params (auth_ref field) must be resolved by the adapter directly, not by the middleware
chain. RFA-1fui's first delivery passed auth_ref verbatim as the Bearer token without calling the
redeemer, which would have sent the raw spike:// URI to external APIs.

**Recommendation:**
1. In all future WS handler stories, document explicitly: "Per-message SPIKE resolution happens
   in the adapter via resolveSPIKERef(), NOT via middleware token substitution."
2. Any WS frame that carries credentials MUST route those credentials through resolveSPIKERef().
3. The integration test for per-message SPIKE resolution must verify the resolved value (e.g.,
   "secret-value-for-whatsapp-api-key") rather than just that the request succeeded.
4. PM-Acceptor checklist for WS stories with auth_ref: "Verify the redeemer is called, not
   auth_ref passed verbatim."

**Applies to:** All WS handler stories that involve per-message credentials or SPIKE references

**Source stories:** RFA-1fui (rejected once), RFA-mbmr, RFA-ajf6

---

### [ARCHITECTURE] Internal loopback is the correct pattern for webhook middleware traversal

**Priority:** Important

**Context:** The webhook receiver (RFA-cweb) must ensure inbound webhook payloads traverse the
full 13-step middleware chain (DLP, rate limiting, audit, etc.). The correct implementation is an
internal HTTP POST to the gateway's own /v1/ingress/submit endpoint. Direct PlaneRequestV2
evaluation bypasses DLP, rate limiting, and audit.

**Recommendation:**
1. Document internal loopback as an architectural pattern: any new inbound path that must traverse
   the full middleware chain should POST to /v1/ingress/submit internally.
2. The loopback client requires InsecureSkipVerify for self-signed TLS in POC mode. Document this
   as a POC limitation with a note about production certificate trust.
3. Integration tests for webhook stories must explicitly verify middleware chain traversal (e.g.,
   audit log entries for the /v1/ingress/submit path), not just that the endpoint returns 200.

**Applies to:** All stories adding new inbound data paths to the gateway

**Source stories:** RFA-cweb, RFA-yt63

---

### [TESTING] Service readiness patterns are mandatory for integration tests

**Priority:** Important

**Context:** RFA-yt63's first delivery had no service readiness patterns. Tests would fail with
connection refused on a cold Compose startup with no diagnostic information. The fix required adding
waitForGatewayWS and waitForService helpers with exponential backoff before tests execute.

**Recommendation:**
1. Integration tests MUST include a TestMain or per-test readiness check that polls service health
   endpoints before running assertions.
2. Minimum readiness set for messaging tests: gateway WS endpoint, messaging simulator health,
   gateway HTTPS health.
3. The retry pattern should use exponential backoff (not fixed sleep) with a configurable timeout
   (60-120 seconds for cold Compose startup).
4. If a service is not ready within the timeout, the test should fail with a clear message:
   "Service X not ready after Y seconds -- is the Compose stack running?"

**Applies to:** All integration test stories that run against Docker Compose stacks

**Source stories:** RFA-yt63 (rejected for missing readiness patterns)

---

### [PROCESS] Verify prior story deliveries before writing new code

**Priority:** Nice-to-have

**Context:** RFA-ajf6 was accepted with zero new code because RFA-mbmr had already delivered the
required capability (resolveSPIKERef, SecretRedeemer exposure via PortGatewayServices, SPIKE
seeding in docker-compose.yml via prior stories). The developer spent time writing unit tests for
code that already existed in the correct form.

**Recommendation:**
1. Before writing any code for a story, read the delivery notes (Notes/History sections) of all
   blocked-by stories to understand what was already delivered.
2. For "wiring" stories (secret seeding, config, interface exposure), explicitly verify whether
   sibling stories already completed the wiring as a side effect.
3. Sr. PM should include in story descriptions: "Verify RFA-xxx delivery before implementing --
   this story may be satisfied by that delivery."

**Applies to:** All stories with narrow scope that depend on sibling story deliveries

**Source stories:** RFA-ajf6

---

### [TESTING] E2E scripts and integration tests have distinct and non-interchangeable roles

**Priority:** Important

**Context:** The story descriptions for RFA-yt63 and RFA-xzj6 explicitly separated their
responsibilities. The E2E script (RFA-xzj6) must NOT call go test -tags=integration. It must use
external tools (curl, CLI binaries) as an operator would. Integration tests (RFA-yt63) cover
detailed behavioral assertions against the live stack.

**Recommendation:**
1. Integration tests: Go test functions with build tag, no mocks, run via go test -tags=integration,
   verify detailed behavioral assertions (audit logs, policy engine responses, middleware chain
   traversal).
2. E2E scripts: bash scripts using curl, compiled CLI tools, jq; verify system works from the
   outside; exit non-zero on failure; do NOT wrap go test calls.
3. PM-Acceptor should reject any E2E script that contains go test invocations -- that is
   integration test scope, not E2E scope.
4. WS-capable E2E clients should be standalone CLI binaries (package main, exits 0/1), not test
   functions.

**Applies to:** All milestone E2E stories and integration test stories

**Source stories:** RFA-xzj6, RFA-yt63

---

## Metrics

- Stories accepted first try: 8/9 (89%)
- Stories rejected at least once: 1 (RFA-yt63)
- Total rejections: 3 (all RFA-yt63)
- Most common rejection reason: t.Logf used instead of t.Errorf/t.Fatalf (all 3 rejections)
- P3 discovered issues: 2 (RFA-exak attestation doc gap, RFA-iqij untracked binary)
- Parallel execution layers: 2 (both successful, no merge conflicts)

## Backlog Impact

**RFA-exak (open P3):** Sr. PM should prioritize: add Makefile target for attestation re-signing
and create ATTESTATION_ROTATION.md. This is operational pain that will recur on every tool registry
change.

**RFA-iqij (open P3):** Sr. PM should prioritize: add messaging-sim to POC/.gitignore. Trivial
one-line fix.

**Future integration test stories:** PM-Acceptor checklist should be updated to explicitly verify:
(a) no t.Logf on blocking assertion paths, (b) service readiness patterns present, (c) mux-level
routing tested (not direct handler invocations).
