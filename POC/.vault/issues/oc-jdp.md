---
id: oc-jdp
title: "Migrate OPA imports from v0 compatibility packages to v1"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T18:11:01Z
created_by: ramirosalas
updated_at: 2026-02-27T03:52:01Z
content_hash: "sha256:602c481b90454a69d7556775d2c80c8a6e0f64d483cc4298da47865c5b2dde34"
closed_at: 2026-02-21T18:19:44Z
close_reason: "Migrated OPA imports from v0 to v1: Go imports (opa/rego -> opa/v1/rego, opa/storage -> opa/v1/storage, opa/storage/inmem -> opa/v1/storage/inmem), Rego policies (future.keywords -> rego.v1), embedded test Rego (future.keywords -> rego.v1 + v1 syntax). Removed lint suppressions. All tests pass: go test ./... (15 packages, 0 failures), opa test config/opa/ (67/67 PASS), go vet clean, grep verification zero hits."
---

## Description
## User Story

As a gateway developer, I need the OPA integration to use the v1 package paths
(`github.com/open-policy-agent/opa/v1/...`) instead of the deprecated v0
compatibility packages, so that we eliminate deprecation warnings, stay on the
supported API surface, and are ready for future OPA releases that may remove the
v0 shims entirely.

## Context and Motivation

The project already pins OPA v1.13.1 in go.mod, but the Go source still imports
the old v0 compatibility packages:

```
github.com/open-policy-agent/opa/rego          (deprecated)
github.com/open-policy-agent/opa/storage       (deprecated)
github.com/open-policy-agent/opa/storage/inmem  (deprecated)
```

These imports produce deprecation warnings from gopls (SA1019). The codebase has
`//nolint:staticcheck` suppressions and a `//lint:file-ignore SA1019` directive
acknowledging the debt. This story pays that debt.

Additionally, some Rego policy files still use `import future.keywords.if` /
`import future.keywords.in` instead of the unified `import rego.v1`. The v1
import is already used by some policies (context_policy.rego, ui_policy.rego,
etc.), creating an inconsistency. All policies should be standardized on
`import rego.v1`.

Per the OPA migration guide (https://www.openpolicyagent.org/docs/latest/v0-compatibility/):
- Using v0 and v1 packages in the same program is "an anti-pattern and is not
  recommended or supported."
- `import rego.v1` makes OPA apply all v1 restrictions by default and
  implicitly imports all `future.keywords`. You CANNOT use both `rego.v1` and
  `future.keywords` in the same module.
- The Go API surface (rego.New, rego.PreparedEvalQuery, storage.MustParsePath,
  etc.) is identical between v0 and v1 packages -- only the import paths change.

## Scope

This story covers THREE changes:
1. Go import path migration (opa_engine.go)
2. Rego policy `future.keywords` -> `import rego.v1` migration (4 files)
3. Embedded Rego string literals in Go test files (3 files)

Out of scope:
- Gatekeeper admission constraint templates in `infra/eks/admission/` -- these
  are evaluated by the OPA Gatekeeper sidecar (not our Go code) and have their
  own OPA version lifecycle. They should be migrated separately if/when the
  cluster Gatekeeper version is upgraded.

---

## Files to Modify

### 1. Go source: import path migration

**File:** `internal/gateway/middleware/opa_engine.go`

Current imports (lines 14-16):
```go
"github.com/open-policy-agent/opa/rego"          //nolint:staticcheck
"github.com/open-policy-agent/opa/storage"       //nolint:staticcheck
"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck
```

Target imports:
```go
"github.com/open-policy-agent/opa/v1/rego"
"github.com/open-policy-agent/opa/v1/storage"
"github.com/open-policy-agent/opa/v1/storage/inmem"
```

Also remove:
- Line 3: `//lint:file-ignore SA1019 OPA v1 migration is tracked separately; this engine intentionally uses compatibility packages for now.`
- All `//nolint:staticcheck // OPA v1 migration tracked separately.` suffixes on the three import lines.

No other code changes needed in this file. The rego.New, rego.PrepareForEval,
rego.EvalInput, rego.Store, rego.Module, rego.Query, rego.PreparedEvalQuery,
storage.MustParsePath, storage.WriteOne, storage.AddOp, and inmem.New
symbols have identical signatures in the v1 packages.

### 2. Rego policy files: future.keywords -> rego.v1

**File:** `config/opa/mcp_policy.rego` (lines 8-9)
```
REMOVE: import future.keywords.if
REMOVE: import future.keywords.in
ADD:    import rego.v1
```

**File:** `config/opa/mcp_policy_test.rego` (lines 14-15)
```
REMOVE: import future.keywords.if
REMOVE: import future.keywords.in
ADD:    import rego.v1
```

**File:** `infra/eks/overlays/local/gateway-config/mcp_policy.rego` (lines 8-9)
```
REMOVE: import future.keywords.if
REMOVE: import future.keywords.in
ADD:    import rego.v1
```

These three are the only Rego files still using `future.keywords`. The
following files already use `import rego.v1` and need NO changes:
- config/opa/context_policy.rego
- config/opa/exfiltration.rego
- config/opa/ui_policy.rego
- config/opa/ui_csp_policy.rego
- config/opa/ui_policy_test.rego
- config/opa/ui_csp_policy_test.rego
- infra/eks/overlays/local/gateway-config/context_policy.rego
- infra/eks/overlays/local/gateway-config/exfiltration.rego
- infra/eks/overlays/local/gateway-config/ui_policy.rego
- infra/eks/overlays/local/gateway-config/ui_csp_policy.rego

### 3. Embedded Rego strings in Go test files

These Go test files contain inline Rego policy strings that use
`import future.keywords.if` / `import future.keywords.in`. Update each
embedded string to use `import rego.v1` instead.

**File:** `internal/gateway/middleware/opa_engine_test.go`
- Line 506-507: embedded policy string in TestOPAEngineConfigInjection uses
  `import future.keywords.if` + `import future.keywords.in`. Replace both
  lines with `import rego.v1`.

**File:** `internal/gateway/middleware/audit_integration_test.go`
- Line 213: embedded policy string uses `import future.keywords.if`. Replace
  with `import rego.v1`.

**Note:** The string `"import rego"` at line 301 of
`internal/gateway/phase3_model_egress_test.go` is a SECURITY TEST assertion
(checking that policy code fragments are not leaked). Do NOT modify it -- it is
not an actual Rego import.

### 4. go.mod

No changes needed. The module already depends on `github.com/open-policy-agent/opa v1.13.1`.
The v1 sub-packages (`opa/v1/rego`, `opa/v1/storage`, `opa/v1/storage/inmem`)
are provided by that same module -- they are subpackages, not a separate Go
module. Run `go mod tidy` after the import changes to confirm.

---

## Technical Notes

### Why only import paths change (no API changes)

The OPA v1 packages re-export the same symbols as v0. Specifically:
- `rego.New`, `rego.Module`, `rego.Query`, `rego.Store`, `rego.EvalInput`,
  `rego.PreparedEvalQuery`, `rego.PrepareForEval`, `rego.Rego` -- all identical.
- `storage.MustParsePath`, `storage.WriteOne`, `storage.AddOp` -- all identical.
- `inmem.New` -- identical.

The migration is a pure find-and-replace on import paths plus lint suppression
cleanup. No function signatures, return types, or calling conventions change.

### Why rego.v1 replaces future.keywords

`import rego.v1` is the canonical way to opt into all Rego v1 semantics. It
implicitly imports `if`, `in`, `contains`, and `every` keywords. You CANNOT
have both `import rego.v1` and `import future.keywords.X` in the same module --
the OPA compiler will reject it. Since our policies already use `if` and `in`
syntax, the only change is replacing the import line(s).

### Admission controller constraint templates (NOT in scope)

The files `infra/eks/admission/constraint-templates/require-image-signature.yaml`
and `require-image-digest.yaml` contain embedded Rego that uses
`import future.keywords.{in,contains,if}`. These are evaluated by OPA
Gatekeeper (a separate binary on the cluster), not by our Go OPAEngine code.
Their migration depends on the Gatekeeper version deployed. Migrate them in a
separate story when upgrading the cluster Gatekeeper.

---

## Acceptance Criteria

1. `internal/gateway/middleware/opa_engine.go` imports `github.com/open-policy-agent/opa/v1/rego`,
   `github.com/open-policy-agent/opa/v1/storage`, and
   `github.com/open-policy-agent/opa/v1/storage/inmem`. No `//nolint:staticcheck`
   or `//lint:file-ignore SA1019` directives remain in the file.

2. All Rego files under `config/opa/` use `import rego.v1`. No file contains
   `import future.keywords`.

3. The infra overlay `infra/eks/overlays/local/gateway-config/mcp_policy.rego`
   uses `import rego.v1`. No `import future.keywords` lines remain.

4. All embedded Rego policy strings in Go test files use `import rego.v1`
   instead of `import future.keywords.{if,in}`.

5. `go mod tidy` produces no changes (confirming no new module dependency was
   introduced).

6. `go vet ./...` passes with zero warnings related to OPA imports.

7. All existing Go tests pass: `go test ./internal/gateway/middleware/... -count=1`
   with zero failures.

8. OPA Rego tests pass: `opa test config/opa/ -v` with zero failures. (Install
   `opa` CLI via `brew install opa` if not already present.)

9. No remaining grep hits for the old import paths:
   `grep -r "open-policy-agent/opa/rego\b" --include="*.go" .` returns zero results.
   `grep -r "open-policy-agent/opa/storage\b" --include="*.go" . | grep -v "/v1/"` returns zero results.
   `grep -r "future\.keywords" --include="*.rego" config/ infra/eks/overlays/` returns zero results.

---

## Testing Requirements

### Unit tests

Run existing unit tests -- no new unit tests needed since this is a pure import
path migration with no behavioral change:
```bash
go test ./internal/gateway/middleware/... -count=1 -v
```

### Integration tests (MANDATORY, no mocks)

The existing OPA integration tests in the test suite exercise real OPA policy
evaluation (no mocks). They must all pass after migration:
```bash
go test ./tests/integration/... -count=1 -v -run "Context"
go test ./internal/gateway/... -count=1 -v
```

### Rego policy tests

OPA ships its own test runner. Validate all .rego test files:
```bash
opa test config/opa/ -v
```

### Verification commands (run all, expect zero errors)

```bash
go mod tidy
go vet ./...
go build ./...
go test ./... -count=1
opa test config/opa/ -v
```

---

## MANDATORY SKILLS TO REVIEW

- None identified. This is a mechanical import path migration with no new
  patterns, APIs, or architectural decisions. Standard Go module and OPA Rego
  knowledge is sufficient.

---

## Scope Boundary

This story is ONLY about migrating import paths and Rego import directives.
It does NOT:
- Change any OPA policy logic or rule semantics
- Add new policies or modify existing policy behavior
- Upgrade the OPA module version in go.mod (already at v1.13.1)
- Touch Gatekeeper admission constraint templates
- Modify any non-OPA code

## Dependencies

- None. This story has no blockers and does not block other stories.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T03:51:55Z status: open -> closed

## Links


## Comments
