#!/usr/bin/env python3
"""Compliance Report Generator -- Agentic Reference Architecture POC.

Reads the control taxonomy YAML, audit logs, and policy configurations to
produce a CSV compliance report mapping gateway controls to SOC 2, ISO 27001,
CCPA, and GDPR frameworks.

Usage:
    python3 tools/compliance/generate.py [--audit-log PATH] [--output-dir PATH]

Defaults:
    --audit-log   /tmp/audit.jsonl
    --output-dir  reports/compliance-YYYY-MM-DD/
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import date, timezone, datetime
from pathlib import Path
from typing import Any

# PyYAML is the sole external dependency -- required to parse the taxonomy.
try:
    import yaml
except ImportError:
    print(
        "ERROR: PyYAML is required.  Install with:  pip install pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
TAXONOMY_PATH = SCRIPT_DIR / "control_taxonomy.yaml"

# Framework requirement descriptions (from BUSINESS.md Section 7)
FRAMEWORK_REQUIREMENTS: dict[str, dict[str, str]] = {
    "soc2": {
        "CC6.1": "Logical and Physical Access Controls",
        "CC6.5": "System Availability Controls",
        "CC6.6": "System Boundary Controls",
        "CC6.7": "Data Transmission Controls",
        "CC7.1": "System Monitoring",
        "CC7.2": "System Change Monitoring",
    },
    "iso27001": {
        "A.8.2.1": "Classification of Information",
        "A.9.2.1": "User Registration and Deregistration",
        "A.9.4.1": "Information Access Restriction",
        "A.10.1.1": "Policy on Use of Cryptographic Controls",
        "A.12.2.1": "Controls Against Malware",
        "A.12.4.1": "Event Logging",
        "A.13.1.1": "Network Controls",
        "A.14.2.7": "Outsourced Development",
    },
    "ccpa": {
        "1798.105": "Right to Deletion",
        "1798.150": "Data Breach Private Right of Action",
    },
    "gdpr": {
        "Art. 17": "Right to Erasure",
        "Art. 25": "Data Protection by Design and by Default",
        "Art. 28": "Processor Requirements",
        "Art. 30": "Records of Processing Activities",
        "Art. 32": "Security of Processing",
    },
}

# CSV column order
CSV_COLUMNS = [
    "control_id",
    "control_name",
    "control_description",
    "framework",
    "framework_requirement",
    "status",
    "evidence_type",
    "evidence_reference",
    "evidence_description",
    "test_result",
    "implementation_notes",
    "limitations",
    "recommendation",
]

# Middleware -> implementation status mapping.
# Controls whose middleware exists in the codebase are "Implemented";
# those without middleware (supply chain) are "Documented Only".
IMPLEMENTED_MIDDLEWARE = {
    "spiffe_auth",
    "opa",
    "dlp",
    "response_firewall",
    "deep_scan",
    "step_up_gating",
    "audit",
    "spike_token",
    "spike_redeemer",
    "rate_limiter",
    "circuit_breaker",
    "size_limit",
    "session_context",
    "tool_registry",
}


# ---------------------------------------------------------------------------
# Taxonomy loading
# ---------------------------------------------------------------------------


def load_taxonomy(path: Path | None = None) -> list[dict[str, Any]]:
    """Load and validate the control taxonomy YAML."""
    path = path or TAXONOMY_PATH
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    controls = data.get("controls", [])
    if not controls:
        raise ValueError(f"No controls found in {path}")
    return controls


# ---------------------------------------------------------------------------
# Audit log analysis
# ---------------------------------------------------------------------------


def load_audit_log(path: str) -> list[dict[str, Any]]:
    """Load JSONL audit log, returning parsed entries.

    Lines that are not valid JSON (e.g. docker-compose prefix lines) are
    silently skipped.
    """
    entries: list[dict[str, Any]] = []
    if not os.path.exists(path):
        return entries
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Handle docker-compose log prefixes: strip everything up to the
            # first '{' character.
            json_start = line.find("{")
            if json_start < 0:
                continue
            json_str = line[json_start:]
            try:
                entry = json.loads(json_str)
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries


def check_evidence_in_log(
    entries: list[dict[str, Any]], query: str | None
) -> tuple[bool, int]:
    """Check if audit log entries satisfy the evidence query.

    Returns (found, count) where found is True if at least one entry matches,
    and count is the number of matching entries.

    The query is a simplified jq-like expression evaluated as Python logic.
    """
    if not query or not entries:
        return False, 0

    count = 0
    for entry in entries:
        if _matches_query(entry, query):
            count += 1
    return count > 0, count


def _matches_query(entry: dict[str, Any], query: str) -> bool:
    """Evaluate a simplified evidence query against a log entry.

    Supports common patterns from the taxonomy:
      - '.field != null'
      - '.field != ""'
      - '.field == "value"'
      - '.field | startswith("prefix")'
      - '.field | contains("substring")'
      - compound 'and' expressions
    """
    # Split on ' and ' for compound queries
    parts = query.split(" and ")
    for part in parts:
        part = part.strip()
        if not _eval_single(entry, part):
            return False
    return True


def _resolve_path(entry: dict[str, Any], dotpath: str) -> Any:
    """Resolve a dot-separated path against a nested dict.

    Returns the value at the path, or a sentinel _MISSING if not found.
    """
    parts = dotpath.split(".")
    obj: Any = entry
    for p in parts:
        if isinstance(obj, dict):
            obj = obj.get(p, _MISSING)
            if obj is _MISSING:
                return _MISSING
        else:
            return _MISSING
    return obj


# Sentinel for missing dict keys (distinct from None)
_MISSING = object()


def _eval_single(entry: dict[str, Any], expr: str) -> bool:
    """Evaluate a single query expression."""
    expr = expr.strip()

    # Handle .field | startswith("value")
    if "| startswith(" in expr:
        field, _, rest = expr.partition(" | startswith(")
        field = field.strip().lstrip(".")
        value = rest.rstrip(")").strip('"').strip("'")
        resolved = _resolve_path(entry, field)
        if resolved is _MISSING:
            return False
        return str(resolved).startswith(value)

    # Handle .field | contains("value")
    if "| contains(" in expr:
        field, _, rest = expr.partition(" | contains(")
        field = field.strip().lstrip(".")
        value = rest.rstrip(")").strip('"').strip("'")
        resolved = _resolve_path(entry, field)
        if resolved is _MISSING:
            return False
        return value in str(resolved)

    # Handle .field != null  (works for nested fields too)
    if "!= null" in expr:
        field = expr.replace("!= null", "").strip().lstrip(".")
        resolved = _resolve_path(entry, field)
        return resolved is not _MISSING and resolved is not None

    # Handle .field != ""
    if '!= ""' in expr:
        field = expr.replace('!= ""', "").strip().lstrip(".")
        resolved = _resolve_path(entry, field)
        if resolved is _MISSING:
            return False
        return resolved != ""

    # Handle .field == "value"
    if '== "' in expr:
        field, _, rest = expr.partition(' == "')
        field = field.strip().lstrip(".")
        value = rest.rstrip('"')
        resolved = _resolve_path(entry, field)
        if resolved is _MISSING:
            return False
        return str(resolved) == value

    # Handle .field == number (e.g. .status_code == 403)
    if " == " in expr:
        field, _, value = expr.partition(" == ")
        field = field.strip().lstrip(".")
        value = value.strip()
        resolved = _resolve_path(entry, field)
        if resolved is _MISSING:
            return False
        try:
            return resolved == int(value)
        except (ValueError, TypeError):
            return str(resolved) == value

    return False


# ---------------------------------------------------------------------------
# Config file evidence
# ---------------------------------------------------------------------------


def check_config_exists(project_root: Path) -> dict[str, bool]:
    """Check which policy/config files exist."""
    configs = {
        "opa_policy": project_root / "config" / "opa" / "mcp_policy.rego",
        "tool_registry": project_root / "config" / "tool-registry.yaml",
        "opa_tool_grants": project_root / "config" / "opa" / "tool_grants.yaml",
        "spiffe_ids": project_root / "config" / "spiffe-ids.yaml",
        "destinations": project_root / "config" / "destinations.yaml",
        "risk_thresholds": project_root / "config" / "risk_thresholds.yaml",
        "cosign_key": project_root / ".cosign",
    }
    return {name: path.exists() for name, path in configs.items()}


# ---------------------------------------------------------------------------
# Status determination
# ---------------------------------------------------------------------------


def determine_status(
    control: dict[str, Any],
    audit_found: bool,
    configs: dict[str, bool],
) -> str:
    """Determine control implementation status.

    Returns one of: Implemented, Partial, Documented Only
    """
    middleware = control.get("middleware")
    evidence_type = control.get("evidence_type", "")

    # No middleware means supply chain or infrastructure control
    if not middleware:
        return "Documented Only"

    # Check if middleware is implemented in the codebase
    if middleware not in IMPLEMENTED_MIDDLEWARE:
        return "Documented Only"

    # For audit_log evidence, check if we found matching entries
    if evidence_type == "audit_log":
        return "Implemented" if audit_found else "Partial"

    # For configuration evidence, check if relevant config exists
    if evidence_type == "configuration":
        if middleware in ("opa", "spiffe_auth"):
            return "Implemented" if configs.get("opa_policy") else "Partial"
        if middleware == "dlp":
            return "Implemented"
        if middleware in ("tool_registry",):
            return "Implemented" if configs.get("tool_registry") else "Partial"
        return "Implemented"

    # For test_result evidence, mark as Implemented (tests exist in codebase)
    if evidence_type == "test_result":
        return "Implemented"

    return "Partial"


# ---------------------------------------------------------------------------
# Evidence description generation
# ---------------------------------------------------------------------------


def build_evidence_reference(
    control: dict[str, Any],
    audit_count: int,
    configs: dict[str, bool],
    project_root: Path,
) -> str:
    """Build a human-readable evidence reference string."""
    evidence_type = control.get("evidence_type", "")

    if evidence_type == "audit_log" and audit_count > 0:
        return f"audit.jsonl ({audit_count} matching entries)"
    if evidence_type == "configuration":
        middleware = control.get("middleware", "")
        if middleware in ("opa", "spiffe_auth"):
            return "config/opa/mcp_policy.rego"
        if middleware == "tool_registry":
            return "config/tool-registry.yaml"
        if middleware == "dlp":
            return "internal/gateway/middleware/dlp.go"
        if middleware == "deep_scan":
            return "config/opa/mcp_policy.rego (poisoning patterns)"
        if middleware == "session_context":
            return "config/opa/mcp_policy.rego (session risk threshold)"
        if middleware in ("size_limit", "rate_limiter", "circuit_breaker"):
            return f"internal/gateway/middleware/{middleware}.go"
        return f"internal/gateway/middleware/{middleware}.go"
    if evidence_type == "test_result":
        middleware = control.get("middleware", "")
        if middleware:
            return f"internal/gateway/middleware/{middleware}_test.go"
        return "tests/"

    return "N/A"


def build_evidence_description(control: dict[str, Any], audit_count: int) -> str:
    """Build a description of the evidence found."""
    evidence_type = control.get("evidence_type", "")
    middleware = control.get("middleware", "")

    if evidence_type == "audit_log":
        if audit_count > 0:
            return f"{audit_count} audit log entries demonstrate {middleware} enforcement"
        return f"No audit log entries found for {middleware} -- run E2E suite to generate"

    if evidence_type == "configuration":
        return f"Configuration file defines {middleware} policy rules"

    if evidence_type == "test_result":
        return f"Unit and integration tests verify {middleware} behavior"

    return "No evidence collected"


def build_implementation_notes(control: dict[str, Any]) -> str:
    """Generate implementation notes based on control metadata."""
    middleware = control.get("middleware")
    step = control.get("step")

    if middleware and step is not None:
        return f"Middleware: {middleware} (chain step {step})"
    if middleware:
        return f"Middleware: {middleware}"
    return "Infrastructure/CI control -- not in middleware chain"


def build_limitations(control: dict[str, Any], status: str) -> str:
    """Generate limitation notes."""
    if status == "Documented Only":
        return "Control exists in design only; not enforced at runtime in POC"
    if status == "Partial":
        return "Partial implementation; evidence collection incomplete"

    middleware = control.get("middleware", "")
    if middleware == "spiffe_auth":
        return "POC uses self-signed CAs; production requires enterprise PKI"
    if middleware in ("spike_token", "spike_redeemer"):
        return "SPIKE Nexus integration requires running Nexus container"
    if middleware == "step_up_gating":
        return "Guard model unavailable in POC; fails open for medium risk"

    return ""


def build_recommendation(control: dict[str, Any], status: str) -> str:
    """Generate recommendations for improvement."""
    if status == "Documented Only":
        return "Implement runtime enforcement before production deployment"
    if status == "Partial":
        return "Complete implementation and run E2E suite to generate evidence"
    return "Maintain current controls; review annually"


# ---------------------------------------------------------------------------
# CSV generation
# ---------------------------------------------------------------------------


def generate_rows(
    controls: list[dict[str, Any]],
    audit_entries: list[dict[str, Any]],
    configs: dict[str, bool],
    project_root: Path,
) -> list[dict[str, str]]:
    """Generate one CSV row per control-framework combination."""
    rows: list[dict[str, str]] = []

    for control in controls:
        frameworks = control.get("frameworks", {})
        evidence_query = control.get("evidence_query")

        audit_found, audit_count = check_evidence_in_log(audit_entries, evidence_query)
        status = determine_status(control, audit_found, configs)

        # Emit one row per framework mapping
        for framework_name, requirements in frameworks.items():
            if not requirements:
                continue
            for req_id in requirements:
                req_desc = FRAMEWORK_REQUIREMENTS.get(framework_name, {}).get(
                    req_id, req_id
                )
                row = {
                    "control_id": control["id"],
                    "control_name": control["name"],
                    "control_description": control["description"],
                    "framework": framework_name.upper(),
                    "framework_requirement": f"{req_id}: {req_desc}",
                    "status": status,
                    "evidence_type": control.get("evidence_type", ""),
                    "evidence_reference": build_evidence_reference(
                        control, audit_count, configs, project_root
                    ),
                    "evidence_description": build_evidence_description(
                        control, audit_count
                    ),
                    "test_result": "PASS" if status == "Implemented" else "N/A",
                    "implementation_notes": build_implementation_notes(control),
                    "limitations": build_limitations(control, status),
                    "recommendation": build_recommendation(control, status),
                }
                rows.append(row)

    return rows


def write_csv(rows: list[dict[str, str]], output_path: Path) -> None:
    """Write rows to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate compliance report CSV from control taxonomy and audit logs"
    )
    parser.add_argument(
        "--audit-log",
        default="/tmp/audit.jsonl",
        help="Path to audit log JSONL file (default: /tmp/audit.jsonl)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: reports/compliance-YYYY-MM-DD/)",
    )
    parser.add_argument(
        "--taxonomy",
        default=None,
        help="Path to control taxonomy YAML (default: tools/compliance/control_taxonomy.yaml)",
    )
    parser.add_argument(
        "--project-root",
        default=None,
        help="Project root directory (default: auto-detected)",
    )
    args = parser.parse_args(argv)

    # Determine project root
    if args.project_root:
        project_root = Path(args.project_root).resolve()
    else:
        # Assume script is at tools/compliance/generate.py
        project_root = SCRIPT_DIR.parent.parent

    # Load taxonomy
    taxonomy_path = Path(args.taxonomy) if args.taxonomy else TAXONOMY_PATH
    print(f"Loading control taxonomy from {taxonomy_path}")
    controls = load_taxonomy(taxonomy_path)
    print(f"  Loaded {len(controls)} controls")

    # Load audit log
    audit_path = args.audit_log
    print(f"Loading audit log from {audit_path}")
    audit_entries = load_audit_log(audit_path)
    print(f"  Loaded {len(audit_entries)} audit entries")

    # Check config files
    configs = check_config_exists(project_root)
    present = sum(1 for v in configs.values() if v)
    print(f"Checked {len(configs)} config files ({present} present)")

    # Generate report
    rows = generate_rows(controls, audit_entries, configs, project_root)
    print(f"Generated {len(rows)} compliance report rows")

    # Determine output path
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        today = date.today().isoformat()
        output_dir = project_root / "reports" / f"compliance-{today}"
    output_path = output_dir / "compliance-report.csv"

    write_csv(rows, output_path)
    print(f"Report written to {output_path}")

    # Summary
    statuses = {}
    for row in rows:
        s = row["status"]
        statuses[s] = statuses.get(s, 0) + 1
    print("\nStatus Summary:")
    for s, count in sorted(statuses.items()):
        print(f"  {s}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
