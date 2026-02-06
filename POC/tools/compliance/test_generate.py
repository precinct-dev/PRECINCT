#!/usr/bin/env python3
"""Tests for the compliance report generator.

Unit tests: YAML parsing, CSV generation, evidence extraction, status determination.
Integration tests: Full pipeline with real audit log data and real taxonomy.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path

import pytest

# Module under test
from generate import (
    CSV_COLUMNS,
    FRAMEWORK_REQUIREMENTS,
    IMPLEMENTED_MIDDLEWARE,
    build_evidence_description,
    build_evidence_reference,
    build_implementation_notes,
    build_limitations,
    build_recommendation,
    check_config_exists,
    check_evidence_in_log,
    determine_status,
    generate_rows,
    load_audit_log,
    load_taxonomy,
    main,
    write_csv,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
TAXONOMY_PATH = SCRIPT_DIR / "control_taxonomy.yaml"


@pytest.fixture
def sample_audit_entries():
    """Sample audit log entries matching the real gateway format."""
    return [
        {
            "timestamp": "2026-02-06T07:33:41Z",
            "session_id": "8ef798c7-fb6a-4232-b11a-56d932f55a60",
            "decision_id": "8933b900-a398-42f7-be06-1f7fb8e53acb",
            "trace_id": "ae7773cc-6246-46a3-9602-aec968876f32",
            "spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
            "action": "mcp_request",
            "result": "completed",
            "status_code": 403,
            "security": {"tool_hash_verified": False},
            "prev_hash": "22da7eb451de26f5f17f1f9c335147f1290705128fd0ff7e8bcba622c0f0c92f",
            "bundle_digest": "563d8c8c8cc9e9b5a0d582f90c788ba34f1a583ee0c67dbd5bb6ced8630dc0c8",
            "registry_digest": "03e8fcd3633063c516d8f087f8fcb7e72c2328bf045c3baf9227b0988451185f",
        },
        {
            "timestamp": "2026-02-06T07:33:41Z",
            "session_id": "2c696b0c-bb6f-49ea-a5fe-54668211ca5f",
            "decision_id": "c0bf8f7f-c160-4d21-ba03-5ee03dd206f3",
            "trace_id": "e2e67949-0c41-40f1-ad11-141810868173",
            "spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
            "action": "step_up_gating",
            "result": "gate=step_up allowed=true total_score=4 impact=1",
        },
        {
            "timestamp": "2026-02-06T07:33:42Z",
            "session_id": "f2d0c677-36af-4277-85af-0d4639ac9252",
            "decision_id": "a8916019-5b30-4b44-ab43-f10009123ff9",
            "trace_id": "fe4cd0d6-7513-4173-a4d4-881af3d98dc7",
            "spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
            "action": "mcp_request",
            "result": "completed",
            "status_code": 404,
            "security": {"tool_hash_verified": False},
            "prev_hash": "2f928ca70e61b18f5b47acae72b777512fed08fb5f555b8358d22af4ff3e0f99",
            "bundle_digest": "563d8c8c8cc9e9b5a0d582f90c788ba34f1a583ee0c67dbd5bb6ced8630dc0c8",
            "registry_digest": "03e8fcd3633063c516d8f087f8fcb7e72c2328bf045c3baf9227b0988451185f",
        },
    ]


@pytest.fixture
def sample_control():
    """A single sample control for unit testing."""
    return {
        "id": "GW-AUTH-001",
        "name": "SPIFFE mTLS Authentication",
        "description": "All agent requests authenticated via SPIFFE SVIDs",
        "middleware": "spiffe_auth",
        "step": 3,
        "frameworks": {
            "soc2": ["CC6.1"],
            "iso27001": ["A.9.2.1"],
            "ccpa": [],
            "gdpr": ["Art. 32"],
        },
        "evidence_type": "audit_log",
        "evidence_query": '.spiffe_id != "" and .spiffe_id != null',
    }


@pytest.fixture
def sample_configs():
    """Configuration presence flags for testing."""
    return {
        "opa_policy": True,
        "tool_registry": True,
        "opa_tool_grants": True,
        "spiffe_ids": True,
        "destinations": True,
        "risk_thresholds": True,
        "cosign_key": True,
    }


# ---------------------------------------------------------------------------
# Unit Tests: YAML Parsing
# ---------------------------------------------------------------------------


class TestLoadTaxonomy:
    """Tests for load_taxonomy function."""

    def test_load_real_taxonomy(self):
        """Verify the real taxonomy file loads and contains expected structure."""
        controls = load_taxonomy(TAXONOMY_PATH)
        assert len(controls) > 0, "Taxonomy must contain at least one control"

    def test_taxonomy_has_all_10_control_areas(self):
        """All 10 control areas must be represented."""
        controls = load_taxonomy(TAXONOMY_PATH)
        ids = [c["id"] for c in controls]
        prefixes = {id_.rsplit("-", 1)[0] for id_ in ids}
        expected_prefixes = {
            "GW-AUTH",
            "GW-AUTHZ",
            "GW-DLP",
            "GW-SCAN",
            "GW-AUDIT",
            "GW-SEC",
            "GW-TRANS",
            "GW-AVAIL",
            "GW-SESS",
            "GW-SC",
        }
        assert expected_prefixes.issubset(prefixes), (
            f"Missing control areas: {expected_prefixes - prefixes}"
        )

    def test_taxonomy_control_fields(self):
        """Each control must have required fields."""
        controls = load_taxonomy(TAXONOMY_PATH)
        required_fields = {"id", "name", "description", "frameworks", "evidence_type"}
        for control in controls:
            missing = required_fields - set(control.keys())
            assert not missing, (
                f"Control {control.get('id', '???')} missing fields: {missing}"
            )

    def test_taxonomy_framework_mappings(self):
        """Each control must map to at least one framework."""
        controls = load_taxonomy(TAXONOMY_PATH)
        for control in controls:
            frameworks = control.get("frameworks", {})
            total_mappings = sum(
                len(reqs) for reqs in frameworks.values() if reqs
            )
            assert total_mappings > 0, (
                f"Control {control['id']} has no framework mappings"
            )

    def test_taxonomy_invalid_path_raises(self):
        """Loading from a nonexistent path raises an error."""
        with pytest.raises(FileNotFoundError):
            load_taxonomy(Path("/nonexistent/taxonomy.yaml"))

    def test_taxonomy_empty_raises(self):
        """Loading a YAML with no controls raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("controls: []\n")
            f.flush()
            with pytest.raises(ValueError, match="No controls found"):
                load_taxonomy(Path(f.name))
            os.unlink(f.name)


# ---------------------------------------------------------------------------
# Unit Tests: Audit Log Loading
# ---------------------------------------------------------------------------


class TestLoadAuditLog:
    """Tests for load_audit_log function."""

    def test_load_jsonl(self):
        """Load a valid JSONL file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(json.dumps({"action": "mcp_request", "status_code": 200}) + "\n")
            f.write(json.dumps({"action": "step_up_gating"}) + "\n")
            f.flush()
            entries = load_audit_log(f.name)
            assert len(entries) == 2
            assert entries[0]["action"] == "mcp_request"
            os.unlink(f.name)

    def test_load_docker_compose_prefixed(self):
        """Handle docker-compose log prefixes gracefully."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write(
                'mcp-security-gateway  | 2026/02/06 07:33:41 '
                + json.dumps({"action": "mcp_request", "session_id": "abc"})
                + "\n"
            )
            f.flush()
            entries = load_audit_log(f.name)
            assert len(entries) == 1
            assert entries[0]["session_id"] == "abc"
            os.unlink(f.name)

    def test_load_nonexistent_file(self):
        """Nonexistent file returns empty list."""
        entries = load_audit_log("/nonexistent/audit.jsonl")
        assert entries == []

    def test_load_with_invalid_lines(self):
        """Invalid JSON lines are silently skipped."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write("not json at all\n")
            f.write("[AUDIT] Internal tool response: tool=tavily_search\n")
            f.write(json.dumps({"action": "valid"}) + "\n")
            f.flush()
            entries = load_audit_log(f.name)
            assert len(entries) == 1
            assert entries[0]["action"] == "valid"
            os.unlink(f.name)


# ---------------------------------------------------------------------------
# Unit Tests: Evidence Checking
# ---------------------------------------------------------------------------


class TestCheckEvidenceInLog:
    """Tests for check_evidence_in_log and query evaluation."""

    def test_spiffe_id_not_empty(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, '.spiffe_id != "" and .spiffe_id != null'
        )
        assert found is True
        assert count == 3

    def test_action_equals(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, '.action == "mcp_request"'
        )
        assert found is True
        assert count == 2

    def test_action_step_up(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, '.action == "step_up_gating"'
        )
        assert found is True
        assert count == 1

    def test_startswith(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, '.spiffe_id | startswith("spiffe://")'
        )
        assert found is True
        assert count == 3

    def test_contains(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, '.result | contains("total_score")'
        )
        assert found is True
        assert count == 1

    def test_prev_hash_not_null(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, ".prev_hash != null"
        )
        assert found is True
        assert count == 2  # step_up_gating entry has no prev_hash

    def test_status_code_equals(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, ".status_code == 403"
        )
        assert found is True
        assert count == 1

    def test_bundle_digest_not_null(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, ".bundle_digest != null and .registry_digest != null"
        )
        assert found is True
        assert count == 2

    def test_nested_field(self, sample_audit_entries):
        found, count = check_evidence_in_log(
            sample_audit_entries, ".security.tool_hash_verified != null"
        )
        assert found is True
        assert count == 2

    def test_empty_query(self, sample_audit_entries):
        found, count = check_evidence_in_log(sample_audit_entries, None)
        assert found is False
        assert count == 0

    def test_empty_entries(self):
        found, count = check_evidence_in_log([], '.action == "mcp_request"')
        assert found is False
        assert count == 0


# ---------------------------------------------------------------------------
# Unit Tests: Status Determination
# ---------------------------------------------------------------------------


class TestDetermineStatus:
    """Tests for determine_status function."""

    def test_implemented_with_audit_evidence(self, sample_control, sample_configs):
        status = determine_status(sample_control, audit_found=True, configs=sample_configs)
        assert status == "Implemented"

    def test_partial_without_audit_evidence(self, sample_control, sample_configs):
        status = determine_status(sample_control, audit_found=False, configs=sample_configs)
        assert status == "Partial"

    def test_documented_only_for_no_middleware(self, sample_configs):
        control = {
            "id": "GW-SC-001",
            "middleware": None,
            "evidence_type": "configuration",
        }
        status = determine_status(control, audit_found=False, configs=sample_configs)
        assert status == "Documented Only"

    def test_implemented_for_config_evidence(self, sample_configs):
        control = {
            "id": "GW-AUTHZ-002",
            "middleware": "opa",
            "evidence_type": "configuration",
        }
        status = determine_status(control, audit_found=False, configs=sample_configs)
        assert status == "Implemented"

    def test_implemented_for_test_result(self, sample_configs):
        control = {
            "id": "GW-DLP-003",
            "middleware": "dlp",
            "evidence_type": "test_result",
        }
        status = determine_status(control, audit_found=False, configs=sample_configs)
        assert status == "Implemented"


# ---------------------------------------------------------------------------
# Unit Tests: CSV Row Generation
# ---------------------------------------------------------------------------


class TestGenerateRows:
    """Tests for generate_rows function."""

    def test_single_control_produces_correct_rows(
        self, sample_control, sample_audit_entries, sample_configs
    ):
        rows = generate_rows(
            [sample_control], sample_audit_entries, sample_configs, PROJECT_ROOT
        )
        # GW-AUTH-001 maps to soc2:CC6.1, iso27001:A.9.2.1, gdpr:Art.32 (ccpa is empty)
        assert len(rows) == 3
        frameworks_seen = {r["framework"] for r in rows}
        assert frameworks_seen == {"SOC2", "ISO27001", "GDPR"}

    def test_csv_columns_present(
        self, sample_control, sample_audit_entries, sample_configs
    ):
        rows = generate_rows(
            [sample_control], sample_audit_entries, sample_configs, PROJECT_ROOT
        )
        for row in rows:
            for col in CSV_COLUMNS:
                assert col in row, f"Missing column: {col}"

    def test_status_populated(
        self, sample_control, sample_audit_entries, sample_configs
    ):
        rows = generate_rows(
            [sample_control], sample_audit_entries, sample_configs, PROJECT_ROOT
        )
        for row in rows:
            assert row["status"] in ("Implemented", "Partial", "Documented Only")

    def test_framework_requirement_has_description(
        self, sample_control, sample_audit_entries, sample_configs
    ):
        rows = generate_rows(
            [sample_control], sample_audit_entries, sample_configs, PROJECT_ROOT
        )
        for row in rows:
            # Should contain both ID and description
            assert ": " in row["framework_requirement"]

    def test_empty_controls_produces_no_rows(self, sample_audit_entries, sample_configs):
        rows = generate_rows([], sample_audit_entries, sample_configs, PROJECT_ROOT)
        assert len(rows) == 0


# ---------------------------------------------------------------------------
# Unit Tests: CSV Writing
# ---------------------------------------------------------------------------


class TestWriteCSV:
    """Tests for write_csv function."""

    def test_write_and_read_csv(self, sample_control, sample_audit_entries, sample_configs):
        rows = generate_rows(
            [sample_control], sample_audit_entries, sample_configs, PROJECT_ROOT
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.csv"
            write_csv(rows, output_path)
            assert output_path.exists()

            with open(output_path, "r") as f:
                reader = csv.DictReader(f)
                read_rows = list(reader)
                assert len(read_rows) == len(rows)
                assert set(reader.fieldnames) == set(CSV_COLUMNS)

    def test_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "a" / "b" / "c" / "report.csv"
            write_csv([], nested)
            assert nested.exists()


# ---------------------------------------------------------------------------
# Unit Tests: Helper Functions
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Tests for evidence, notes, limitations, recommendation builders."""

    def test_evidence_reference_audit(self, sample_control):
        ref = build_evidence_reference(sample_control, 42, {}, PROJECT_ROOT)
        assert "audit.jsonl" in ref
        assert "42" in ref

    def test_evidence_reference_config(self):
        control = {"evidence_type": "configuration", "middleware": "opa"}
        ref = build_evidence_reference(control, 0, {}, PROJECT_ROOT)
        assert "mcp_policy.rego" in ref

    def test_evidence_reference_test(self):
        control = {"evidence_type": "test_result", "middleware": "dlp"}
        ref = build_evidence_reference(control, 0, {}, PROJECT_ROOT)
        assert "dlp_test.go" in ref

    def test_evidence_description_with_entries(self, sample_control):
        desc = build_evidence_description(sample_control, 10)
        assert "10 audit log entries" in desc

    def test_evidence_description_no_entries(self, sample_control):
        desc = build_evidence_description(sample_control, 0)
        assert "No audit log entries" in desc

    def test_implementation_notes(self, sample_control):
        notes = build_implementation_notes(sample_control)
        assert "spiffe_auth" in notes
        assert "step 3" in notes

    def test_limitations_documented_only(self, sample_control):
        lim = build_limitations(sample_control, "Documented Only")
        assert "design only" in lim

    def test_limitations_implemented_spiffe(self, sample_control):
        lim = build_limitations(sample_control, "Implemented")
        assert "self-signed" in lim

    def test_recommendation_implemented(self, sample_control):
        rec = build_recommendation(sample_control, "Implemented")
        assert "Maintain" in rec

    def test_recommendation_partial(self, sample_control):
        rec = build_recommendation(sample_control, "Partial")
        assert "Complete" in rec


# ---------------------------------------------------------------------------
# Unit Tests: Config Checking
# ---------------------------------------------------------------------------


class TestCheckConfigExists:
    """Tests for check_config_exists function."""

    def test_real_project_root(self):
        configs = check_config_exists(PROJECT_ROOT)
        # These should exist in the real project
        assert configs["opa_policy"] is True
        assert configs["tool_registry"] is True

    def test_nonexistent_root(self):
        configs = check_config_exists(Path("/nonexistent/project"))
        for v in configs.values():
            assert v is False


# ---------------------------------------------------------------------------
# Unit Tests: Framework Requirements Completeness
# ---------------------------------------------------------------------------


class TestFrameworkRequirements:
    """Verify framework requirement mappings are complete."""

    def test_soc2_requirements_present(self):
        assert "CC6.1" in FRAMEWORK_REQUIREMENTS["soc2"]
        assert "CC6.5" in FRAMEWORK_REQUIREMENTS["soc2"]
        assert "CC6.6" in FRAMEWORK_REQUIREMENTS["soc2"]
        assert "CC6.7" in FRAMEWORK_REQUIREMENTS["soc2"]
        assert "CC7.1" in FRAMEWORK_REQUIREMENTS["soc2"]
        assert "CC7.2" in FRAMEWORK_REQUIREMENTS["soc2"]

    def test_iso27001_requirements_present(self):
        expected = [
            "A.8.2.1", "A.9.2.1", "A.9.4.1", "A.10.1.1",
            "A.12.2.1", "A.12.4.1", "A.13.1.1", "A.14.2.7",
        ]
        for req in expected:
            assert req in FRAMEWORK_REQUIREMENTS["iso27001"]

    def test_ccpa_requirements_present(self):
        assert "1798.105" in FRAMEWORK_REQUIREMENTS["ccpa"]
        assert "1798.150" in FRAMEWORK_REQUIREMENTS["ccpa"]

    def test_gdpr_requirements_present(self):
        expected = ["Art. 17", "Art. 25", "Art. 28", "Art. 30", "Art. 32"]
        for req in expected:
            assert req in FRAMEWORK_REQUIREMENTS["gdpr"]


# ---------------------------------------------------------------------------
# Integration Tests: Full Pipeline
# ---------------------------------------------------------------------------


class TestIntegrationFullPipeline:
    """Integration tests that exercise the full generate pipeline."""

    def test_full_pipeline_with_real_taxonomy_no_audit(self):
        """Generate a report from real taxonomy without audit log."""
        controls = load_taxonomy(TAXONOMY_PATH)
        configs = check_config_exists(PROJECT_ROOT)
        audit_entries = []  # No audit log

        rows = generate_rows(controls, audit_entries, configs, PROJECT_ROOT)

        assert len(rows) > 0, "Must produce at least one row"

        # Verify all 10 control areas appear
        control_ids = {r["control_id"] for r in rows}
        control_prefixes = {cid.rsplit("-", 1)[0] for cid in control_ids}
        expected = {
            "GW-AUTH", "GW-AUTHZ", "GW-DLP", "GW-SCAN", "GW-AUDIT",
            "GW-SEC", "GW-TRANS", "GW-AVAIL", "GW-SESS", "GW-SC",
        }
        assert expected.issubset(control_prefixes)

        # Verify all 4 frameworks appear
        frameworks = {r["framework"] for r in rows}
        assert frameworks == {"SOC2", "ISO27001", "CCPA", "GDPR"}

        # Verify all CSV columns present
        for row in rows:
            for col in CSV_COLUMNS:
                assert col in row

    def test_full_pipeline_with_sample_audit(self, sample_audit_entries):
        """Generate a report with sample audit entries (simulating E2E output)."""
        controls = load_taxonomy(TAXONOMY_PATH)
        configs = check_config_exists(PROJECT_ROOT)

        rows = generate_rows(controls, sample_audit_entries, configs, PROJECT_ROOT)
        assert len(rows) > 0

        # Controls with audit_log evidence and matching queries should be Implemented
        auth_rows = [r for r in rows if r["control_id"] == "GW-AUTH-001"]
        assert len(auth_rows) > 0
        for r in auth_rows:
            assert r["status"] == "Implemented"

    def test_full_pipeline_csv_output(self, sample_audit_entries):
        """Full pipeline writes a valid CSV file."""
        controls = load_taxonomy(TAXONOMY_PATH)
        configs = check_config_exists(PROJECT_ROOT)
        rows = generate_rows(controls, sample_audit_entries, configs, PROJECT_ROOT)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "compliance-report.csv"
            write_csv(rows, output_path)

            # Read back and verify
            with open(output_path, "r") as f:
                reader = csv.DictReader(f)
                read_rows = list(reader)

            assert len(read_rows) == len(rows)
            assert set(reader.fieldnames) == set(CSV_COLUMNS)

            # Verify specific framework requirement values
            soc2_rows = [r for r in read_rows if r["framework"] == "SOC2"]
            assert len(soc2_rows) > 0
            iso_rows = [r for r in read_rows if r["framework"] == "ISO27001"]
            assert len(iso_rows) > 0
            ccpa_rows = [r for r in read_rows if r["framework"] == "CCPA"]
            assert len(ccpa_rows) > 0
            gdpr_rows = [r for r in read_rows if r["framework"] == "GDPR"]
            assert len(gdpr_rows) > 0

    def test_full_pipeline_with_real_audit_log(self):
        """Integration test with the real E2E audit log if available."""
        real_log = PROJECT_ROOT / "tests" / "e2e" / "gateway-audit-logs.log"
        if not real_log.exists():
            pytest.skip("Real audit log not available (run E2E suite first)")

        controls = load_taxonomy(TAXONOMY_PATH)
        configs = check_config_exists(PROJECT_ROOT)
        audit_entries = load_audit_log(str(real_log))

        assert len(audit_entries) > 0, "Real audit log should have entries"

        rows = generate_rows(controls, audit_entries, configs, PROJECT_ROOT)
        assert len(rows) > 0

        # With real audit data, audit-backed controls should be Implemented
        audit_controls = [
            r for r in rows
            if r["evidence_type"] == "audit_log" and r["status"] == "Implemented"
        ]
        assert len(audit_controls) > 0, (
            "With real audit data, some audit-based controls should be Implemented"
        )

    def test_cli_main_with_output(self, sample_audit_entries):
        """Test the main() CLI function end-to-end."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a sample audit log file
            audit_path = Path(tmpdir) / "audit.jsonl"
            with open(audit_path, "w") as f:
                for entry in sample_audit_entries:
                    f.write(json.dumps(entry) + "\n")

            output_dir = Path(tmpdir) / "output"

            exit_code = main([
                "--audit-log", str(audit_path),
                "--output-dir", str(output_dir),
                "--project-root", str(PROJECT_ROOT),
            ])

            assert exit_code == 0
            csv_path = output_dir / "compliance-report.csv"
            assert csv_path.exists()

            with open(csv_path, "r") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            assert len(rows) > 0

    def test_cli_main_no_audit_log(self):
        """CLI works even without audit log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "output"
            exit_code = main([
                "--audit-log", "/nonexistent/audit.jsonl",
                "--output-dir", str(output_dir),
                "--project-root", str(PROJECT_ROOT),
            ])
            assert exit_code == 0
            csv_path = output_dir / "compliance-report.csv"
            assert csv_path.exists()


# ---------------------------------------------------------------------------
# Integration Tests: Evidence Cross-Referencing
# ---------------------------------------------------------------------------


class TestEvidenceCrossReferencing:
    """Verify evidence references point to real files/resources."""

    def test_opa_policy_referenced_controls(self):
        """Controls referencing OPA policy should point to existing file."""
        controls = load_taxonomy(TAXONOMY_PATH)
        configs = check_config_exists(PROJECT_ROOT)
        rows = generate_rows(controls, [], configs, PROJECT_ROOT)

        opa_rows = [
            r for r in rows
            if "mcp_policy.rego" in r["evidence_reference"]
        ]
        assert len(opa_rows) > 0
        # The file must actually exist
        assert (PROJECT_ROOT / "config" / "opa" / "mcp_policy.rego").exists()

    def test_tool_registry_referenced_controls(self):
        """Controls using tool_registry middleware should reference existing files."""
        controls = load_taxonomy(TAXONOMY_PATH)

        # GW-SC-003 uses tool_registry middleware with audit_log evidence.
        # When audit data is present, it references audit.jsonl; when absent,
        # the test_result fallback references the test file.  Verify both
        # the middleware source and config file exist in the project.
        assert (PROJECT_ROOT / "config" / "tool-registry.yaml").exists()
        assert (
            PROJECT_ROOT / "internal" / "gateway" / "middleware" / "tool_registry.go"
        ).exists()

        # With audit entries matching the query, the reference includes audit.jsonl
        sample_entries = [
            {"security": {"tool_hash_verified": True}, "action": "mcp_request"}
        ]
        configs = check_config_exists(PROJECT_ROOT)
        rows = generate_rows(controls, sample_entries, configs, PROJECT_ROOT)
        sc003_rows = [r for r in rows if r["control_id"] == "GW-SC-003"]
        assert len(sc003_rows) > 0
        assert "audit.jsonl" in sc003_rows[0]["evidence_reference"]

    def test_middleware_test_files_exist(self):
        """Controls referencing test files should have corresponding middleware tests."""
        controls = load_taxonomy(TAXONOMY_PATH)
        for control in controls:
            if control.get("evidence_type") == "test_result" and control.get("middleware"):
                middleware = control["middleware"]
                # Check that either the test file or the middleware file exists
                middleware_file = (
                    PROJECT_ROOT
                    / "internal"
                    / "gateway"
                    / "middleware"
                    / f"{middleware}.go"
                )
                if middleware_file.exists():
                    test_file = (
                        PROJECT_ROOT
                        / "internal"
                        / "gateway"
                        / "middleware"
                        / f"{middleware}_test.go"
                    )
                    assert test_file.exists(), (
                        f"Middleware {middleware} has no test file at {test_file}"
                    )
