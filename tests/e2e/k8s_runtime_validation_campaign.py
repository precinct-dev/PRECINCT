#!/usr/bin/env python3
"""
Run a Kubernetes runtime validation campaign for v2.4 control planes and emit
machine-readable pass/fail evidence per control.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request


DEFAULT_SPIFFE_ID = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"


@dataclass
class CheckResult:
    check_id: str
    plane: str
    scenario: str
    expected_status: int
    expected_reason_code: str
    actual_status: int
    actual_reason_code: str
    pass_check: bool
    decision_id: str
    trace_id: str
    run_id: str
    response_excerpt: str


def run_cmd(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({' '.join(cmd)}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def detect_gateway_url() -> tuple[str, str]:
    env_url = os.environ.get("GATEWAY_URL", "").strip()
    if env_url:
        context = run_cmd(["kubectl", "config", "current-context"])
        return env_url, context

    context = run_cmd(["kubectl", "config", "current-context"])
    node_port = run_cmd(
        [
            "kubectl",
            "-n",
            "gateway",
            "get",
            "svc",
            "precinct-gateway",
            "-o",
            "jsonpath={.spec.ports[0].nodePort}",
        ]
    )
    if not node_port:
        raise RuntimeError("failed to resolve gateway NodePort from service")

    node_ip = run_cmd(
        [
            "kubectl",
            "get",
            "node",
            "desktop-control-plane",
            "-o",
            "jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}",
        ]
    )
    node_ipv4 = ""
    for token in node_ip.split():
        if token.count(".") == 3:
            node_ipv4 = token
            break
    if not node_ipv4:
        node_ipv4 = run_cmd(
            [
                "docker",
                "inspect",
                "desktop-control-plane",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            ]
        ).split()[0]
    if not node_ipv4:
        raise RuntimeError("failed to determine Kubernetes node IP")

    return f"http://{node_ipv4}:{node_port}", context


def http_post_json(url: str, payload: dict[str, Any], spiffe_id: str) -> tuple[int, dict[str, Any], str]:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-SPIFFE-ID": spiffe_id,
        },
    )
    try:
        with request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            return resp.status, parsed, raw
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        parsed = json.loads(raw) if raw else {}
        return exc.code, parsed, raw


def http_get_status(url: str, timeout_seconds: int = 3) -> int:
    req = request.Request(url=url, method="GET")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            return resp.status
    except error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def is_gateway_reachable(gateway_url: str) -> bool:
    return http_get_status(f"{gateway_url}/health", timeout_seconds=3) == 200


def start_gateway_port_forward(local_port: int = 39090) -> tuple[subprocess.Popen[bytes], str]:
    proc = subprocess.Popen(
        [
            "kubectl",
            "-n",
            "gateway",
            "port-forward",
            "svc/precinct-gateway",
            f"{local_port}:9090",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    fallback_url = f"http://localhost:{local_port}"
    for _ in range(30):
        if is_gateway_reachable(fallback_url):
            return proc, fallback_url
        if proc.poll() is not None:
            break
        time.sleep(1)

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    raise RuntimeError("failed to establish gateway port-forward reachability")


def make_envelope(run_id: str, session_id: str, spiffe_id: str, plane: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "session_id": session_id,
        "tenant": "tenant-a",
        "actor_spiffe_id": spiffe_id,
        "plane": plane,
    }


def make_check(
    gateway_url: str,
    check_id: str,
    plane: str,
    scenario: str,
    path: str,
    spiffe_id: str,
    expected_status: int,
    expected_reason_code: str,
    payload: dict[str, Any],
) -> CheckResult:
    status, body, raw = http_post_json(f"{gateway_url}{path}", payload, spiffe_id)
    actual_reason = str(body.get("reason_code", ""))
    decision_id = str(body.get("decision_id", ""))
    trace_id = str(body.get("trace_id", ""))
    run_id = str((body.get("envelope") or {}).get("run_id", ""))
    pass_check = status == expected_status and actual_reason == expected_reason_code
    return CheckResult(
        check_id=check_id,
        plane=plane,
        scenario=scenario,
        expected_status=expected_status,
        expected_reason_code=expected_reason_code,
        actual_status=status,
        actual_reason_code=actual_reason,
        pass_check=pass_check,
        decision_id=decision_id,
        trace_id=trace_id,
        run_id=run_id,
        response_excerpt=raw[:400],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run K8s runtime validation campaign and emit JSON pass/fail report."
    )
    parser.add_argument(
        "--output",
        default="build/validation/k8s-runtime-validation-report.v2.4.json",
        help="Output JSON report path (relative to POC root or absolute).",
    )
    parser.add_argument(
        "--spiffe-id",
        default=DEFAULT_SPIFFE_ID,
        help="SPIFFE ID used for campaign calls.",
    )
    return parser.parse_args()


def build_control_result(control_id: str, plane: str, checks: list[CheckResult]) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "plane": plane,
        "status": "pass" if all(c.pass_check for c in checks) else "fail",
        "checks": [c.__dict__ for c in checks],
    }


def main() -> int:
    args = parse_args()
    poc_root = Path(__file__).resolve().parents[2]
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = poc_root / out_path

    try:
        gateway_url, cluster_context = detect_gateway_url()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    port_forward_proc: subprocess.Popen[bytes] | None = None
    if not is_gateway_reachable(gateway_url):
        try:
            port_forward_proc, gateway_url = start_gateway_port_forward(local_port=39090)
        except Exception as exc:
            print(
                f"ERROR: gateway not reachable and port-forward fallback failed: {exc}",
                file=sys.stderr,
            )
            return 2

    try:
        ts = int(datetime.now(timezone.utc).timestamp())
        session_id = f"k8s-v24-validation-session-{ts}"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        spiffe_id = args.spiffe_id

        # Connector lifecycle bootstrap for ingress checks.
        register_payload_1 = {
            "connector_id": "compose-webhook",
            "manifest": {
                "connector_id": "compose-webhook",
                "connector_type": "webhook",
                "source_principal": spiffe_id,
                "version": "1.0",
                "capabilities": ["ingress.submit"],
                "signature": {
                    "algorithm": "sha256-manifest-v1",
                    "value": "bootstrap-signature",
                },
            },
        }
        reg_status, reg_body, _ = http_post_json(
            f"{gateway_url}/v1/connectors/register", register_payload_1, spiffe_id
        )
        if reg_status != 200:
            print(
                f"ERROR: connector bootstrap register failed: status={reg_status} body={reg_body}",
                file=sys.stderr,
            )
            return 3
        connector_sig = str((reg_body.get("record") or {}).get("expected_signature", ""))
        if not connector_sig:
            print(
                f"ERROR: connector bootstrap register returned no expected_signature: body={reg_body}",
                file=sys.stderr,
            )
            return 3

        register_payload_2 = {
            "connector_id": "compose-webhook",
            "manifest": {
                "connector_id": "compose-webhook",
                "connector_type": "webhook",
                "source_principal": spiffe_id,
                "version": "1.0",
                "capabilities": ["ingress.submit"],
                "signature": {
                    "algorithm": "sha256-manifest-v1",
                    "value": connector_sig,
                },
            },
        }
        reg_status_2, reg_body_2, _ = http_post_json(
            f"{gateway_url}/v1/connectors/register", register_payload_2, spiffe_id
        )
        if reg_status_2 != 200:
            print(
                f"ERROR: connector canonical register failed: status={reg_status_2} body={reg_body_2}",
                file=sys.stderr,
            )
            return 3

        for op in ("validate", "approve", "activate"):
            op_status, op_body, _ = http_post_json(
                f"{gateway_url}/v1/connectors/{op}",
                {"connector_id": "compose-webhook"},
                spiffe_id,
            )
            if op_status != 200:
                print(
                    f"ERROR: connector {op} failed: status={op_status} body={op_body}",
                    file=sys.stderr,
                )
                return 3

        control_checks: dict[str, list[CheckResult]] = {
            "phase3.ingress": [],
            "phase3.context": [],
            "phase3.model": [],
            "phase3.tool": [],
            "phase3.loop": [],
        }

        ingress_allow_run = "k8s-v24-ingress-allow"
        ingress_allow_payload = {
            "envelope": make_envelope(ingress_allow_run, session_id, spiffe_id, "ingress"),
            "policy": {
                "envelope": make_envelope(ingress_allow_run, session_id, spiffe_id, "ingress"),
                "action": "ingress.admit",
                "resource": "ingress/event",
                "attributes": {
                    "connector_id": "compose-webhook",
                    "connector_signature": connector_sig,
                    "source_id": "compose-webhook",
                    "source_principal": spiffe_id,
                    "event_id": f"evt-{ts}-ingress-allow",
                    "event_timestamp": now_utc,
                },
            },
        }
        control_checks["phase3.ingress"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.ingress.allow",
                plane="ingress",
                scenario="allow",
                path="/v1/ingress/submit",
                spiffe_id=spiffe_id,
                expected_status=200,
                expected_reason_code="INGRESS_ALLOW",
                payload=ingress_allow_payload,
            )
        )

        context_allow_run = "k8s-v24-context-allow"
        context_allow_payload = {
            "envelope": make_envelope(context_allow_run, session_id, spiffe_id, "context"),
            "policy": {
                "envelope": make_envelope(context_allow_run, session_id, spiffe_id, "context"),
                "action": "context.admit",
                "resource": "context/segment",
                "attributes": {
                    "scan_passed": True,
                    "prompt_check_passed": True,
                    "prompt_injection_detected": False,
                },
            },
        }
        control_checks["phase3.context"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.context.allow",
                plane="context",
                scenario="allow",
                path="/v1/context/admit",
                spiffe_id=spiffe_id,
                expected_status=200,
                expected_reason_code="CONTEXT_ALLOW",
                payload=context_allow_payload,
            )
        )

        context_deny_run = "k8s-v24-context-deny"
        context_deny_payload = {
            "envelope": make_envelope(context_deny_run, session_id, spiffe_id, "context"),
            "policy": {
                "envelope": make_envelope(context_deny_run, session_id, spiffe_id, "context"),
                "action": "context.admit",
                "resource": "context/segment",
                "attributes": {
                    "scan_passed": False,
                    "prompt_check_passed": False,
                    "prompt_injection_detected": True,
                },
            },
        }
        control_checks["phase3.context"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.context.deny",
                plane="context",
                scenario="deny",
                path="/v1/context/admit",
                spiffe_id=spiffe_id,
                expected_status=403,
                expected_reason_code="CONTEXT_NO_SCAN_NO_SEND",
                payload=context_deny_payload,
            )
        )

        model_allow_run = "k8s-v24-model-allow"
        model_allow_payload = {
            "envelope": make_envelope(model_allow_run, session_id, spiffe_id, "model"),
            "policy": {
                "envelope": make_envelope(model_allow_run, session_id, spiffe_id, "model"),
                "action": "model.call",
                "resource": "model/inference",
                "attributes": {
                    "provider": "openai",
                    "model": "gpt-4o",
                    "prompt": "Summarize this non-sensitive wellness note.",
                },
            },
        }
        control_checks["phase3.model"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.model.allow",
                plane="model",
                scenario="allow",
                path="/v1/model/call",
                spiffe_id=spiffe_id,
                expected_status=200,
                expected_reason_code="MODEL_ALLOW",
                payload=model_allow_payload,
            )
        )

        model_deny_run = "k8s-v24-model-deny"
        model_deny_payload = {
            "envelope": make_envelope(model_deny_run, session_id, spiffe_id, "model"),
            "policy": {
                "envelope": make_envelope(model_deny_run, session_id, spiffe_id, "model"),
                "action": "model.call",
                "resource": "model/inference",
                "attributes": {
                    "provider": "openai",
                    "model": "gpt-4o",
                    "direct_egress": True,
                    "mediation_mode": "direct",
                },
            },
        }
        control_checks["phase3.model"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.model.deny",
                plane="model",
                scenario="deny",
                path="/v1/model/call",
                spiffe_id=spiffe_id,
                expected_status=403,
                expected_reason_code="MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED",
                payload=model_deny_payload,
            )
        )

        tool_allow_run = "k8s-v24-tool-allow"
        tool_allow_payload = {
            "envelope": make_envelope(tool_allow_run, session_id, spiffe_id, "tool"),
            "policy": {
                "envelope": make_envelope(tool_allow_run, session_id, spiffe_id, "tool"),
                "action": "tool.execute",
                "resource": "tool/read",
                "attributes": {
                    "capability_id": "tool.default.mcp",
                    "tool_name": "read",
                },
            },
        }
        control_checks["phase3.tool"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.tool.allow",
                plane="tool",
                scenario="allow",
                path="/v1/tool/execute",
                spiffe_id=spiffe_id,
                expected_status=200,
                expected_reason_code="TOOL_ALLOW",
                payload=tool_allow_payload,
            )
        )

        tool_deny_run = "k8s-v24-tool-deny"
        tool_deny_payload = {
            "envelope": make_envelope(tool_deny_run, session_id, spiffe_id, "tool"),
            "policy": {
                "envelope": make_envelope(tool_deny_run, session_id, spiffe_id, "tool"),
                "action": "tool.execute",
                "resource": "tool/write",
                "attributes": {
                    "capability_id": "tool.unapproved.mcp",
                    "tool_name": "write",
                },
            },
        }
        control_checks["phase3.tool"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.tool.deny",
                plane="tool",
                scenario="deny",
                path="/v1/tool/execute",
                spiffe_id=spiffe_id,
                expected_status=403,
                expected_reason_code="TOOL_CAPABILITY_DENIED",
                payload=tool_deny_payload,
            )
        )

        loop_allow_run = "k8s-v24-loop-allow"
        loop_allow_payload = {
            "envelope": make_envelope(loop_allow_run, session_id, spiffe_id, "loop"),
            "policy": {
                "envelope": make_envelope(loop_allow_run, session_id, spiffe_id, "loop"),
                "action": "loop.check",
                "resource": "loop/external-governor",
                "attributes": {
                    "limits": {
                        "max_steps": 10,
                        "max_tool_calls": 10,
                        "max_model_calls": 10,
                        "max_wall_time_ms": 60000,
                        "max_egress_bytes": 100000,
                        "max_model_cost_usd": 1.0,
                        "max_provider_failovers": 2,
                        "max_risk_score": 0.9,
                    },
                    "usage": {
                        "steps": 1,
                        "tool_calls": 1,
                        "model_calls": 1,
                        "wall_time_ms": 1000,
                        "egress_bytes": 10,
                        "model_cost_usd": 0.01,
                        "provider_failovers": 0,
                        "risk_score": 0.2,
                    },
                },
            },
        }
        control_checks["phase3.loop"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.loop.allow",
                plane="loop",
                scenario="allow",
                path="/v1/loop/check",
                spiffe_id=spiffe_id,
                expected_status=200,
                expected_reason_code="LOOP_ALLOW",
                payload=loop_allow_payload,
            )
        )

        loop_deny_run = "k8s-v24-loop-deny"
        loop_deny_payload = {
            "envelope": make_envelope(loop_deny_run, session_id, spiffe_id, "loop"),
            "policy": {
                "envelope": make_envelope(loop_deny_run, session_id, spiffe_id, "loop"),
                "action": "loop.check",
                "resource": "loop/external-governor",
                "attributes": {
                    "limits": {
                        "max_steps": 1,
                        "max_tool_calls": 10,
                        "max_model_calls": 10,
                        "max_wall_time_ms": 60000,
                        "max_egress_bytes": 100000,
                        "max_model_cost_usd": 1.0,
                        "max_provider_failovers": 2,
                        "max_risk_score": 0.9,
                    },
                    "usage": {
                        "steps": 2,
                        "tool_calls": 1,
                        "model_calls": 1,
                        "wall_time_ms": 1000,
                        "egress_bytes": 10,
                        "model_cost_usd": 0.01,
                        "provider_failovers": 0,
                        "risk_score": 0.2,
                    },
                },
            },
        }
        control_checks["phase3.loop"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.loop.deny",
                plane="loop",
                scenario="deny",
                path="/v1/loop/check",
                spiffe_id=spiffe_id,
                expected_status=429,
                expected_reason_code="LOOP_HALT_MAX_STEPS",
                payload=loop_deny_payload,
            )
        )

        revoke_status, revoke_body, _ = http_post_json(
            f"{gateway_url}/v1/connectors/revoke",
            {"connector_id": "compose-webhook"},
            spiffe_id,
        )
        if revoke_status != 200:
            print(
                f"ERROR: connector revoke failed: status={revoke_status} body={revoke_body}",
                file=sys.stderr,
            )
            return 3

        ingress_deny_run = "k8s-v24-ingress-deny"
        ingress_deny_payload = {
            "envelope": make_envelope(ingress_deny_run, session_id, spiffe_id, "ingress"),
            "policy": {
                "envelope": make_envelope(ingress_deny_run, session_id, spiffe_id, "ingress"),
                "action": "ingress.admit",
                "resource": "ingress/event",
                "attributes": {
                    "connector_id": "compose-webhook",
                    "connector_signature": connector_sig,
                    "source_id": "compose-webhook",
                    "source_principal": spiffe_id,
                    "event_id": f"evt-{ts}-ingress-deny",
                    "event_timestamp": now_utc,
                },
            },
        }
        control_checks["phase3.ingress"].append(
            make_check(
                gateway_url=gateway_url,
                check_id="phase3.ingress.deny",
                plane="ingress",
                scenario="deny",
                path="/v1/ingress/submit",
                spiffe_id=spiffe_id,
                expected_status=403,
                expected_reason_code="INGRESS_SOURCE_UNAUTHENTICATED",
                payload=ingress_deny_payload,
            )
        )

        controls = [
            build_control_result("phase3.ingress", "ingress", control_checks["phase3.ingress"]),
            build_control_result("phase3.context", "context", control_checks["phase3.context"]),
            build_control_result("phase3.model", "model", control_checks["phase3.model"]),
            build_control_result("phase3.tool", "tool", control_checks["phase3.tool"]),
            build_control_result("phase3.loop", "loop", control_checks["phase3.loop"]),
        ]

        all_checks = [chk for c in controls for chk in c["checks"]]
        controls_passed = sum(1 for c in controls if c["status"] == "pass")
        checks_passed = sum(1 for c in all_checks if c["pass_check"])

        report = {
            "schema_version": "k8s.runtime.validation.v1",
            "story_id": "RFA-l6h6.4.3",
            "executed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cluster_context": cluster_context,
            "gateway_url": gateway_url,
            "session_id": session_id,
            "summary": {
                "controls_total": len(controls),
                "controls_passed": controls_passed,
                "controls_failed": len(controls) - controls_passed,
                "checks_total": len(all_checks),
                "checks_passed": checks_passed,
                "checks_failed": len(all_checks) - checks_passed,
                "status": "pass" if controls_passed == len(controls) else "fail",
            },
            "controls": controls,
        }

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(f"k8s-runtime-validation: wrote {out_path}")
        print(
            "k8s-runtime-validation: "
            f"controls={report['summary']['controls_passed']}/{report['summary']['controls_total']} "
            f"checks={report['summary']['checks_passed']}/{report['summary']['checks_total']}"
        )

        return 0 if report["summary"]["status"] == "pass" else 1
    finally:
        if port_forward_proc is not None and port_forward_proc.poll() is None:
            port_forward_proc.terminate()
            try:
                port_forward_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                port_forward_proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
