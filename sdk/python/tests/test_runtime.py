"""Unit tests for shared runtime helpers in mcp-gateway-sdk."""

from mcp_gateway_sdk import (
    build_spike_token_ref,
    normalize_model_name,
    resolve_model_api_key_ref,
)
from mcp_gateway_sdk.runtime import _is_local_otel_endpoint, _should_use_insecure_otlp


def test_normalize_model_name():
    assert normalize_model_name("groq/llama-3.3-70b-versatile") == "llama-3.3-70b-versatile"
    assert normalize_model_name("openai:gpt-4o-mini") == "gpt-4o-mini"
    assert normalize_model_name("groq/openai/gpt-oss-20b") == "gpt-oss-20b"
    assert normalize_model_name("gpt-4o") == "gpt-4o"


def test_build_spike_token_ref():
    assert build_spike_token_ref("deadbeef", exp_seconds=3600) == "Bearer $SPIKE{ref:deadbeef,exp:3600}"
    assert build_spike_token_ref("") == ""


def test_resolve_model_api_key_ref_prefers_explicit_ref():
    token = resolve_model_api_key_ref(
        model_api_key_ref="Bearer $SPIKE{ref:explicit,exp:900}",
        spike_ref="deadbeef",
        env={},
    )
    assert token == "Bearer $SPIKE{ref:explicit,exp:900}"


def test_resolve_model_api_key_ref_from_spike_ref():
    token = resolve_model_api_key_ref(model_api_key_ref="", spike_ref="deadbeef", env={})
    assert token == "Bearer $SPIKE{ref:deadbeef,exp:3600}"


def test_resolve_model_api_key_ref_from_env(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY_REF", "")
    monkeypatch.setenv("GROQ_LM_SPIKE_REF", "from-env")
    token = resolve_model_api_key_ref()
    assert token == "Bearer $SPIKE{ref:from-env,exp:3600}"


def test_is_local_otel_endpoint():
    assert _is_local_otel_endpoint("http://localhost:4317")
    assert _is_local_otel_endpoint("127.0.0.1:4317")
    assert not _is_local_otel_endpoint("https://otel.example.com:4317")


def test_should_use_insecure_otlp_defaults():
    assert _should_use_insecure_otlp(
        "http://localhost:4317",
        allow_insecure_local=True,
        allow_insecure_non_local=False,
    )
    assert not _should_use_insecure_otlp(
        "https://otel.example.com:4317",
        allow_insecure_local=True,
        allow_insecure_non_local=False,
    )
