"""
Runtime utilities shared by gateway-integrated agents.

These helpers centralize repeated setup code that appeared in multiple demos:
  - .env loading
  - SPIKE token formatting for model credentials
  - model name normalization
  - model API key reference resolution
  - OpenTelemetry setup
  - DSPy gateway LM configuration (including optional reasoning LM / RLM)
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Optional


def load_dotenv(path: Optional[str] = None, *, override: bool = False) -> bool:
    """Load environment variables from a .env file when python-dotenv is installed.

    Returns:
        True when loading was attempted successfully.
        False when python-dotenv is not available.
    """
    try:
        from dotenv import load_dotenv as _load_dotenv
    except ImportError:
        return False

    kwargs: dict[str, Any] = {"override": override}
    if path:
        kwargs["dotenv_path"] = path
    return bool(_load_dotenv(**kwargs))


def normalize_model_name(raw_model: str) -> str:
    """Normalize model identifier to a provider-agnostic model name.

    Examples:
      - groq/openai/gpt-oss-20b -> gpt-oss-20b
      - openai:gpt-4o-mini -> gpt-4o-mini
      - gpt-4o -> gpt-4o
    """
    model = (raw_model or "").strip()
    if ":" in model:
        model = model.split(":", 1)[1]
    if "/" in model:
        model = model.split("/")[-1]
    return model


def build_spike_token_ref(spike_ref: str, *, exp_seconds: int = 3600) -> str:
    """Build a Bearer SPIKE token reference for gateway model/tool egress."""
    ref = (spike_ref or "").strip()
    if not ref:
        return ""
    return f"Bearer $SPIKE{{ref:{ref},exp:{int(exp_seconds)}}}"


def resolve_model_api_key_ref(
    *,
    model_api_key_ref: str = "",
    spike_ref: str = "",
    exp_seconds: int = 3600,
    env: Optional[dict[str, str]] = None,
) -> str:
    """Resolve model API credential as a full SPIKE Bearer token reference.

    Resolution order:
      1) MODEL_API_KEY_REF (explicit full Bearer token reference)
      2) GROQ_LM_SPIKE_REF (converted to Bearer $SPIKE{...})
      3) function arguments
    """
    source_env = env
    if source_env is None:
        import os

        source_env = os.environ

    explicit_ref = (source_env.get("MODEL_API_KEY_REF", "") or model_api_key_ref).strip()
    if explicit_ref:
        return explicit_ref

    spike_ref_value = (source_env.get("GROQ_LM_SPIKE_REF", "") or spike_ref).strip()
    if spike_ref_value:
        return build_spike_token_ref(spike_ref_value, exp_seconds=exp_seconds)
    return ""


def setup_observability(
    *,
    service_name: str,
    service_version: str,
    spiffe_id: str,
    session_id: str,
    otel_endpoint: str,
    instrument_dspy: bool = False,
    allow_insecure_local: bool = True,
    allow_insecure_non_local: bool = False,
) -> Any:
    """Configure OpenTelemetry tracing and return a tracer for the service.

    Raises:
        ImportError: if required telemetry dependencies are not installed.
    """
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
            "spiffe.id": spiffe_id,
            "session.id": session_id,
        }
    )

    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=otel_endpoint,
        insecure=_should_use_insecure_otlp(
            otel_endpoint,
            allow_insecure_local=allow_insecure_local,
            allow_insecure_non_local=allow_insecure_non_local,
        ),
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    if instrument_dspy:
        from openinference.instrumentation.dspy import DSPyInstrumentor

        DSPyInstrumentor().instrument()

    return trace.get_tracer(service_name)


def _is_local_otel_endpoint(otel_endpoint: str) -> bool:
    endpoint = (otel_endpoint or "").strip()
    if not endpoint:
        return False
    parsed = urlparse(endpoint if "://" in endpoint else f"http://{endpoint}")
    host = (parsed.hostname or "").strip().lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def _should_use_insecure_otlp(
    otel_endpoint: str,
    *,
    allow_insecure_local: bool,
    allow_insecure_non_local: bool,
) -> bool:
    if _is_local_otel_endpoint(otel_endpoint):
        return allow_insecure_local
    return allow_insecure_non_local


def build_dspy_gateway_lm(
    *,
    llm_model: str,
    gateway_url: str,
    model_gateway_base_url: Optional[str] = None,
    model_provider: str = "groq",
    model_api_key_ref: str = "",
    spike_ref: str = "",
    compatibility: str = "openai",
) -> Any:
    """Build a DSPy LM configured for gateway-mediated model egress."""
    try:
        import dspy
    except ImportError as exc:
        raise ImportError("dspy is required to build DSPy LM configuration") from exc

    compat = (compatibility or "openai").strip().lower()
    if compat != "openai":
        raise ValueError(
            f"Unsupported MODEL_GATEWAY_COMPAT={compat!r}. "
            "Current gateway demo route is OpenAI-compatible only."
        )

    normalized = normalize_model_name(llm_model)
    api_base = model_gateway_base_url or f"{gateway_url.rstrip('/')}/openai/v1"
    api_key_ref = resolve_model_api_key_ref(
        model_api_key_ref=model_api_key_ref,
        spike_ref=spike_ref,
    )

    extra_headers = {"X-Model-Provider": model_provider}
    return dspy.LM(
        f"openai/{normalized}",
        api_base=api_base,
        api_key=api_key_ref,
        extra_headers=extra_headers,
    )


def configure_dspy_gateway_lms(
    *,
    llm_model: str,
    gateway_url: str,
    model_gateway_base_url: Optional[str] = None,
    model_provider: str = "groq",
    model_api_key_ref: str = "",
    spike_ref: str = "",
    compatibility: str = "openai",
    rlm_model: str = "",
    rlm_gateway_base_url: Optional[str] = None,
    rlm_provider: Optional[str] = None,
    rlm_api_key_ref: str = "",
    rlm_spike_ref: str = "",
    rlm_compatibility: Optional[str] = None,
) -> tuple[Any, Optional[Any]]:
    """Configure DSPy with gateway LM and optional reasoning LM (RLM).

    Returns:
        (lm, rlm) where rlm can be None.
    """
    try:
        import dspy
    except ImportError as exc:
        raise ImportError("dspy is required to configure DSPy gateway LMs") from exc

    lm = build_dspy_gateway_lm(
        llm_model=llm_model,
        gateway_url=gateway_url,
        model_gateway_base_url=model_gateway_base_url,
        model_provider=model_provider,
        model_api_key_ref=model_api_key_ref,
        spike_ref=spike_ref,
        compatibility=compatibility,
    )
    dspy.configure(lm=lm)

    if not (rlm_model or "").strip():
        return lm, None

    rlm = build_dspy_gateway_lm(
        llm_model=rlm_model,
        gateway_url=gateway_url,
        model_gateway_base_url=rlm_gateway_base_url or model_gateway_base_url,
        model_provider=rlm_provider or model_provider,
        model_api_key_ref=rlm_api_key_ref or model_api_key_ref,
        spike_ref=rlm_spike_ref or spike_ref,
        compatibility=rlm_compatibility or compatibility,
    )
    return lm, rlm
