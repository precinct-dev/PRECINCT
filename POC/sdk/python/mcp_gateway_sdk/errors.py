"""
GatewayError -- structured error type mirroring the unified JSON envelope.

Mirrors the Go GatewayError struct from internal/gateway/middleware/errors.go
(RFA-tj9.1). Every field from the JSON envelope is accessible as an attribute.
"""

from __future__ import annotations

from typing import Any, Optional


class GatewayError(Exception):
    """Raised when the gateway returns an error response.

    Attributes match the unified JSON error envelope defined in RFA-tj9.1:
        code:            Machine-readable error code (e.g. "authz_policy_denied").
        message:         Human-readable description.
        reason_code:     Stable reason identifier for policy/UI handling.
        middleware:       Which middleware layer rejected the request.
        step:            Middleware step number in the chain.
        decision_id:     Audit decision ID for cross-referencing.
        trace_id:        OpenTelemetry trace ID.
        details:         Optional structured details (risk scores, etc.).
        remediation:     Optional remediation guidance.
        docs_url:        Optional link to documentation.
        http_status:     The HTTP status code from the response.
    """

    def __init__(
        self,
        *,
        code: str = "",
        message: str = "",
        reason_code: str = "",
        middleware: str = "",
        step: int = 0,
        decision_id: str = "",
        trace_id: str = "",
        details: Optional[dict[str, Any]] = None,
        remediation: str = "",
        docs_url: str = "",
        http_status: int = 0,
    ) -> None:
        self.code = code
        self.message = message
        self.reason_code = reason_code
        self.middleware = middleware
        self.step = step
        self.decision_id = decision_id
        self.trace_id = trace_id
        self.details = details or {}
        self.remediation = remediation
        self.docs_url = docs_url
        self.http_status = http_status
        super().__init__(self.message or self.code or f"HTTP {self.http_status}")

    @classmethod
    def from_response(cls, http_status: int, body: dict[str, Any]) -> GatewayError:
        """Parse a GatewayError from an HTTP response JSON body.

        The body is expected to follow the unified JSON envelope:
        {
            "code": "...",
            "message": "...",
            "reason_code": "...",
            "middleware": "...",
            "middleware_step": 0,
            "decision_id": "...",
            "trace_id": "...",
            "details": {...},
            "remediation": "...",
            "docs_url": "..."
        }

        Falls back gracefully if fields are missing (e.g. legacy format).
        """
        return cls(
            code=body.get("code", body.get("error", "")),
            message=body.get("message", body.get("reason", "")),
            reason_code=body.get("reason_code", ""),
            middleware=body.get("middleware", ""),
            step=body.get("middleware_step", 0),
            decision_id=body.get("decision_id", ""),
            trace_id=body.get("trace_id", ""),
            details=body.get("details"),
            remediation=body.get("remediation", ""),
            docs_url=body.get("docs_url", ""),
            http_status=http_status,
        )

    def __repr__(self) -> str:
        parts = [f"GatewayError(code={self.code!r}"]
        if self.message:
            parts.append(f"message={self.message!r}")
        if self.middleware:
            parts.append(f"middleware={self.middleware!r}")
        if self.http_status:
            parts.append(f"http_status={self.http_status}")
        return ", ".join(parts) + ")"
