FROM python:3.13-slim-bookworm@sha256:1245b6c39d0b8e49e911c7d07b60cd9ed26016b0e439b6903d5e08730e417553 AS build
WORKDIR /build

RUN pip install --no-cache-dir httpx>=0.28.0

# Copy SDK and demo
COPY sdk/python/mcp_gateway_sdk/ /sdk/python/mcp_gateway_sdk/
COPY examples/python/demo.py ./demo.py

FROM python:3.13-slim-bookworm@sha256:1245b6c39d0b8e49e911c7d07b60cd9ed26016b0e439b6903d5e08730e417553

# Create non-root user
RUN groupadd -g 65532 appuser && \
    useradd -r -u 65532 -g appuser -s /sbin/nologin appuser

WORKDIR /app

# Copy installed packages and app from builder
COPY --from=build --chown=appuser:appuser /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=build --chown=appuser:appuser /sdk/python/mcp_gateway_sdk/ /sdk/python/mcp_gateway_sdk/
COPY --from=build --chown=appuser:appuser /build/demo.py ./demo.py

ENV PYTHONPATH=/sdk/python

USER appuser
ENTRYPOINT ["python3", "demo.py"]
