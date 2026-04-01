FROM ghcr.io/astral-sh/uv:0.6.1 AS uv

FROM python:3.13-slim-bookworm@sha256:1245b6c39d0b8e49e911c7d07b60cd9ed26016b0e439b6903d5e08730e417553 AS build
WORKDIR /workspace

COPY --from=uv /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY sdk/python/ /workspace/sdk/python/
COPY examples/python/pyproject.toml /workspace/examples/python/pyproject.toml
COPY examples/python/demo.py /workspace/examples/python/demo.py

RUN cd /workspace/examples/python && uv sync --python 3.13 --no-dev --no-editable

FROM python:3.13-slim-bookworm@sha256:1245b6c39d0b8e49e911c7d07b60cd9ed26016b0e439b6903d5e08730e417553

# Create non-root user
RUN groupadd -g 65532 appuser && \
    useradd -r -u 65532 -g appuser -s /sbin/nologin appuser

WORKDIR /app

COPY --from=build --chown=appuser:appuser /opt/venv /opt/venv
COPY --from=build --chown=appuser:appuser /workspace/examples/python/demo.py ./demo.py

ENV PATH="/opt/venv/bin:$PATH"

USER appuser
ENTRYPOINT ["python", "demo.py"]
