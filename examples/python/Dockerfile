FROM python:3.13-slim
WORKDIR /app

RUN pip install --no-cache-dir httpx>=0.28.0

# Create non-root user
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -s /sbin/nologin appuser

# Copy SDK
COPY sdk/python/mcp_gateway_sdk/ /sdk/python/mcp_gateway_sdk/

# Copy demo
COPY examples/python/demo.py ./demo.py

# Point at SDK
ENV PYTHONPATH=/sdk/python

USER appuser
ENTRYPOINT ["python3", "demo.py"]
