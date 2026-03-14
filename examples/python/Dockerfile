FROM python:3.13-slim
WORKDIR /app

RUN pip install --no-cache-dir httpx>=0.28.0

# Copy SDK
COPY sdk/python/mcp_gateway_sdk/ /sdk/python/mcp_gateway_sdk/

# Copy demo
COPY demo/python/demo.py ./demo.py

# Point at SDK
ENV PYTHONPATH=/sdk/python

ENTRYPOINT ["python3", "demo.py"]
