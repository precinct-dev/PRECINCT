# Mock Guard Model

Mock OpenAI-compatible chat completions endpoint for deterministic deep-scan
testing. Classifies payloads as malicious or benign based on keyword matching,
without requiring a real LLM API key.

## Endpoints

- `POST /v1/chat/completions` -- OpenAI-compatible chat completion

## Usage

Built and deployed automatically by the Docker Compose stack.
Set `GUARD_MODEL_URL` to point the gateway at this service.
