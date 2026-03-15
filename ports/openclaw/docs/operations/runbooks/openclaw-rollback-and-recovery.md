# OpenClaw Rollback and Recovery Runbook

Last Updated: 2026-02-16  
Scope: OpenClaw secure-port wrapper rollback across Compose and K8s release paths.

## 1. Preconditions

- Incident commander and approver assigned.
- Last known-good release/digest references identified.
- Open change freeze declared for non-rollback work.

## 2. Compose Rollback

```bash
# Validate production-intent locks and policy wiring first.
make compose-production-intent-preflight

# Roll wrapper service back to known-good material.
docker compose stop mcp-security-gateway
docker compose --profile strict \
  --env-file config/compose-production-intent.env \
  -f docker-compose.yml \
  -f docker-compose.strict.yml \
  -f docker-compose.prod-intent.yml up -d mcp-security-gateway
```

## 3. K8s Rollback

```bash
make k8s-validate
kustomize build deploy/terraform/overlays/staging | kubectl apply -f -
kustomize build deploy/terraform/overlays/prod | kubectl apply -f -
```

## 4. OpenClaw Recovery Smoke Checks

```bash
curl -sf http://localhost:9090/health | jq .
go run ./cmd/openclaw-ws-smoke \
  --url ws://localhost:9090/openclaw/ws \
  --spiffe-id spiffe://poc.local/agents/mcp-client/dspy-researcher/dev \
  --phase post-rollback \
  --output docs/operations/artifacts/openclaw-ws-smoke-post-rollback.json
bash tests/e2e/validate_openclaw_operations_runbook_pack.sh
go test ./tests/integration/... -run 'OpenClawHTTP|OpenClawWS' -count=1
```

## 5. Exit Criteria

- Wrapper health recovered and stable.
- Readiness checks pass:
  - `make operations-readiness-validate`
  - `make readiness-state-validate`
- Rollback evidence (commands + artifact paths + outcomes) appended to `bd` story.
