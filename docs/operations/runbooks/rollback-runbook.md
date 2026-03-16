# Rollback Runbook (Compose + K8s)

Last Updated: 2026-02-15
Scope: rollback of gateway/runtime posture to last accepted release candidate.

## 1. Preconditions

- Incident commander assigned.
- Last known good artifact references identified.
- Change freeze declared for non-rollback work.

## 2. Compose Rollback

```bash
# Preflight current state + supply-chain policy
make compose-production-intent-preflight

# Stop affected workload
docker compose stop precinct-gateway

# Re-apply known-good digest lock (config/compose-production-intent.env)
docker compose --profile strict \
  --env-file config/compose-production-intent.env \
  -f docker-compose.yml \
  -f docker-compose.strict.yml \
  -f docker-compose.prod-intent.yml up -d precinct-gateway
```

## 3. K8s Rollback

```bash
# Validate manifests before rollout
make k8s-validate

# Re-apply previously approved overlay release material
kustomize build deploy/terraform/overlays/staging | kubectl apply -f -
kustomize build deploy/terraform/overlays/prod | kubectl apply -f -
```

## 4. Post-Rollback Verification

```bash
make strict-runtime-validate
make production-readiness-validate
make readiness-state-validate
```

## 5. Exit Criteria

- Health checks recovered.
- No unresolved critical alerts.
- Rollback evidence attached in the active `nd` story notes with command outcomes.
