# Incident Triage and Response Runbook

Last Updated: 2026-02-15
Scope: `precinct-gateway`, SPIRE, SPIKE, KeyDB, observability path.

## 1. Trigger Conditions

- Gateway health check failures (`/health` non-200)
- Elevated deny/error rates in demo/readiness campaigns
- Identity/bootstrap failures (SPIRE/SPIKE startup regressions)
- Security event requiring rapid containment

## 2. Initial Triage (first 10 minutes)

```bash
make phoenix-up
make up
docker compose ps
docker compose logs --tail 200 precinct-gateway
docker compose logs --tail 200 spire-agent spire-server
docker compose logs --tail 200 spike-nexus spike-keeper-1 keydb
```

## 3. Containment Actions

```bash
# Stop ingress path if gateway is compromised
docker compose stop precinct-gateway

# Restart only affected service(s) after config/material check
docker compose restart precinct-gateway
docker compose restart spike-nexus keydb
```

## 4. Recovery Validation

```bash
make strict-runtime-validate
make compose-bootstrap-verify
make demo-compose
```

## 5. Evidence Collection

- Preserve relevant logs:
  - `docker compose logs --timestamps > build/incident/<timestamp>-compose.log`
- Capture readiness snapshot:
  - `make production-readiness-validate`
- Record incident timeline in the active `nd` story notes.
