#!/usr/bin/env bash
# Scenario WS Skeleton: Messaging Simulator + WhatsApp message.send vertical slice (RFA-1fui)
# Validates the messaging simulator health, WhatsApp POST happy path, and auth rejection.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../../../.." && pwd)}"
source "${POC_DIR}/tests/e2e/common.sh"

log_header "Scenario WS Skeleton: Messaging Simulator smoke test"

# ---- Check: messaging-sim health ----
MESSAGING_SIM_URL="${MESSAGING_SIM_URL:-http://localhost:8090}"

health_body=$(curl -sf "${MESSAGING_SIM_URL}/health" 2>&1 || true)
if echo "$health_body" | grep -q '"status":"ok"'; then
    log_pass "messaging-sim /health returns ok"
else
    log_fail "messaging-sim /health unreachable or bad response" "$health_body"
fi

# ---- Check: WhatsApp POST happy path ----
wa_body=$(curl -sf -X POST "${MESSAGING_SIM_URL}/v1/messages" \
    -H "Authorization: Bearer test-token-123" \
    -H "Content-Type: application/json" \
    -d '{
        "messaging_product": "whatsapp",
        "to": "15551234567",
        "type": "text",
        "text": {"body": "Hello from E2E test"}
    }' 2>&1 || true)

if echo "$wa_body" | grep -q '"messaging_product":"whatsapp"'; then
    log_pass "WhatsApp POST returns messaging_product=whatsapp"
else
    log_fail "WhatsApp POST response missing messaging_product" "$wa_body"
fi

if echo "$wa_body" | grep -q '"wamid\.'; then
    log_pass "WhatsApp POST returns message ID with wamid. prefix"
else
    # Fallback: check for the id field containing wamid
    if echo "$wa_body" | grep -q 'wamid'; then
        log_pass "WhatsApp POST returns message ID with wamid prefix"
    else
        log_fail "WhatsApp POST response missing wamid message ID" "$wa_body"
    fi
fi

# ---- Check: 401 without auth ----
wa_noauth_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${MESSAGING_SIM_URL}/v1/messages" \
    -H "Content-Type: application/json" \
    -d '{
        "messaging_product": "whatsapp",
        "to": "15551234567",
        "type": "text",
        "text": {"body": "No auth"}
    }' 2>&1 || true)

if [ "$wa_noauth_status" = "401" ]; then
    log_pass "WhatsApp POST without auth returns 401"
else
    log_fail "Expected 401 without auth, got $wa_noauth_status"
fi

# ---- Check: 400 with missing fields ----
wa_bad_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${MESSAGING_SIM_URL}/v1/messages" \
    -H "Authorization: Bearer test-token" \
    -H "Content-Type: application/json" \
    -d '{"messaging_product": "whatsapp"}' 2>&1 || true)

if [ "$wa_bad_status" = "400" ]; then
    log_pass "WhatsApp POST with missing fields returns 400"
else
    log_fail "Expected 400 for missing fields, got $wa_bad_status"
fi

print_summary
