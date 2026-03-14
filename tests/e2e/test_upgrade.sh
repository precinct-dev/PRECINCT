#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

log_header() {
  echo ""
  echo -e "${BOLD}=========================================${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${BOLD}=========================================${NC}"
}

log_info() {
  echo -e "  [${CYAN}INFO${NC}] $1"
}

log_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo -e "  [${GREEN}PASS${NC}] $1"
}

log_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo -e "  [${RED}FAIL${NC}] $1"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
}

hash_file() {
  local file="$1"
  shasum -a 256 "$file" | awk '{print $1}'
}

get_keydb_version() {
  local file="$1"
  awk '
    $0 ~ "^  keydb:[[:space:]]*$" { in_comp=1; next }
    in_comp && $0 ~ "^  [a-zA-Z0-9_-]+:[[:space:]]*$" { in_comp=0 }
    in_comp && $0 ~ "^    version:[[:space:]]*" {
      gsub(/"/, "", $2); print $2; exit
    }
  ' "$file"
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if grep -qE "$pattern" "$file"; then
    log_pass "$label"
  else
    log_fail "$label"
    echo "    expected pattern '${pattern}' in ${file}" >&2
    return 1
  fi
}

assert_file_exists() {
  local file="$1"
  local label="$2"
  if [[ -f "$file" ]]; then
    log_pass "$label"
  else
    log_fail "$label"
    echo "    missing file: ${file}" >&2
    return 1
  fi
}

assert_equal() {
  local left="$1"
  local right="$2"
  local label="$3"
  if [[ "$left" == "$right" ]]; then
    log_pass "$label"
  else
    log_fail "$label"
    echo "    left='${left}' right='${right}'" >&2
    return 1
  fi
}

setup_temp_repo() {
  local tmp_repo="$1"
  mkdir -p "$tmp_repo/scripts" "$tmp_repo/config" "$tmp_repo/docs/upgrades"

  cat >"$tmp_repo/.gitignore" <<'EOF'
config/versions.yaml.snapshot.*
config/upgrade-snapshots/
EOF

  cat >"$tmp_repo/config/versions.yaml" <<'EOF'
components:
  keydb:
    image: eqalpha/keydb
    version: "1.0.0"
    pinned: false
EOF

  cat >"$tmp_repo/scripts/upgrade-check.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

fmt="table"
if [[ "${1:-}" == "--format" ]]; then
  fmt="${2:-table}"
fi

if [[ "$fmt" == "json" ]]; then
  cat <<'JSON'
{"generated_at":"2026-02-11T00:00:00Z","components":[{"component":"keydb","current":"1.0.0","latest":"1.0.1","status":"UPDATE AVAILABLE","pinned":false,"image":"eqalpha/keydb"}]}
JSON
  exit 0
fi

cat <<'TABLE'
COMPONENT        CURRENT   LATEST   STATUS
keydb            1.0.0     1.0.1    UPDATE AVAILABLE
TABLE
EOF
  chmod +x "$tmp_repo/scripts/upgrade-check.sh"

  cp "$ROOT_DIR/scripts/upgrade.sh" "$tmp_repo/scripts/upgrade.sh"
  chmod +x "$tmp_repo/scripts/upgrade.sh"

  cat >"$tmp_repo/Makefile" <<'EOF'
upgrade-check:
	@bash scripts/upgrade-check.sh --format table
	@echo ""
	@bash scripts/upgrade-check.sh --format json

upgrade:
	@if [ -z "$(COMPONENT)" ]; then \
		echo "ERROR: COMPONENT is required"; \
		exit 1; \
	fi
	@bash scripts/upgrade.sh --component $(COMPONENT)

upgrade-all:
	@bash scripts/upgrade.sh --all

ci:
	@echo "ci pass"

demo-compose:
	@echo "demo-compose pass"
EOF

  git -C "$tmp_repo" init >/dev/null 2>&1
  git -C "$tmp_repo" config user.email "upgrade-demo@example.com"
  git -C "$tmp_repo" config user.name "Upgrade Demo"
  git -C "$tmp_repo" add -A
  git -C "$tmp_repo" commit -m "baseline" >/dev/null 2>&1
}

run_success_flow() {
  local repo="$1"
  local out="$repo/.upgrade-check.out"
  local report_file="$repo/docs/upgrades/$(date +%F)-upgrade-report.md"
  local before_version after_version

  log_header "Scenario 1: Successful Upgrade Path"
  log_info "Running make upgrade-check"
  (cd "$repo" && make -s upgrade-check) | tee "$out" >/dev/null

  assert_contains "$out" "^COMPONENT" "make upgrade-check prints table output"
  assert_contains "$out" "\"components\"" "make upgrade-check prints JSON output"
  assert_contains "$out" "UPDATE AVAILABLE" "make upgrade-check identifies available updates"

  before_version="$(get_keydb_version "$repo/config/versions.yaml")"

  log_info "Running make upgrade COMPONENT=keydb"
  (
    cd "$repo"
    UPGRADE_SKIP_DOCKER=1 make -s upgrade COMPONENT=keydb
  )

  assert_file_exists "$report_file" "upgrade success report generated in docs/upgrades"
  assert_contains "$report_file" "Status: SUCCESS" "success report records SUCCESS"
  assert_contains "$report_file" "make ci: PASS" "success report records make ci PASS"
  assert_contains "$report_file" "make demo-compose: PASS" "success report records make demo-compose PASS"

  after_version="$(get_keydb_version "$repo/config/versions.yaml")"
  if [[ "$before_version" != "$after_version" ]]; then
    log_pass "keydb version changed after successful upgrade (${before_version} -> ${after_version})"
  else
    log_fail "keydb version changed after successful upgrade"
    return 1
  fi

  assert_equal "$(git -C "$repo" rev-list --count HEAD | tr -d '[:space:]')" "2" "successful upgrade created a commit"
}

run_failure_flow() {
  local repo="$1"
  local real_make="$2"
  local wrapper_dir="$repo/.failing-make-bin"
  local report_file="$repo/docs/upgrades/$(date +%F)-upgrade-report.md"
  local pre_hash post_hash

  log_header "Scenario 2: Simulated Test Failure + Rollback"
  pre_hash="$(hash_file "$repo/config/versions.yaml")"

  mkdir -p "$wrapper_dir"
  cat >"$wrapper_dir/make" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "demo-compose" ]]; then
  echo "simulated demo-compose failure" >&2
  exit 1
fi
exec "$real_make" "\$@"
EOF
  chmod +x "$wrapper_dir/make"

  log_info "Forcing make demo-compose to fail during upgrade"
  set +e
  (
    cd "$repo"
    PATH="$wrapper_dir:$PATH" \
    UPGRADE_SKIP_DOCKER=1 \
    UPGRADE_CHECK_JSON='{"components":[{"component":"keydb","current":"1.0.1","latest":"1.0.2","status":"UPDATE AVAILABLE","pinned":false,"image":"eqalpha/keydb"}]}' \
    ./scripts/upgrade.sh --component keydb
  )
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    log_pass "upgrade failed as expected when tests were forced to fail"
  else
    log_fail "upgrade failed as expected when tests were forced to fail"
    return 1
  fi

  post_hash="$(hash_file "$repo/config/versions.yaml")"
  assert_equal "$post_hash" "$pre_hash" "versions.yaml restored after rollback"

  assert_file_exists "$report_file" "failure report generated in docs/upgrades"
  assert_contains "$report_file" "Status: FAILURE" "failure report records FAILURE"
  assert_contains "$report_file" "make demo-compose: FAIL" "failure report documents failed test target"
  assert_contains "$report_file" "Snapshot:" "failure report documents rollback snapshot/action"

  assert_equal "$(git -C "$repo" rev-list --count HEAD | tr -d '[:space:]')" "2" "failed upgrade did not create an additional commit"
}

print_summary() {
  log_header "Stakeholder Summary"
  echo -e "  Total checks: $((PASS_COUNT + FAIL_COUNT))"
  echo -e "  ${GREEN}PASS${NC}: ${PASS_COUNT}"
  echo -e "  ${RED}FAIL${NC}: ${FAIL_COUNT}"
  echo ""

  if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}Upgrade workflow demo outcome: PASS${NC}"
    echo "Validated: upgrade-check detection, successful component upgrade with report, and rollback with failure report."
  else
    echo -e "${RED}Upgrade workflow demo outcome: FAIL${NC}"
    echo "One or more checks failed; see details above."
  fi
}

main() {
  require_cmd git
  require_cmd make
  require_cmd shasum
  require_cmd awk
  require_cmd grep

  local tmp_root tmp_repo real_make
  tmp_root="$(mktemp -d)"
  tmp_repo="${tmp_root}/upgrade-e2e-demo"
  real_make="$(command -v make)"

  trap 'rm -rf "${tmp_root:-}"' EXIT

  log_header "Prepare Isolated Demo Workspace"
  log_info "Creating a temporary git repo so upgrade commits do not affect your current branch"
  setup_temp_repo "$tmp_repo"

  run_success_flow "$tmp_repo"
  run_failure_flow "$tmp_repo" "$real_make"
  print_summary

  if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
