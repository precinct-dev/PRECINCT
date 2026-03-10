#!/usr/bin/env bash
set -euo pipefail

# Programmatic rename: RamXX/agentic_reference_architecture -> precinct-dev/PRECINCT
# Run from repo root. Uses rg to find files, sed to replace.
# Idempotent: safe to run multiple times.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# macOS sed needs '' after -i; GNU sed does not
if sed --version 2>/dev/null | grep -q GNU; then
  SED_I=(-i)
else
  SED_I=(-i '')
fi

replaced=0

apply() {
  local pattern="$1" replacement="$2" description="$3"
  local files
  # Use rg to find files, skip binary, skip .git, skip this script itself
  files=$(rg -l --hidden --no-binary "$pattern" --glob '!.git' --glob '!scripts/rename-repo.sh' 2>/dev/null || true)
  if [[ -z "$files" ]]; then
    echo "  [skip] $description -- no matches"
    return
  fi
  local count
  count=$(echo "$files" | wc -l | tr -d ' ')
  echo "$files" | while IFS= read -r f; do
    sed "${SED_I[@]}" "s|$pattern|$replacement|g" "$f"
  done
  echo "  [done] $description -- $count files"
  replaced=$((replaced + count))
}

echo "=== Repo Rename: RamXX/agentic_reference_architecture -> precinct-dev/PRECINCT ==="
echo ""

# 1. Go module path (most specific first to avoid partial matches)
echo "Phase 1: Go module and import paths"
apply \
  'github\.com/RamXX/agentic_reference_architecture' \
  'github.com/precinct-dev/PRECINCT' \
  "Go module/import paths"

# 2. GitHub URLs (https://github.com/RamXX/agentic_reference_architecture)
#    Already covered by #1 since the pattern is the same

# 3. Container image registry (ghcr.io/ramxx/agentic-ref-arch)
echo ""
echo "Phase 2: Container image references"
apply \
  'ghcr\.io/ramxx/agentic-ref-arch' \
  'ghcr.io/precinct-dev/precinct' \
  "GHCR image paths (lowercase)"

apply \
  'ghcr\.io/RamXX/agentic-ref-arch' \
  'ghcr.io/precinct-dev/precinct' \
  "GHCR image paths (mixed case)"

# 4. Image prefix in CI/Makefile (agentic-ref-arch used as prefix)
echo ""
echo "Phase 3: Image prefix and SPIFFE trust domain"
apply \
  'agentic-ref-arch\.poc' \
  'precinct.poc' \
  "SPIFFE trust domain"

# The image prefix pattern: owner/agentic-ref-arch (without ghcr.io)
# Be careful not to double-replace things already handled above
apply \
  '/agentic-ref-arch' \
  '/precinct' \
  "Image prefix in paths"

# Standalone agentic-ref-arch (e.g., in variable values, cluster names)
# More targeted: only match when it's a standalone value, not part of a URL already handled
apply \
  'agentic-ref-arch' \
  'precinct' \
  "Standalone agentic-ref-arch references"

# 5. Bare references to old repo name without org prefix
echo ""
echo "Phase 4: Bare repo name references"
# Only in non-Go files to avoid breaking already-fixed imports
# agentic_reference_architecture as standalone (not part of github.com URL, already handled)
# This catches things like workspace paths, relative references
apply \
  'agentic_reference_architecture' \
  'PRECINCT' \
  "Standalone underscore repo name"

# 6. RamXX standalone (case-sensitive, in contexts like org references)
echo ""
echo "Phase 5: Org name references"
apply \
  'RamXX' \
  'precinct-dev' \
  "Org name RamXX"

# Lowercase variant
apply \
  'ramxx' \
  'precinct-dev' \
  "Org name ramxx (lowercase)"

echo ""
echo "=== Done. $replaced file groups updated. ==="
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff --stat"
echo "  2. Run: cd POC && go mod tidy"
echo "  3. Run: cd POC && go build ./..."
echo "  4. Commit the changes"
