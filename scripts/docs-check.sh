#!/usr/bin/env bash
# Knowledge base freshness check. Fails CI when the agent harness docs are
# missing or internal links are broken, with remediation instructions.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

require() {
  if [ ! -e "$1" ]; then
    echo "[DOCS_MISSING] $1 is missing."
    echo "Why: the docs/ tree is the system of record; agents depend on it."
    echo "Fix: restore $1 (see AGENTS.md for the knowledge base map)."
    fail=1
  fi
}

require AGENTS.md
require ARCHITECTURE.md
require SECURITY.md
require QUALITY_SCORE.md
require RELIABILITY.md
require docs/design-docs/index.md
require docs/design-docs/core-beliefs.md
require docs/design-docs/golden-principles.md
require docs/exec-plans/tech-debt-tracker.md
require docs/exec-plans/exec-plan.md

# Verify relative markdown links resolve.
while IFS=: read -r file link; do
  target="${link#./}"
  dir="$(dirname "$file")"
  if [ ! -e "$dir/$target" ] && [ ! -e "$target" ]; then
    echo "[DOCS_BROKEN_LINK] $file links to $link which does not exist."
    echo "Why: broken links make the knowledge base untrustworthy for agents."
    echo "Fix: update the link in $file or restore the target file."
    fail=1
  fi
done < <(grep -RoE '\]\((\.\.?/[A-Za-z0-9._/-]+\.md)\)' --include='*.md' AGENTS.md ARCHITECTURE.md docs 2>/dev/null \
  | sed -E 's/\]\((.*)\)/\1/' || true)

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "docs-check: OK"
