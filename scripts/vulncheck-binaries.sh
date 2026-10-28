#!/usr/bin/env bash
# govulncheck every binary a release would ship (vulncheck-binaries.sh <binary>...), the way a customer's scanner
# sees it, and fail on any finding the VEX statements in .vex/ do not declare not_affected. Release binaries are
# stripped, so binary mode matches whole modules; .vex/ records, and publishes with each release, why a match does
# not apply. The source-mode scan in CI stays exact, so code that starts using a declared package still fails there.
set -euo pipefail

govulncheck="${GOVULNCHECK:-govulncheck}"
declared=$(jq -r '.statements[] | select(.status == "not_affected") | .vulnerability.name' .vex/*.json | sort -u)
failed=0
for bin in "$@"; do
  found=$("$govulncheck" -mode=binary -format json "$bin" | jq -r 'select(.finding) | .finding.osv' | sort -u)
  undeclared=$(comm -23 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$declared"))
  if [ -n "$undeclared" ]; then
    echo "$bin: $(echo "$undeclared" | tr '\n' ' ')" >&2
    failed=1
  else
    echo "$bin: clean${found:+ (not affected, per .vex/: $(echo "$found" | tr '\n' ' '))}"
  fi
done
exit "$failed"
