#!/usr/bin/env bash
# Sign and notarize one darwin binary (a goreleaser post-build hook: sign-macos.sh <path> <os>):
# codesign with the Developer ID Application identity in the keychain
# (scripts/macos-keychain.sh), hardened runtime and a secure timestamp, then notarytool with an Apple ID and an
# app-specific password. A bare binary cannot carry a stapled ticket; Gatekeeper looks the notarization up online.
#
# Environment: APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD (notarization); MACOS_SIGN_IDENTITY overrides the
# identity found in the keychain. REQUIRE_MACOS_SIGNING=1 (release tags) turns anything missing into a failure
# instead of an unsigned binary that looks shippable.
set -euo pipefail

bin="$1"
os="${2:-}"
[ "$os" = darwin ] || exit 0
log() { printf 'sign-macos: %s\n' "$*"; }
missing() {
  if [ "${REQUIRE_MACOS_SIGNING:-}" = 1 ]; then
    log "error: $1" >&2
    exit 1
  fi
  log "$1; leaving $bin unsigned"
  exit 0
}

[ "$(uname -s)" = Darwin ] || missing "signing needs macOS (codesign, notarytool)"
identity="${MACOS_SIGN_IDENTITY:-$(security find-identity -v -p codesigning 2>/dev/null |
  sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -n 1)}"
[ -n "$identity" ] || missing "no Developer ID Application identity in the keychain"

name=$(basename "$bin")
codesign --force --options runtime --timestamp --identifier "ai.straiker.$name" --sign "$identity" "$bin"
codesign --verify --strict --verbose=2 "$bin"
log "signed $bin: $identity"

if [ -z "${APPLE_ID:-}" ] || [ -z "${APPLE_TEAM_ID:-}" ] || [ -z "${APPLE_APP_PASSWORD:-}" ]; then
  [ "${REQUIRE_MACOS_SIGNING:-}" = 1 ] && { log "error: APPLE_ID, APPLE_TEAM_ID and APPLE_APP_PASSWORD are needed to notarize" >&2; exit 1; }
  log "no notarization credentials; $bin is signed but not notarized"
  exit 0
fi

# notarytool's --timeout bounds Apple's processing, not a stalled upload, so each attempt also has a hard cap
# (uploads from GitHub runners have been seen to wedge until the job's 6 h limit).
zip="$(mktemp -d)/$name.zip"
ditto -c -k --keepParent "$bin" "$zip"
out=$(mktemp)
for attempt in 1 2 3; do
  xcrun notarytool submit "$zip" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" --wait --timeout 10m >"$out" 2>&1 &
  pid=$!
  ( sleep 720; kill -TERM "$pid" 2>/dev/null ) &
  watchdog=$!
  if wait "$pid"; then
    kill -TERM "$watchdog" 2>/dev/null || true
    cat "$out"
    grep -q "status: Accepted" "$out" || { log "error: notarization did not end Accepted" >&2; exit 1; }
    log "notarized $bin"
    rm -rf "$(dirname "$zip")" "$out"
    exit 0
  fi
  kill -TERM "$watchdog" 2>/dev/null || true
  cat "$out"
  log "notarization attempt $attempt did not succeed"
  sleep 10
done
id=$(sed -n 's/^ *id: \([0-9a-fA-F-]*\) *$/\1/p' "$out" | head -n 1)
if [ -n "$id" ]; then
  xcrun notarytool log "$id" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" >&2 || true
fi
log "error: notarizing $bin failed after 3 attempts" >&2
exit 1
