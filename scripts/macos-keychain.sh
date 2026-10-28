#!/usr/bin/env bash
# Create or delete the throwaway keychain a macOS release job signs from, so the Developer ID private key
# exists on the runner for one job and nowhere else (the recipe straiker-ai/sentry ships with).
#
#   macos-keychain.sh create   # import MACOS_APP_P12; no secret: nothing to do (an unsigned build)
#   macos-keychain.sh delete   # run it even when the job failed (if: always())
#
# MACOS_APP_P12 is the base64 .p12 holding Straiker's Developer ID Application identity, MACOS_APP_P12_PASSWORD
# its export password. The keychain's own password is random per run and never stored.
set -euo pipefail

KEYCHAIN="${KEYCHAIN:-ascend-release.keychain}"
log() { printf 'macos-keychain: %s\n' "$*"; }

create() {
  if [ -z "${MACOS_APP_P12:-}" ]; then
    log "no MACOS_APP_P12; skipping (darwin binaries stay unsigned)"
    return 0
  fi
  : "${MACOS_APP_P12_PASSWORD:?the export password of MACOS_APP_P12}"
  local password p12
  password=$(openssl rand -hex 24)
  security create-keychain -p "$password" "$KEYCHAIN"
  security set-keychain-settings -lut 21600 "$KEYCHAIN"      # auto-locks after 6 h if a job hangs
  security unlock-keychain -p "$password" "$KEYCHAIN"
  # Prepend to the search list, keeping what the runner image relies on.
  # shellcheck disable=SC2046
  security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
  p12=$(mktemp -t p12)
  printf '%s' "$MACOS_APP_P12" | base64 --decode >"$p12"
  security import "$p12" -k "$KEYCHAIN" -P "$MACOS_APP_P12_PASSWORD" -f pkcs12 -T /usr/bin/codesign
  rm -f "$p12"
  # Without this, the first codesign blocks on an access prompt no one can answer.
  security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$KEYCHAIN" >/dev/null
  log "identities (names only):"
  security find-identity -v -p codesigning "$KEYCHAIN"
}

delete() {
  if security delete-keychain "$KEYCHAIN" 2>/dev/null; then
    log "deleted $KEYCHAIN"
  else
    log "no $KEYCHAIN to delete"
  fi
}

case "${1:-}" in
  create) create ;;
  delete) delete ;;
  *) echo "usage: $(basename "$0") create|delete" >&2; exit 2 ;;
esac
