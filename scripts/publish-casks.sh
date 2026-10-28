#!/usr/bin/env bash
# Push the Homebrew casks goreleaser generated (dist/homebrew/Casks/*.rb) to straiker-ai/homebrew-tap, one
# commit per cask. release.yml runs it after it publishes the release, so a cask never points at a draft
# release's downloads (they 404 until publish, and forever if the job fails first).
#
#   publish-casks.sh [tag]   # tag defaults to GITHUB_REF_NAME
#
# GH_TOKEN must be able to write homebrew-tap's contents (the release environment's PACKAGES_TOKEN).
# Prerelease tags (v1.2.3-rc.1) publish nothing, so they can test a release without moving brew users.
set -euo pipefail

tag="${1:-${GITHUB_REF_NAME:?pass the tag or set GITHUB_REF_NAME}}"
tap="${TAP_REPO:-straiker-ai/homebrew-tap}"
log() { printf 'publish-casks: %s\n' "$*"; }

case "$tag" in
  *-*) log "$tag is a prerelease; leaving $tap as it is"; exit 0 ;;
esac
: "${GH_TOKEN:?a token that can write $tap}"

shopt -s nullglob
casks=(dist/homebrew/Casks/*.rb)
[ "${#casks[@]}" -gt 0 ] || { log "error: no casks in dist/homebrew/Casks" >&2; exit 1; }

for cask in "${casks[@]}"; do
  name=$(basename "$cask" .rb)
  path="Casks/$name.rb"
  # The current blob's sha, needed to update a file; empty for a cask the tap doesn't have yet.
  sha=$(gh api "repos/$tap/contents/$path" --jq .sha 2>/dev/null || true)
  args=(-X PUT "repos/$tap/contents/$path"
    -f message="$name ${tag#v}"
    -f content="$(base64 <"$cask" | tr -d '\n')")
  [ -n "$sha" ] && args+=(-f sha="$sha")
  gh api "${args[@]}" --jq '.commit.html_url' | sed "s|^|publish-casks: $name ${tag#v}: |"
done
