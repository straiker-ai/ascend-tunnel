#!/usr/bin/env bash
# Tag the head of main for the release being run (release.yml, Run workflow). Runs after the release
# environment's approval, so a run nobody approved leaves no tag.
#
#   release-tag.sh <version>     e.g. v1.2.3-rc.1 or v1.2.3
#
# Environment: GH_TOKEN (contents: write), GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA.
set -euo pipefail

tag="${1:?usage: release-tag.sh <version>}"
log() { printf 'release-tag: %s\n' "$*"; }
die() { log "error: $*" >&2; exit 1; }

[ "${GITHUB_REF:-}" = refs/heads/main ] || die "run the workflow on main, not ${GITHUB_REF:-?}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die "$tag is not a version: v1.2.3 for a release, v1.2.3-rc.1 for a candidate"

remote="https://x-access-token:${GH_TOKEN:?}@github.com/${GITHUB_REPOSITORY:?}.git"
if git ls-remote --exit-code --tags "$remote" "refs/tags/$tag" >/dev/null; then
  die "$tag exists already; releases never move, so pick the next version"
fi

git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
  tag -a "$tag" -m "$tag" "${GITHUB_SHA:?}"
git push "$remote" "refs/tags/$tag"
log "tagged ${GITHUB_SHA:0:7} (main) as $tag"
