#!/bin/sh
# Write the license and NOTICE texts of everything linked into the given commands - each third-party module
# on every platform we build for, and Go's own (its runtime and standard library are in every binary) - to
# one file shipped beside the binaries. The MIT, BSD and ISC licenses ask for their text to travel with a
# binary, and Apache-2.0 for any NOTICE file.
#
#   third-party-notices.sh <output file> <package>...   e.g. THIRD_PARTY_NOTICES ./cmd/ascend-tunnel
#
# POSIX sh, so the Docker build stage (alpine) runs it too. A module whose release has no license file is
# taken from third_party/licenses/<module path> (see its README); one with neither fails the build rather
# than shipping without its notice. Run it from the repository root.
set -eu

out="$1"
shift
[ "$#" -gt 0 ] || { echo "usage: $(basename "$0") <output file> <package>..." >&2; exit 2; }

modules=$(
  for os in linux darwin windows; do
    GOOS=$os go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' "$@"
  done | sort -u
)

rule='================================================================================'
licenses() { # <directory>
  find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' \
    -o -iname 'NOTICE*' \) | sort
}
section() { # <title> <directory> [<module path>]
  files=$(licenses "$2")
  if [ -z "$files" ] && [ -n "${3:-}" ] && [ -d "third_party/licenses/$3" ]; then
    files=$(licenses "third_party/licenses/$3")
  fi
  [ -n "$files" ] || { echo "third-party-notices: no license file for $1 (in $2 or third_party/licenses)" >&2; exit 1; }
  printf '%s\n%s\n%s\n\n' "$rule" "$1" "$rule"
  for f in $files; do
    cat "$f"
    printf '\n'
  done
}

{
  printf 'Third-party software in this distribution, and the terms it is used under.\n\n'
  section "Go $(go env GOVERSION) (runtime and standard library)" "$(go env GOROOT)"
  printf '%s\n' "$modules" | while read -r path version dir; do
    [ -n "$path" ] || continue
    section "$path $version" "$dir" "$path"
  done
} >"$out"
