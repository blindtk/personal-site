#!/usr/bin/env bash
# Workflow naming convention — the same file, byte for byte, in every repo
# of this account (blindtk, github-stars, homelab, honeypot-vps-infra,
# personal-site). The convention itself is written down in
# knowledge-base/notes/nomenclatura-de-workflows.md.
#
#   file:  .github/workflows/<family>[-<object>].yml   (kebab-case, .yml)
#   name:  exactly the file name without .yml
#
#   ci | security | release                  may stand alone, or take -<object>
#   deploy | verify | audit | repair | ops | update   always take -<object>
#
# Fails closed: no workflow directory, or no workflow in it, is a failure,
# not a pass — a check that passes when there is nothing to check is not a
# check.
set -euo pipefail

dir="${1:-.github/workflows}"
[ -d "$dir" ] || { echo "::error::$dir does not exist"; exit 1; }

standalone='ci|security|release'
prefixed='deploy|verify|audit|repair|ops|update'
pattern="^(($standalone)(-[a-z0-9]+)*|($prefixed)(-[a-z0-9]+)+)\$"

count=0
fail=0
for f in "$dir"/*; do
  [ -f "$f" ] || continue
  count=$((count + 1))
  base="$(basename "$f")"
  case "$base" in
    *.yml) ;;
    *) echo "::error file=$f::extension must be .yml (got $base)"; fail=1; continue ;;
  esac
  stem="${base%.yml}"
  if ! [[ "$stem" =~ $pattern ]]; then
    echo "::error file=$f::'$stem' is not <family>[-<object>] with family in: $standalone|$prefixed"
    fail=1
  fi
  # Top-level `name:` only (no indentation), quotes stripped.
  name="$(sed -n 's/^name:[[:space:]]*//p' "$f" | head -n 1 | sed "s/^[\"']//; s/[\"'][[:space:]]*\$//; s/[[:space:]]*\$//")"
  if [ "$name" != "$stem" ]; then
    echo "::error file=$f::top-level name: must be '$stem' (got '${name:-<missing>}')"
    fail=1
  fi
done

[ "$count" -gt 0 ] || { echo "::error::no workflow files in $dir"; exit 1; }
[ "$fail" -eq 0 ] || exit 1
echo "OK: $count workflow(s) follow the naming convention"
