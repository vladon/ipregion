#!/usr/bin/env bash
# Regenerates the auto-generated check registry table in README.md
# between the ipregion:checks markers. Run from the repo root:
#   scripts/generate-readme-checks.sh
set -euo pipefail

cd "$(dirname "$0")/.."

START_MARK="<!-- ipregion:checks-start -->"
END_MARK="<!-- ipregion:checks-end -->"
README="README.md"

[[ -f "$README" ]] || { echo "README.md not found" >&2; exit 1; }
grep -q "$START_MARK" "$README" || { echo "markers missing in README.md" >&2; exit 1; }

registry=$(bash ipregion.sh --list)
total=$(wc -l <<<"$registry" | tr -d ' ')

table_file=$(mktemp)
{
  echo
  echo "| Group | Check | Key |"
  echo "|---|---|---|"
  while IFS=$'\t' read -r group key display; do
    echo "| $group | $display | \`$key\` |"
  done <<<"$registry"
  echo
  echo "Total: $total checks."
  echo "$END_MARK"
} >"$table_file"

awk -v repl_file="$table_file" '
  $0 == start_mark {
    print start_mark
    while ((getline line < repl_file) > 0) print line
    skip = 1
    next
  }
  $0 == end_mark { skip = 0 }
  skip { next }
  { print }
' start_mark="$START_MARK" end_mark="$END_MARK" "$README" >"$README.tmp"
mv "$README.tmp" "$README"
rm -f "$table_file"
echo "README check registry updated: $total checks"
