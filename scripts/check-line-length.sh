#!/usr/bin/env bash
# Enforce CODINGSTANDARDS.md §3: hard 78-char limit on .sol lines.
# Exit 0 = clean; exit 1 = violations printed as "file:line: N chars".
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
while IFS= read -r file; do
    if ! awk -v f="$file" '
        length > 78 { printf "%s:%d: %d chars\n", f, FNR, length; bad = 1 }
        END { exit bad }
    ' "$file"; then
        status=1
    fi
done < <(git ls-files "*.sol")
exit "$status"
