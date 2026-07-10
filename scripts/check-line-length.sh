#!/usr/bin/env bash
# Enforce CODINGSTANDARDS.md §3: hard 78-char limit on .sol lines.
# Exit 0 = clean; exit 1 = violations printed as "file:line: N chars".
# A line may be exempted by the directive "// line-length: allow —
# <reason>" on the line directly above it (CODINGSTANDARDS.md §3;
# reserved for single unbreakable tokens such as long names or
# literals).
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
while IFS= read -r file; do
    if ! awk -v f="$file" '
        /line-length: allow/ { allowed = FNR + 1 }
        length > 78 && FNR != allowed {
            printf "%s:%d: %d chars\n", f, FNR, length
            bad = 1
        }
        END { exit bad }
    ' "$file"; then
        status=1
    fi
done < <(git ls-files "*.sol")
exit "$status"
