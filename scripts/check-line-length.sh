#!/bin/sh
# Enforce CODINGSTANDARDS.md §3: hard 78-char limit on .sol lines.
# Exit 0 = clean; exit 1 = violations printed as "file:line: N chars".
# A line may be exempted by the directive "// line-length: allow —
# <reason>" on the line directly above it (CODINGSTANDARDS.md §3;
# reserved for single unbreakable tokens and fmt-canonical overflow).
# POSIX sh so it runs in the alpine-based Foundry CI image.
set -eu
cd "$(dirname "$0")/.."

violations=$(git ls-files '*.sol' | xargs awk '
    FNR == 1 { allowed = 0 }
    /line-length: allow/ { allowed = FNR + 1 }
    length > 78 && FNR != allowed {
        printf "%s:%d: %d chars\n", FILENAME, FNR, length
    }
')
if [ -n "$violations" ]; then
    printf "%s\n" "$violations"
    exit 1
fi
