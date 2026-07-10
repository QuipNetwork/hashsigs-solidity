#!/bin/sh
# Enforce CODINGSTANDARDS.md §3: hard 78-char limit on .sol lines.
# Exit 0 = clean; exit 1 = violations printed as "file:line: N chars".
# A line may be exempted by the directive "// line-length: allow —
# <reason>" on the line directly above it (CODINGSTANDARDS.md §3;
# reserved for single unbreakable tokens and fmt-canonical overflow).
# POSIX sh so it runs in the alpine-based Foundry CI image.
# Scans tracked AND untracked (non-ignored) .sol files so a new file
# cannot dodge the gate before its first commit; deleted-but-still-
# indexed paths are skipped. Note: awk length() counts BYTES, so a
# multibyte character (e.g. the 2-byte §) counts twice — deliberately
# stricter than a visual count, and deterministic across locales.
set -eu
cd "$(dirname "$0")/.."

violations=$(git ls-files --cached --others --exclude-standard '*.sol' |
    while read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done |
    xargs awk '
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
