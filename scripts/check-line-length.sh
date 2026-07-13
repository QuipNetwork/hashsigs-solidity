#!/bin/sh
# Enforce CODINGSTANDARDS.md §3: hard 78-char limit on .sol lines.
# Exit 0 = clean; exit 1 = violations printed as "file:line: N chars".
# A line may be exempted by a "// line-length: allow — <reason>"
# comment line directly above it (CODINGSTANDARDS.md §3; reserved for
# single unbreakable tokens and fmt-canonical overflow). The directive
# must be its own (optionally indented) comment line — "line-length:
# allow" appearing elsewhere, e.g. trailing real code or inside a
# string literal, does not count.
# POSIX sh so it runs in the alpine-based Foundry CI image.
# Scans tracked AND untracked (non-ignored) .sol files so a new file
# cannot dodge the gate before its first commit; deleted-but-still-
# indexed paths are skipped. Note: awk length() counts BYTES, so a
# multibyte character (e.g. the 2-byte §) counts twice — deliberately
# stricter than a visual count, and deterministic across locales.
#
# Each stage below writes to its own temp file and its exit status is
# checked explicitly. POSIX sh (dash, used in the CI image) has no
# `pipefail`, so folding this into a single `x=$(cmd1 | cmd2 | cmd3)`
# would let a failure in git ls-files or xargs/awk get swallowed by
# the last command's exit status and produce a silent-green run.
set -eu
cd "$(dirname "$0")/.."

files=$(mktemp)
scanned=$(mktemp)
violations=$(mktemp)
trap 'rm -f "$files" "$scanned" "$violations"' EXIT

if ! git ls-files --cached --others --exclude-standard '*.sol' >"$files"; then
	echo "check-line-length: git ls-files failed" >&2
	exit 1
fi

while read -r f; do
	if [ -f "$f" ]; then
		printf '%s\n' "$f"
	fi
done <"$files" >"$scanned"

if [ -s "$scanned" ]; then
	if ! xargs awk '
        FNR == 1 { allowed = 0 }
        /^[ \t]*\/\/[ \t]*line-length: allow/ { allowed = FNR + 1 }
        length > 78 && FNR != allowed {
            printf "%s:%d: %d chars\n", FILENAME, FNR, length
        }
    ' <"$scanned" >"$violations"; then
		echo "check-line-length: awk scan failed" >&2
		exit 1
	fi
fi

if [ -s "$violations" ]; then
	cat "$violations"
	exit 1
fi
