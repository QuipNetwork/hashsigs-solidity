#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-$ROOT_DIR/test/test_vectors/shrincs_account_wrapper_vectors.json}"

# Pinned the same way as scripts/gas-report.sh: a bare `forge` can resolve
# to an unrelated PATH entry on this team's machines. Default to the
# Foundry install location and allow an override for machines that keep
# it elsewhere.
FORGE="${FORGE:-/opt/homebrew/bin/forge}"

mkdir -p "$(dirname "$OUTPUT_PATH")"

TMP_OUTPUT="$(mktemp)"
AWK_OUTPUT="$(mktemp)"
trap 'rm -f "$TMP_OUTPUT" "$AWK_OUTPUT"' EXIT

cd "$ROOT_DIR"
"$FORGE" test --match-path test/SHRINCSAccountVectorExport.t.sol -vv >"$TMP_OUTPUT"

awk '
function flush_test() {
    if (current_test == "") return
    tests[++test_count] = current_test
}

function json_escape(str,    out) {
    out = str
    gsub(/\\/, "\\\\", out)
    gsub(/"/, "\\\"", out)
    return out
}

/^\[PASS\] test/ {
    flush_test()
    current_test = $2
    sub(/\(.*/, "", current_test)
    next
}

/^  [A-Za-z0-9_]+: 0x[0-9a-fA-F]+$/ {
    if (current_test == "") next
    line = $0
    sub(/^  /, "", line)
    split(line, parts, ": ")
    key = parts[1]
    value = parts[2]
    compound = current_test SUBSEP key
    if (!(compound in seen)) {
        seen[compound] = 1
        key_count[current_test]++
        keys[current_test, key_count[current_test]] = key
    }
    values[compound] = value
    next
}

END {
    flush_test()
    print "{"
    for (i = 1; i <= test_count; ++i) {
        test = tests[i]
        printf "  \"%s\": {\n", json_escape(test)
        for (j = 1; j <= key_count[test]; ++j) {
            key = keys[test, j]
            compound = test SUBSEP key
            comma = (j < key_count[test]) ? "," : ""
            printf "    \"%s\": \"%s\"%s\n", json_escape(key), values[compound], comma
        }
        comma = (i < test_count) ? "," : ""
        printf "  }%s\n", comma
    }
    print "}"
}
' "$TMP_OUTPUT" >"$AWK_OUTPUT"

# Guard mirrors scripts/gas-report.sh's zero-metrics check: refuse to
# overwrite the committed fixture if forge's output yielded no test
# vectors (e.g. the match path found no tests, or forge's log format
# changed underneath the awk patterns above) instead of silently
# clobbering it with an empty "{}".
extracted_count=$(grep -c '^  "' "$AWK_OUTPUT" || true)
if [ "${extracted_count:-0}" -eq 0 ]; then
	echo "export-account-vectors: no test vectors extracted from forge" \
		"output; refusing to overwrite $OUTPUT_PATH" >&2
	exit 1
fi

mv "$AWK_OUTPUT" "$OUTPUT_PATH"
echo "Wrote $OUTPUT_PATH"
