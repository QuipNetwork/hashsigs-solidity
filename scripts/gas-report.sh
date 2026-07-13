#!/usr/bin/env bash
# Runs the SHRINCSMeasurements call-gas suite under every build profile
# and renders one markdown table (rows = measurement labels, columns =
# profiles) to stdout. Regenerate README.md's "## Gas Measurements"
# table with this script whenever a measured call shape changes.
set -euo pipefail

FORGE=/opt/homebrew/bin/forge
PROFILES=(default 128s-q18 128s-q20 256s-sha2)

# Mirrors test/SHRINCSMeasurements.t.sol's isStateless128sVectorProfile()
# gate: under these profiles, these two labels measure the raw
# SHRINCS.verifyStatelessUncheckedMessage call through
# MeasurementRawStatelessHarness (wrapper context-hash derivation
# excluded) instead of the full account wrapper. The delegation label is
# excluded: it calls the real verifyStateless entrypoint on every
# profile, vector-sourced inputs at 128s notwithstanding.
RAW_HARNESS_PROFILES=(128s-q18 128s-q20)
RAW_HARNESS_LABELS=(
	stateless.canonical_wrapper_call_gas
	stateless.erc1271_call_gas
)

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

RESULTS="$WORKDIR/results.tsv"
LABELS="$WORKDIR/labels.txt"
: >"$RESULTS"
: >"$LABELS"

for profile in "${PROFILES[@]}"; do
	log="$WORKDIR/$profile.log"
	if ! FOUNDRY_PROFILE="$profile" "$FORGE" test \
		--match-contract SHRINCSMeasurements -vv >"$log" 2>&1; then
		echo "gas-report: forge test failed under profile $profile" >&2
		cat "$log" >&2
		exit 1
	fi

	count=0
	while IFS=$'\t' read -r label value; do
		printf '%s\t%s\t%s\n' "$profile" "$label" "$value" >>"$RESULTS"
		if ! grep -qxF "$label" "$LABELS"; then
			printf '%s\n' "$label" >>"$LABELS"
		fi
		count=$((count + 1))
	done < <(grep -E '^  [A-Za-z0-9_.]+: [0-9]+$' "$log" |
		sed -E 's/^  ([A-Za-z0-9_.]+): ([0-9]+)$/\1\t\2/')

	if [[ "$count" -eq 0 ]]; then
		echo "gas-report: profile $profile emitted zero metrics" >&2
		exit 1
	fi
done

# Formats a non-negative integer with thousands separators (e.g. 190792
# -> 190,792) without depending on locale (`printf %'d` is locale-gated
# and not portable to the alpine-based CI image).
comma_format() {
	local n=$1
	local out="" len=${#n} tail
	while ((len > 3)); do
		tail=${n:len-3:3}
		n=${n:0:len-3}
		out=",$tail$out"
		len=${#n}
	done
	printf '%s' "$n$out"
}

array_contains() {
	local needle=$1 item
	shift
	for item in "$@"; do
		[[ "$item" == "$needle" ]] && return 0
	done
	return 1
}

is_raw_harness_cell() {
	local profile=$1 label=$2
	array_contains "$profile" "${RAW_HARNESS_PROFILES[@]}" || return 1
	array_contains "$label" "${RAW_HARNESS_LABELS[@]}"
}

header="| Measurement |"
divider="| --- |"
for profile in "${PROFILES[@]}"; do
	header="$header $profile |"
	divider="$divider --- |"
done
echo "$header"
echo "$divider"

footnote_needed=0
while IFS= read -r label; do
	row="| \`$label\` |"
	for profile in "${PROFILES[@]}"; do
		value=$(awk -F'\t' -v p="$profile" -v l="$label" \
			'$1 == p && $2 == l { print $3 }' "$RESULTS")
		if [[ -z "$value" ]]; then
			cell="—"
		else
			cell=$(comma_format "$value")
			if is_raw_harness_cell "$profile" "$label"; then
				cell="${cell}†"
				footnote_needed=1
			fi
		fi
		row="$row $cell |"
	done
	echo "$row"
done <"$LABELS"

if [[ "$footnote_needed" -eq 1 ]]; then
	echo
	echo "† raw \`SHRINCS.verifyStatelessUncheckedMessage\` call (wrapper" \
		"context-hash derivation excluded); see README.md \"Gas" \
		"Measurements\" for detail."
fi
