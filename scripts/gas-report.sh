#!/usr/bin/env bash
# Runs the SHRINCSMeasurements call-gas suite under every build profile
# and renders one markdown table (rows = measurement labels, columns =
# profiles) to stdout. Regenerate README.md's "## Gas Measurements"
# table with this script whenever a measured call shape changes.
set -euo pipefail

FORGE=/opt/homebrew/bin/forge
PROFILES=(default 128s-q18 128s-q20 256s-sha2)

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

header="| Measurement |"
divider="| --- |"
for profile in "${PROFILES[@]}"; do
	header="$header $profile |"
	divider="$divider --- |"
done
echo "$header"
echo "$divider"

while IFS= read -r label; do
	row="| \`$label\` |"
	for profile in "${PROFILES[@]}"; do
		value=$(awk -F'\t' -v p="$profile" -v l="$label" \
			'$1 == p && $2 == l { print $3 }' "$RESULTS")
		row="$row ${value:-—} |"
	done
	echo "$row"
done <"$LABELS"
