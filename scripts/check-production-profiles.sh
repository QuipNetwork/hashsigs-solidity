#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

fail() {
    echo "production-profile policy check failed: $1" >&2
    exit 1
}

for profile in \
    test-128s-q18 \
    test-128s-q20 \
    experimental-128s-q18 \
    experimental-128s-q20
do
    grep -Fq "[profile.$profile]" foundry.toml || \
        fail "missing [profile.$profile]"
done

if grep -Eq '^\[profile\.production-128s-q(18|20)\]' foundry.toml; then
    fail "a 128-bit profile is named production"
fi

if grep -Eq '^\[profile\.128s-q(18|20)\]' foundry.toml; then
    fail "a 128-bit test profile is not named test-*"
fi

if grep -Eq 'out-128s-q(18|20)-prod' foundry.toml; then
    fail "an experimental output directory is named production"
fi

if find script -maxdepth 1 -type f -name '*.sol' -exec \
    grep -El '128sQ(18|20)' {} + | grep -q .; then
    fail "a production deployment script imports a 128-bit profile"
fi

if grep -Eq 'QUIP:(SHRINCS|SPHINCSPlusC)128sQ(18|20)' DEPLOYMENTS.md; then
    fail "DEPLOYMENTS.md advertises a production salt for a 128-bit profile"
fi

if grep -Eiq \
    '23cc6a3b31a3f6734530fcddb19eabe31f9a3037|f6e309c6795447584110404fbae112e4236d40ad|695ba9d92fb431b4d446eecb40b9874c9e43cc91|a301c72c150d735ed741f3fd980691d1a77f7c52' \
    contracts/*.sol
then
    fail "a contract embeds a former canonical 128-bit deployment address"
fi

echo "production-profile policy check passed"
