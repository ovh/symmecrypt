#!/usr/bin/env bash
# Functional tests for the symmecrypt CLI.
# Usage: bash scripts/test-cli.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); echo "  ok: $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  KO: $1" >&2; }

assert_eq() { # <description> <expected> <actual>
	if [ "$2" = "$3" ]; then ok "$1"; else ko "$1 (expected '$2', got '$3')"; fi
}

assert_fails() { # <description> <command...>
	local desc="$1"
	shift
	if "$@" >/dev/null 2>&1; then ko "$desc (expected failure)"; else ok "$desc"; fi
}

echo "== build"
BIN="$WORKDIR/symmecrypt"
(cd "$ROOT" && go build -o "$BIN" ./cmd/symmecrypt)

echo "== env var roundtrip"
export ENCRYPTION_KEY_BASE64="$("$BIN" key new --base64)"
out=$(echo -n hello | "$BIN" encrypt --base64 | "$BIN" decrypt --base64)
assert_eq "encrypt|decrypt via ENCRYPTION_KEY_BASE64" "hello" "$out"

echo "== key file + extra data"
"$BIN" key new --cipher aes-gcm --identifier storage >"$WORKDIR/key.json"
echo -n "secret data" | "$BIN" encrypt --key-file "$WORKDIR/key.json" --extra ctx1 --extra ctx2 >"$WORKDIR/data.enc"
out=$("$BIN" decrypt --key-file "$WORKDIR/key.json" --extra ctx1 --extra ctx2 <"$WORKDIR/data.enc")
assert_eq "roundtrip with extra data" "secret data" "$out"
assert_fails "decrypt with wrong extra fails" \
	"$BIN" decrypt --key-file "$WORKDIR/key.json" --extra wrong --in "$WORKDIR/data.enc"

echo "== configstore file"
printf -- "- key: encryption-key\n  value: '%s'\n" "$(cat "$WORKDIR/key.json")" >"$WORKDIR/config.yml"
out=$(echo -n "via configstore" | "$BIN" encrypt --config "$WORKDIR/config.yml" |
	"$BIN" decrypt --config "$WORKDIR/config.yml")
assert_eq "roundtrip via configstore file" "via configstore" "$out"

echo "== key rotation"
echo -n "old data" | "$BIN" encrypt --key-file "$WORKDIR/key.json" >"$WORKDIR/old.enc"
"$BIN" key rotate --key-file "$WORKDIR/key.json" >"$WORKDIR/keyring.json"
assert_eq "rotate emits 2 configs" "2" "$(wc -l <"$WORKDIR/keyring.json")"
out=$("$BIN" decrypt --key-file "$WORKDIR/keyring.json" <"$WORKDIR/old.enc")
assert_eq "old ciphertext still decryptable after rotate" "old data" "$out"
out=$(echo -n "new data" | "$BIN" encrypt --key-file "$WORKDIR/keyring.json" |
	"$BIN" decrypt --key-file "$WORKDIR/keyring.json")
assert_eq "roundtrip with rotated keyring" "new data" "$out"

echo "== inspect"
secret=$(sed -n 's/.*"key":"\([^"]*\)".*/\1/p' "$WORKDIR/key.json")
out=$("$BIN" key inspect --key-file "$WORKDIR/keyring.json")
if echo "$out" | grep -q "$secret"; then ko "inspect leaks key material"; else ok "inspect does not leak key material"; fi
if echo "$out" | grep -q "storage"; then ok "inspect shows the identifier"; else ko "inspect misses the identifier"; fi

echo "== stream (5MiB)"
dd if=/dev/urandom of="$WORKDIR/big.bin" bs=1M count=5 2>/dev/null
"$BIN" encrypt --stream --key-file "$WORKDIR/key.json" --in "$WORKDIR/big.bin" --out "$WORKDIR/big.enc"
"$BIN" decrypt --stream --key-file "$WORKDIR/key.json" --in "$WORKDIR/big.enc" --out "$WORKDIR/big.dec"
if cmp -s "$WORKDIR/big.bin" "$WORKDIR/big.dec"; then ok "stream roundtrip (5MiB)"; else ko "stream roundtrip (5MiB)"; fi
assert_fails "plain decrypt of stream data fails" \
	"$BIN" decrypt --key-file "$WORKDIR/key.json" --in "$WORKDIR/big.enc" --out /dev/null

echo "== seal ceremony"
"$BIN" seal new --min 2 --total 3 >"$WORKDIR/seal.json" 2>"$WORKDIR/shards.txt"
assert_eq "seal new emits 3 shards" "3" "$(grep -cv '^#' "$WORKDIR/shards.txt")"
"$BIN" key seal --seal-file "$WORKDIR/seal.json" --shard-file "$WORKDIR/shards.txt" \
	--key-file "$WORKDIR/key.json" >"$WORKDIR/sealed.key"
out=$("$BIN" key inspect --key-file "$WORKDIR/sealed.key")
if echo "$out" | grep -q "true"; then ok "sealed config inspected as sealed"; else ko "sealed config not marked sealed"; fi
shard1=$(grep -v '^#' "$WORKDIR/shards.txt" | sed -n 1p)
shard3=$(grep -v '^#' "$WORKDIR/shards.txt" | sed -n 3p)
out=$(echo -n topsecret |
	"$BIN" encrypt --key-file "$WORKDIR/sealed.key" --seal-file "$WORKDIR/seal.json" --shard "$shard1" --shard "$shard3" --base64 |
	"$BIN" decrypt --key-file "$WORKDIR/sealed.key" --seal-file "$WORKDIR/seal.json" --shard "$shard1" --shard "$shard3" --base64)
assert_eq "roundtrip with sealed key (2 shards)" "topsecret" "$out"
assert_fails "sealed key with 1 shard fails" \
	"$BIN" key unseal --seal-file "$WORKDIR/seal.json" --shard "$shard1" --key-file "$WORKDIR/sealed.key"
out=$("$BIN" key unseal --seal-file "$WORKDIR/seal.json" --shard-file "$WORKDIR/shards.txt" \
	--key-file "$WORKDIR/sealed.key" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
assert_eq "unseal restores original key material" "$secret" "$out"

echo "== exit codes"
set +e
"$BIN" bogus >/dev/null 2>&1
rc=$?
set -e
assert_eq "unknown command exits 2" "2" "$rc"
set +e
unset ENCRYPTION_KEY_BASE64
echo x | "$BIN" encrypt >/dev/null 2>&1
rc=$?
set -e
assert_eq "missing key exits 1" "1" "$rc"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
