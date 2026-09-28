#!/usr/bin/env bash
# End-to-end run on a local anvil chain, following docs/coordinator.md and
# docs/creators.md step by step. Every check fails the run if it doesn't hold.
# Set VAULT_SEAL and VAULT_OPEN to the two binaries to skip building them.
set -euo pipefail
export PATH=$HOME/.cargo/bin:$HOME/.foundry/bin:$PATH
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { [ "$1" = "$2" ] || fail "$3: expected $2, got $1"; }

if [ -n "${VAULT_SEAL:-}" ] && [ -n "${VAULT_OPEN:-}" ]; then
  VS=$VAULT_SEAL
  VO=$VAULT_OPEN
else
  (cd "$ROOT/vault-seal" && cargo build --release -q)
  VS=$ROOT/vault-seal/target/release/vault-seal
  VO=$ROOT/vault-seal/target/release/vault-open
fi
W=$(mktemp -d); cd "$W"
export RPC_URL=http://127.0.0.1:8545
anvil --silent >/dev/null 2>&1 & ANVIL=$!
trap 'kill $ANVIL 2>/dev/null; rm -rf "$W"' EXIT
for _ in $(seq 100); do
  cast block-number --rpc-url $RPC_URL >/dev/null 2>&1 && break
  sleep 0.1
done
cast block-number --rpc-url $RPC_URL >/dev/null 2>&1 || fail "anvil did not start"
COORD_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil account 0
BACKER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d  # anvil account 1

echo "== Coordinator: generate the campaign key"
$VS keygen --out campaign.secret > keygen.txt 2>/dev/null
eval "$(grep KEY_ keygen.txt)"
EXPECTED_KEY_ADDRESS=$(grep keyAddress keygen.txt | awk '{print $NF}')

echo "== Coordinator: deploy"
cd "$ROOT/contracts"
export RECIPIENT=0x000000000000000000000000000000000000bEEF
THRESHOLD_WEI=$(cast to-wei 5 ether)
export THRESHOLD_WEI
export CLAIM_WINDOW_SECONDS=3600
export KEY_X KEY_Y
OUT=$(forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --private-key $COORD_KEY 2>&1)
VAULT=$(echo "$OUT" | grep "deployed at" | awk '{print $NF}')
FACTORY=$(echo "$OUT" | grep "CrowdVaultFactory at" | awk '{print $NF}')
if [ -z "$VAULT" ] || [ -z "$FACTORY" ]; then
  echo "$OUT" >&2
  fail "deployment printed no addresses"
fi
cd "$W"
RECOGNIZED=$(cast call "$FACTORY" "isVault(address)(bool)" "$VAULT" --rpc-url $RPC_URL)
expect "$RECOGNIZED" true "factory recognizes the vault"
echo "factory recognizes the vault: $RECOGNIZED"
CHECK=$(cast balance $RECIPIENT --rpc-url $RPC_URL)
expect "$CHECK" 1 "recipient's 1 wei check"
echo "recipient received the 1 wei check: $CHECK wei"
ONCHAIN=$(cast call "$VAULT" "keyAddress()(address)" --rpc-url $RPC_URL)
expect "$(echo "$ONCHAIN" | tr A-F a-f)" "$EXPECTED_KEY_ADDRESS" "vault's key address"
echo "vault $VAULT holds the right key"

echo "== Creator: read the campaign key from the vault and seal"
KX=$(cast call "$VAULT" "keyX()" --rpc-url $RPC_URL)
KY=$(cast call "$VAULT" "keyY()" --rpc-url $RPC_URL)
CAMPAIGN_KEY=04${KX#0x}${KY#0x}
echo "hello from the collective" > note.txt
head -c 5000000 /dev/urandom > film.bin
for f in note.txt film.bin; do
  $VS seal --campaign-key "$CAMPAIGN_KEY" "$f" --out-dir sealed > /dev/null
done
echo "roses are sealed, violets are proven" > poem.txt
$VS seal --campaign-key "$CAMPAIGN_KEY" poem.txt --out-dir sealed --prove | grep -E "proof:|gates"
echo "published fingerprint: $($VS fingerprint poem.txt)"

echo "== Backer: verify against the vault's key, then contribute"
for f in note.txt film.bin poem.txt; do
  REPORT=$($VO verify --campaign-key "$CAMPAIGN_KEY" "sealed/$f.meta.json")
  echo "${REPORT%%$'\n'*}"
done
cast send "$VAULT" "contribute()" --value 6ether --private-key $BACKER_KEY --rpc-url $RPC_URL > /dev/null
PHASE=$(cast call "$VAULT" 'phase()(uint8)' --rpc-url $RPC_URL)
expect "$PHASE" 1 "phase after the goal is met (1 = Locked)"
echo "phase: $PHASE (1 = Locked)"

echo "== Coordinator: check the secret locally, then claim"
LOCAL=$($VS pubkey --secret-file campaign.secret | grep keyAddress | awk '{print $NF}')
expect "$LOCAL" "$EXPECTED_KEY_ADDRESS" "local secret's key address"
echo "secret matches the vault"
cast send "$VAULT" "claim(uint256)" "$(cat campaign.secret)" --private-key $COORD_KEY --rpc-url $RPC_URL > /dev/null
PHASE=$(cast call "$VAULT" 'phase()(uint8)' --rpc-url $RPC_URL)
RELEASED=$(cast from-wei "$(cast call "$VAULT" 'releasedAmount()(uint256)' --rpc-url $RPC_URL | awk '{print $1}')")
expect "$PHASE" 2 "phase after the claim (2 = Claimed)"
expect "$RELEASED" 6.000000000000000000 "amount released"
echo "phase: $PHASE (2 = Claimed), released $RELEASED ETH"

echo "== Everyone: read the key from the vault and open"
KEY=$(cast to-hex "$(cast call "$VAULT" 'revealedKey()(uint256)' --rpc-url $RPC_URL | awk '{print $1}')")
for f in note.txt film.bin poem.txt; do
  $VO open --secret "$KEY" "sealed/$f.meta.json" --out-dir opened > /dev/null
  cmp -s "$f" "opened/$f" || fail "opened $f differs from the original"
  echo "opened $f: identical to the original"
done
echo "== All end-to-end checks passed"
