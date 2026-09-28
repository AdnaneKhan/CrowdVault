#!/usr/bin/env bash
# macOS only. An unsigned build must remind the user to sign it with the
# hardened runtime before handling secrets; once signed, the reminder must
# stop. The binary is left signed, so later CI steps run the hardened build.
set -euo pipefail
vs=${1:?usage: check-macos-signing.sh <vault-seal>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$vs" keygen --out "$work/k.secret" > /dev/null 2> "$work/unsigned.txt"
if ! grep -q "hardened runtime" "$work/unsigned.txt"; then
  echo "FAIL: an unsigned build did not remind the user to sign it" >&2
  cat "$work/unsigned.txt" >&2
  exit 1
fi

codesign --force --options runtime --sign - "$vs"
if ! codesign --display --verbose "$vs" 2>&1 | grep -q "flags=.*runtime"; then
  echo "FAIL: the signature does not carry the hardened runtime" >&2
  exit 1
fi

"$vs" pubkey --secret-file "$work/k.secret" > /dev/null 2> "$work/signed.txt"
if grep -q "hardened runtime" "$work/signed.txt"; then
  echo "FAIL: a signed build still shows the reminder" >&2
  exit 1
fi
echo "hardened-runtime reminder: shown before signing, gone after"
