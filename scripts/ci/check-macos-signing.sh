#!/usr/bin/env bash
# macOS only. An unsigned build of either tool must remind the user to sign it
# with the hardened runtime before handling secrets; once signed, the reminder
# must stop. The binaries are left signed, so later CI steps run the hardened
# builds.
set -euo pipefail
bin=${1:?usage: check-macos-signing.sh <directory holding vault-seal and vault-open>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$bin/vault-seal" keygen --out "$work/k.secret" > /dev/null

# Each tool's first command that handles a secret. vault-open warns before
# it reads the (missing) sealed file, so its failure here is expected.
seal_secret() { "$bin/vault-seal" pubkey --secret-file "$work/k.secret" > /dev/null; }
open_secret() { "$bin/vault-open" open --secret-file "$work/k.secret" "$work/none.sealed" > /dev/null || true; }

check() {
  local name=$1 run=$2 vs=$bin/$1
  $run 2> "$work/unsigned.txt"
  if ! grep -q "hardened runtime" "$work/unsigned.txt"; then
    echo "FAIL: an unsigned $name did not remind the user to sign it" >&2
    cat "$work/unsigned.txt" >&2
    exit 1
  fi

  codesign --force --options runtime --sign - "$vs"
  # Capture first: with pipefail, grep -q closing the pipe early can fail codesign.
  sig=$(codesign --display --verbose "$vs" 2>&1)
  if ! grep -q "flags=.*runtime" <<< "$sig"; then
    echo "FAIL: $name's signature does not carry the hardened runtime" >&2
    exit 1
  fi

  $run 2> "$work/signed.txt"
  if grep -q "hardened runtime" "$work/signed.txt"; then
    echo "FAIL: a signed $name still shows the reminder" >&2
    exit 1
  fi
  echo "$name hardened-runtime reminder: shown before signing, gone after"
}

check vault-seal seal_secret
check vault-open open_secret
