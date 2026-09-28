#!/usr/bin/env bash
# Round trip used by CI on Linux, macOS and Windows (Git Bash).
#
# <bin> is the directory holding the vault-seal and vault-open binaries.
#
#   round-trip.sh seal <bin> <dir>
#       Seal sample files into <dir> under the shared test key: an empty
#       file, one byte, exactly one chunk, 5 MB (several batches) and a
#       proven text file. The originals are kept in <dir>/originals.
#   round-trip.sh open <bin> <dir>...
#       Verify every sample sealed into each <dir> (the proven one must
#       verify as PROVEN), open it, and compare it with the original.
#
# The test key below is public: it must never protect anything real.
set -euo pipefail

TEST_SECRET=0x1111111111111111111111111111111111111111111111111111111111111111
PLAIN="empty.bin one.bin chunk.bin big.bin"
PROVEN=proven.txt

mode=${1:?usage: round-trip.sh seal|open <bin> <dir>...}
bin=${2:?missing the directory holding vault-seal and vault-open}
shift 2
exe=
[ -f "$bin/vault-seal.exe" ] && exe=.exe
vs=$bin/vault-seal$exe
vo=$bin/vault-open$exe

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' "$TEST_SECRET" > "$work/test.secret"
key=$("$vs" pubkey --secret-file "$work/test.secret" | tr -d '\r' | awk '/^campaign key/ {print $NF}')
[ -n "$key" ] || { echo "FAIL: could not derive the test campaign key" >&2; exit 1; }

case $mode in
  seal)
    dir=${1:?missing the output directory}
    mkdir -p "$dir/originals"
    : > "$dir/originals/empty.bin"
    printf 'x' > "$dir/originals/one.bin"
    head -c 65536 /dev/urandom > "$dir/originals/chunk.bin"
    head -c 5000000 /dev/urandom > "$dir/originals/big.bin"
    printf 'sealed and proven on %s\n' "$(uname -s)" > "$dir/originals/$PROVEN"
    for f in $PLAIN; do
      "$vs" seal --campaign-key "$key" "$dir/originals/$f" --out-dir "$dir" > /dev/null ||
        { echo "FAIL: sealing $f" >&2; exit 1; }
    done
    "$vs" seal --campaign-key "$key" "$dir/originals/$PROVEN" --out-dir "$dir" --prove > /dev/null ||
      { echo "FAIL: sealing and proving $PROVEN" >&2; exit 1; }
    echo "sealed into $dir: $(cd "$dir" && printf '%s ' *)"
    ;;
  open)
    [ $# -gt 0 ] || { echo "FAIL: no directories to open" >&2; exit 1; }
    for dir in "$@"; do
      out="$work/opened/$(basename "$dir")"
      for f in $PLAIN $PROVEN; do
        meta="$dir/$f.meta.json"
        [ -f "$meta" ] || { echo "FAIL: $meta is missing" >&2; exit 1; }
        want=OK
        [ "$f" = "$PROVEN" ] && want=PROVEN
        if ! report=$("$vo" verify --campaign-key "$key" "$meta"); then
          echo "FAIL: $meta does not verify (the error is above)" >&2
          exit 1
        fi
        verdict=$(printf '%s\n' "$report" | tr -d '\r' | sed -n 1p)
        case $verdict in
          "$want":*) ;;
          *) echo "FAIL: verify $meta: expected $want, got: $verdict" >&2; exit 1 ;;
        esac
        "$vo" open --secret-file "$work/test.secret" "$meta" --out-dir "$out" > /dev/null ||
          { echo "FAIL: $meta does not open (the error is above)" >&2; exit 1; }
        cmp -s "$dir/originals/$f" "$out/$f" || { echo "FAIL: $dir/$f does not open to the original" >&2; exit 1; }
        echo "ok  $dir/$f ($want)"
      done
    done
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 1
    ;;
esac
