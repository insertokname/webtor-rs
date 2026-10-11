#!/usr/bin/env bash
# Fetch a Tor directory snapshot: the microdescriptor consensus, the directory
# authorities' key certificates and the microdescriptor of every relay in the
# consensus.
#
# Usage: scripts/fetch-consensus.sh [OUTPUT_DIR]   (default webtor/src/cached)
#
# Writes consensus.txt, certs.txt and microdescriptors.txt, brotli copies
# (*.txt.br) and fetched_at.txt.
#
# The documents are fetched over plain HTTP from the directory authorities,
# as Tor clients without a cache do. Nothing is trusted on the way: webtor
# (directory.rs) checks the consensus signatures against the authority
# certificates, the certificates against the authority identities pinned in
# its code (Arti's list), and every microdescriptor against its digest in the
# signed consensus, and refuses documents that fail.

set -euo pipefail

OUTPUT_DIR="${1:-webtor/src/cached}"
mkdir -p "$OUTPUT_DIR"

# Directory authorities (Arti's default list, tor-dircommon authority.rs).
AUTHORITIES=(
  204.13.164.118:80   # bastet
  193.23.244.244:80   # dannenberg
  45.66.35.11:80      # dizum
  216.218.219.41:80   # faravahar
  131.188.40.189:80   # gabelmoo
  199.58.81.140:80    # longclaw
  171.25.193.9:443    # maatuska
  128.31.0.39:9231    # moria1
  217.196.147.77:80   # tor26
)
# Microdescriptor digests per request (Tor clients ask for at most 92).
BATCH_SIZE=90
# Requests in flight at once.
PARALLEL=4
# The snapshot is refused below this share of relays with a microdescriptor.
MIN_MICRODESC_PERCENT=95

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

is_consensus() { head -1 "$1" | grep -qx 'network-status-version 3 microdesc'; }
is_certs() { grep -q '^dir-key-certificate-version 3' "$1"; }
is_microdescs() { grep -q '^ntor-onion-key ' "$1"; }

# fetch PATH OUT CHECK: GET PATH from the authorities, starting at a random
# one, until a response passes CHECK.
fetch() {
  local path="$1" out="$2" check="$3"
  local n=${#AUTHORITIES[@]} start=$((RANDOM % ${#AUTHORITIES[@]})) i auth
  for ((i = 0; i < n; i++)); do
    auth="${AUTHORITIES[$(((start + i) % n))]}"
    if curl -sSf --connect-timeout 10 --max-time 120 -o "$out" "http://$auth$path" 2> "$out.err" \
      && "$check" "$out"; then
      rm -f "$out.err"
      return 0
    fi
    echo "   $auth$path: failed $(head -c 200 "$out.err" 2> /dev/null)" >&2
  done
  return 1
}

echo "Fetching the microdescriptor consensus..."
fetch /tor/status-vote/current/consensus-microdesc "$WORK/consensus.txt" is_consensus || {
  echo "could not fetch the consensus from any directory authority" >&2
  exit 1
}
RELAY_COUNT=$(grep -c '^r ' "$WORK/consensus.txt")
echo "   consensus: $(wc -c < "$WORK/consensus.txt") bytes, $RELAY_COUNT relays"

echo "Fetching the directory authorities' key certificates..."
# The current certificates of the authorities that signed the consensus.
SIGNERS=$(sed -n 's/^directory-signature \(sha256 \)\{0,1\}\([0-9A-F]\{40\}\) .*/\2/p' "$WORK/consensus.txt" | sort -u | paste -sd+)
fetch "/tor/keys/fp/$SIGNERS" "$WORK/certs.txt" is_certs || {
  echo "could not fetch the authority certificates from any directory authority" >&2
  exit 1
}
echo "   certificates: $(grep -c '^dir-key-certificate-version' "$WORK/certs.txt")"

echo "Fetching microdescriptors..."
mapfile -t DIGESTS < <(sed -n 's/^m //p' "$WORK/consensus.txt" | sort -u)
mkdir -p "$WORK/md"
BATCHES=0
for ((offset = 0; offset < ${#DIGESTS[@]}; offset += BATCH_SIZE)); do
  (IFS=-; echo "/tor/micro/d/${DIGESTS[*]:offset:BATCH_SIZE}") > "$WORK/md/$(printf '%05d' "$BATCHES").path"
  BATCHES=$((BATCHES + 1))
done
fetch_batch() {
  local path_file="$1"
  fetch "$(cat "$path_file")" "${path_file%.path}.txt" is_microdescs \
    || echo "   batch $(basename "$path_file" .path) failed at every authority" >&2
}
export -f fetch fetch_batch is_microdescs
export AUTHORITY_LIST="${AUTHORITIES[*]}"
# shellcheck disable=SC2016 # expanded by the inner bash
find "$WORK/md" -name '*.path' -print0 | sort -z \
  | xargs -0 -P "$PARALLEL" -I{} bash -c 'read -ra AUTHORITIES <<< "$AUTHORITY_LIST"; fetch_batch "$1"' _ {}
: > "$WORK/microdescriptors.txt"
for f in "$WORK"/md/*.txt; do
  if [ -e "$f" ]; then cat "$f" >> "$WORK/microdescriptors.txt"; fi
done
MICRO_COUNT=$(grep -c '^ntor-onion-key ' "$WORK/microdescriptors.txt" || true)
echo "   microdescriptors: $MICRO_COUNT for $RELAY_COUNT relays ($BATCHES requests)"
if ((MICRO_COUNT * 100 < RELAY_COUNT * MIN_MICRODESC_PERCENT)); then
  echo "only $MICRO_COUNT microdescriptors for $RELAY_COUNT relays (need $MIN_MICRODESC_PERCENT%)" >&2
  exit 1
fi

for name in consensus certs microdescriptors; do
  mv "$WORK/$name.txt" "$OUTPUT_DIR/$name.txt"
  brotli -q 11 -f -o "$OUTPUT_DIR/$name.txt.br" "$OUTPUT_DIR/$name.txt"
  echo "   $name.txt.br: $(wc -c < "$OUTPUT_DIR/$name.txt.br") bytes"
done
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUTPUT_DIR/fetched_at.txt"
echo "Done: $OUTPUT_DIR"
