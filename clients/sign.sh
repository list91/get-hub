#!/usr/bin/env bash
# Minimal bridge-mta signed client (bash + openssl + python3 for urlencode).
#
#   BRIDGE_URL="https://<worker>" BRIDGE_SECRET="bridge-..." \
#     ./sign.sh do t=https://api.github.com/zen
set -euo pipefail

BASE="${BRIDGE_URL%/}"
SECRET="${BRIDGE_SECRET:?set BRIDGE_SECRET}"
UA="${BRIDGE_UA:-bridge-client/1.0}"

op="${1:?usage: sign.sh <op> [k=v ...]}"; shift || true
ts=$(date +%s)                                    # ±3600s window
nonce=$(openssl rand -base64 12 | tr '+/' '-_' | tr -d '=')

pairs=("op=$op" "ts=$ts" "nonce=$nonce")
for kv in "$@"; do
  k="${kv%%=*}"; v="${kv#*=}"
  v_enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$v")
  pairs+=("$k=$v_enc")
done

qs=$(printf '%s\n' "${pairs[@]}" | sort | paste -sd '&' -)
canonical=$(printf 'v1\n/\n%s' "$qs")
sig=$(printf '%s' "$canonical" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -s -A "$UA" "$BASE/?$qs&sig=$sig"
echo
