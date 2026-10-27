#!/bin/sh
# Probe a public issuer with GET. Other methods on the discovery documents are rejected.
# Usage: deploy/oauth/check-discovery.sh https://auth.example.com
set -eu

issuer=${1:-}
case "$issuer" in
  https://*) ;;
  *) echo "usage: check-discovery.sh https://issuer.example" >&2; exit 2 ;;
esac
issuer=${issuer%/}

tmp=${TMPDIR:-/tmp}/new-api-oauth-discovery.$$
trap 'rm -f "$tmp"' EXIT

fetch() {
  url=$1
  expected=$2
  code=$(curl -sS --max-time 20 -o "$tmp" -w '%{http_code}' "$url")
  if [ "$code" != "$expected" ]; then
    echo "GET $url -> $code, want $expected" >&2
    exit 1
  fi
  echo "GET $url -> $code"
}

fetch "$issuer/.well-known/openid-configuration" 200
python3 - "$tmp" "$issuer/" <<'PY'
import json, sys
document = json.load(open(sys.argv[1]))
issuer = sys.argv[2]
for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
    value = document.get(key, "")
    if key == "issuer" and value != issuer:
        raise SystemExit(f"{key}={value!r}")
    if key != "issuer" and not str(value).startswith(issuer):
        raise SystemExit(f"{key}={value!r}")
print("issuer", document["issuer"])
PY

fetch "$issuer/.well-known/oauth-authorization-server" 200
fetch "$issuer/.well-known/jwks.json" 200
fetch "$issuer/oauth2/not-whitelisted" 404
python3 - "$tmp" <<'PY'
import json, sys
document = json.load(open(sys.argv[1]))
if document.get("error") != "not_found":
    raise SystemExit("whitelist miss did not return not_found")
print("whitelist miss not_found")
PY
