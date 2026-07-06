#!/usr/bin/env python3
"""Minimal bridge-mta signed client.

Usage:
    export BRIDGE_URL="https://<worker>"
    export BRIDGE_SECRET="bridge-..."      # current Bridge HMAC (from the bot's ⚡)
    python sign.py secure_echo note=hi
    python sign.py do t=https://api.github.com/zen
"""
import hashlib, hmac, json, os, secrets, sys, time
import urllib.parse, urllib.request

BASE = os.environ["BRIDGE_URL"].rstrip("/")
SECRET = os.environ["BRIDGE_SECRET"].encode()
UA = os.environ.get("BRIDGE_UA", "bridge-client/1.0")


def signed_url(op, **kw):
    path = "/"
    params = {
        "op": op,
        **{k: str(v) for k, v in kw.items()},
        "ts": str(int(time.time())),          # ±3600s window
        "nonce": secrets.token_urlsafe(12),   # single-use
    }
    qs = "&".join(sorted(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in params.items()
    ))
    canonical = f"v1\n{path}\n{qs}"
    params["sig"] = hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest()
    return f"{BASE}{path}?" + urllib.parse.urlencode(params)


def call(op, **kw):
    req = urllib.request.Request(signed_url(op, **kw), headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: sign.py <op> [k=v ...]")
    op = sys.argv[1]
    kw = dict(a.split("=", 1) for a in sys.argv[2:])
    print(json.dumps(call(op, **kw), ensure_ascii=False))
