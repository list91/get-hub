"""Тест-клиент для bridge-mta v2 — HMAC + ts + nonce + anti-replay.

Запуск:
    BRIDGE_SECRET='bridge-mta-hmac-...' python3 test_client.py
"""
import hashlib
import hmac
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://bridge-mta.mta-bridge-list91.workers.dev"
SECRET = os.environ.get("BRIDGE_SECRET", "").encode()
if not SECRET:
    print("Set BRIDGE_SECRET env var", file=sys.stderr)
    sys.exit(1)

UA = "bridge-client/0.2 (test)"
SIG_VERSION = "v1"


def signed_url(op: str, ts_override=None, **kw) -> str:
    """v2: canonical = SIG_VERSION + \\n + path + \\n + sorted(URL-encoded k=v)."""
    path = "/"
    ts = str(ts_override if ts_override is not None else int(time.time()))
    nonce = secrets.token_urlsafe(12)
    params = {"op": op, **{k: str(v) for k, v in kw.items()},
              "ts": ts, "nonce": nonce}
    qs_parts = sorted(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in params.items()
    )
    canonical = f"{SIG_VERSION}\n{path}\n{'&'.join(qs_parts)}"
    sig = hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest()
    params["sig"] = sig
    return f"{BASE}{path}?" + urllib.parse.urlencode(params)


def get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return f"HTTP {resp.status}: {resp.read().decode()[:300]}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode()[:300]}"


def call(op: str, **kw) -> str:
    return get(signed_url(op, **kw))


print("=== 1. signed secure_echo (valid) ===")
print(call("secure_echo", note="hello v2"))
print()

print("=== 2. без подписи (no_sig) ===")
print(get(f"{BASE}/?op=secure_echo&note=hack"))
print()

print("=== 3. поддельная подпись (bad_sig) ===")
ts = str(int(time.time()))
nonce = secrets.token_urlsafe(12)
print(get(f"{BASE}/?op=secure_echo&note=hack&ts={ts}&nonce={nonce}&sig=" + "a"*64))
print()

print("=== 4. replay — тот же URL дважды ===")
url = signed_url("secure_echo", note="replay-test")
print("First call:", get(url))
print("Replay   :", get(url))   # ожидаем 'replay'
print()

print("=== 5. expired ts (час назад) ===")
print(get(signed_url("secure_echo", ts_override=int(time.time()) - 3600, note="from-past")))
print()

print("=== 6. signed unknown op ===")
print(call("does.not.exist", x="1"))
