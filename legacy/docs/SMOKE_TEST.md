# Smoke test

> **This page covers the Cloudflare Worker.** Expected values below (`version:"0.3.0"`,
> `op=do` → `{ok,status,body}`) are Worker shapes. For the **universal Node server**
> (`server-node/`) the checks are the same but the fields differ
> (`version:"node-0.1.0"`, `op=do` → `{ok,upstream_status,error,hint,fetched_at,body}`)
> — see [`server-node/README.md`](../server-node/README.md) §4–§5 for its exact outputs.

Confirms a deploy works without asking a human. `B` = your Worker URL. Always send a
non-default User-Agent (Cloudflare Bot Fight Mode blocks empty/default UAs).

## Public ops (no key)

```bash
B="https://<worker>"; UA="-A smoke/1"

curl -s $UA "$B/?op=ping"
# {"ok":true,"pong":true,"time":<ms>}

curl -s $UA "$B/?op=info"
# {"ok":true,"version":"0.3.0","time":<ms>,"colo":"WAW","country":"..","asn":..,"tlsVersion":"TLSv1.3"}

curl -s $UA "$B/?op=ops"
# {"ok":true,"commands":["do","echo","info","ops","ping","secure_echo"]}

curl -s $UA "$B/?op=do&t=x"
# {"ok":false,"error":"no_sig"}          ← do is signed; unsigned is rejected
```

## Signed ops (needs an active HMAC in KV — press ⚡ or use README §10 bootstrap)

Use a signer from `../clients/` with `BRIDGE_SECRET` set to the current Bridge HMAC.

```bash
export BRIDGE_URL="$B" BRIDGE_SECRET="bridge-..."

python ../clients/sign.py secure_echo note=hi
# {"ok":true,"secured":true,"params":{"op":"secure_echo","note":"hi","ts":"..","nonce":".."}}

# do → api.github.com/zen (200 expected; body is the zen line)
python ../clients/sign.py do t=https://api.github.com/zen
# {"ok":true,"status":200,"body":"<a github zen quote>"}

# host not in allowlist → 403
python ../clients/sign.py do t=https://example.com/
# {"ok":false,"error":"host_not_allowed","host":"example.com"}
```

**Bad-sig check:** tamper with the secret (`BRIDGE_SECRET=wrong`) and rerun any signed
call → `{"ok":false,"error":"bad_sig"}` (HTTP 401).

## Pass criteria

ping/info/ops return `ok:true`; unsigned `do` → `no_sig`; signed `do`→zen → `200`;
example.com → `403`; wrong secret → `bad_sig`. All five ⇒ the mechanism is live.
