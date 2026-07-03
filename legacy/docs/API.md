# bridge-mta API reference

> **Scope: the Cloudflare Worker (`src/index.js`).** The signing math (canonical,
> HMAC, ts/nonce) is identical for every deployment, but some **response shapes and
> vocabulary are Worker-specific** — `info` reports `version:"0.3.0"` plus Cloudflare
> `colo`/`country`/`asn` fields, `op=do` returns `{ok,status,body}`, and keys live in
> KV minted by the `⚡` Telegram button. The **universal Node server** (`server-node/`)
> reports `version:"node-0.1.0"` (no colo), returns `{ok,upstream_status,error,hint,fetched_at,body}`
> from `op=do`, and mints keys with the `issue` CLI. If you deployed the Node server,
> its own [`server-node/README.md`](../server-node/README.md) is authoritative.

Accurate as of `src/index.js` v0.3.0. Supersedes the deprecated root `BRIDGE_API.md`
(which listed a 60 s window and an `env HMAC_SECRET` that no longer exist).

All bridge requests are **GET**; all params live in the query string. The request
body is ignored. Non-GET → `405 method_not_allowed`.

## Ops

| op | auth | params | returns |
|----|------|--------|---------|
| (none) | public | — | health `{ok,pong,msg,v,time}` |
| `ping` | public | — | `{ok,pong,time}` |
| `info` | public | — | `{ok,version,time,colo,country,asn,tlsVersion}` |
| `echo` | public | `msg` | `{ok,msg}` |
| `ops` | public | — | `{ok,commands:[...]}` |
| `secure_echo` | signed | any + signature | `{ok,secured,params}` (sig omitted) |
| `do` | signed | see below | `{ok,status,body}` |

## Signing

```
canonical = "v1\n" + path + "\n" + sorted_urlencoded_params_without_sig
sig       = HMAC_SHA256_hex(secret, canonical)
```
- `path` = `/`. Params: every key/value `encodeURIComponent`'d, sorted by key,
  joined with `&`, excluding `sig`.
- `ts` unix seconds, within **±3600 s**. `nonce` 8–128 chars, single-use (KV
  anti-replay, TTL 3600 s). Constant-time compare.
- `secret` = current Bridge HMAC (KV `hmac:current`, rotated by ⚡). Empty KV →
  `401 no_secret_server`.

**Degraded auth:** `key=<current HMAC>` in the URL instead of `ts`/`nonce`/`sig`
(GET-only clients). Leaks the key into the URL — see README §2.

## `op=do`

`?op=do&t=<target>&m=<method>&p=<body b64url>&c=<0|1>&h=<headers b64url-json>` + auth.

- `t` must be `encodeURIComponent`'d (a raw `#` drops `sig` → 401).
- `c=1` → `p` is `deflate-raw`.
- Guards: `ALLOW_HOSTS` allowlist, https-only, `redirect: manual`, 10 s timeout,
  100 KB response cap.
- `api.github.com` + no client `Authorization` → Worker injects KV GitHub token.

## Errors

`no_sig` `no_ts` `bad_ts` `ts_expired` `bad_nonce` `bad_sig` `replay`
`no_secret_server` (401) · `unknown_op` `bad_target` `only_https` `bad_payload`
`bad_headers` (400) · `host_not_allowed` (403) · `method_not_allowed` (405) ·
`upstream_failed` (502) · `op_failed` (500). See README §16 for fixes.

## KV layout (binding `NONCES`)

| key | value | TTL |
|-----|-------|-----|
| `hmac:current` | active Bridge HMAC | 3600 s |
| `kc:gh` | `{token,expires_at}` GitHub installation token | ~1 h |
| `nonce:<n>` | `"1"` anti-replay marker | 3600 s |
