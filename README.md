# get-hub — signed, fetch-only HTTPS LLM-chat gateway

**One LAN HTTPS URL that gives a fetch-only LLM chat controlled, signed access to your
private APIs — running on any box with Node.js. Zero dependencies.**

get-hub is a small, self-contained **GET/HEAD-only** gateway. A client (typically an
LLM that can only issue HTTP GETs) calls `?op=<name>&…`; the kernel authenticates the
request with an HMAC **door-key**, dispatches to the first matching **module**, and the
module injects a server-side credential the client never sees before forwarding the
call through the kernel's single outbound-HTTPS proxy.

The security-bearing core is `kernel.mjs`. Behaviour is composed from auto-loaded
`modules/*.mjs` files. `server.mjs` is BOTH the HTTP server and the operator CLI.

For the full contract and threat model, see [`SPEC.md`](SPEC.md).

---

## What it is

- **Fetch-only.** Only `GET` and `HEAD` reach the kernel; every other method is
  `405 method_not_allowed`. A plain web-fetch chat is a first-class client.
- **Signed.** Protected ops require the **door-key**: either a full HMAC-SHA256
  signature (`sig`/`ts`/`nonce`) or a degraded `key=<door-key>` form for clients that
  cannot compute an HMAC.
- **Zero dependency.** Node ≥ 18 built-ins only (`node:http`, `node:crypto`,
  `node:https`, `node:dns`, `node:child_process`, …). No `npm install`.
- **Kernel-centred security.** Modules carry ZERO per-service policy. Every clamp
  — auth, SSRF/proxy guards, exec RCE guards, secret scrubbing — lives in the kernel,
  in three generic primitives (`core.proxy`, `core.exec`, `core.store`). A module only:
  `match` → inject its env secret → call a `core.*` primitive.
- **ASLEEP / ACTIVE.** With no door-key minted the bridge is **ASLEEP**: public ops
  answer, protected ops are rejected. `node server.mjs issue` mints a key → **ACTIVE**.

---

## Requirements

- A host with **Node.js ≥ 18** (`node --version`). Nothing else — zero npm deps.
- Outbound HTTPS from that host to the APIs you want to reach (the proxy allowlist).
- No secret is required to prove the mechanism works. GitHub / Telegram credentials are
  **optional** add-ons; the bridge boots and serves public + `fetch`/`hash`/`secure_echo`
  ops with no credential at all.

---

## Quickstart

```bash
git clone <repo-url>
cd get-hub    # the repo root is the product — self-contained

cp .env.example .env
chmod 600 .env                 # secrets live ONLY here — keep it out of git (I5)
# edit .env: set BIND to your LAN IP, PORT (default 8787), ALLOW_HOSTS to the hosts you
# expose, and (optionally) GITHUB_* / TELEGRAM_TOKEN.

node server.mjs issue          # mint the door-key — printed ONCE, copy it now
                               # (server.mjs loads ./.env itself — no `source .env` needed)
node server.mjs                # start the server (prints the ASLEEP/ACTIVE banner)
```

Both `server.mjs issue` and `server.mjs` (and `kill`/`show`) load `./.env` from the working
directory themselves, so the CLI picks up `GITHUB_TOKEN` etc. with no `set -a; . ./.env` dance.
A real environment variable always wins over `.env`.

The startup banner (PORT here is whatever you set — default 8787):

```
get-hub get-hub-1.0.0 on http://127.0.0.1:8787
  allow_hosts=api.github.com,api.telegram.org  store=./get-hub-store.json
  modules=echo,fetch,github,hash,info,ops,ping,run,secure_echo,telegram,temp
  exec=disabled
  state: ACTIVE — door-key present.
```

Smoke-test the public ops (no key needed) and then a protected op (`PORT` = your configured port):

```bash
PORT=8787
curl "http://127.0.0.1:$PORT/?op=ping"          # {"ok":true,"pong":true,...}
curl "http://127.0.0.1:$PORT/?op=info"          # version + allow_hosts + op catalog
curl "http://127.0.0.1:$PORT/?op=ops"           # op-name index

# protected op WITHOUT a key -> rejected:
curl "http://127.0.0.1:$PORT/?op=hash&s=hi"     # {"ok":false,"error":"no_sig"}

# protected op WITH the degraded key= form (paste the door-key from `issue`):
KEY='bridge-...'
curl "http://127.0.0.1:$PORT/?op=hash&s=hi&key=$KEY"
```

For a persistent LAN deploy on a Raspberry Pi, see [`DEPLOY.md`](DEPLOY.md).

---

## The door-key + signed request

The **door-key** authorizes *calling* the bridge (the data plane). It is minted by the
operator CLI (`node server.mjs issue`) and stored — hashed at rest as an opaque value —
in the JSON store. It is shown **once**, on issue. It NEVER rotates itself: only the
operator (local CLI, or a whitelisted operator channel) may rotate it (I12).

A protected op accepts the key in one of two forms.

### (a) Degraded `key=` form — for clients that cannot sign

Pass the raw door-key as `key=<door-key>`:

```bash
curl "http://127.0.0.1:8787/?op=secure_echo&key=$KEY&hello=world"
# {"ok":true,"authenticated":true,"params":{"hello":"world"},...}
```

The kernel compares `key` to the stored door-key in constant time. This is the form a
plain web-fetch LLM uses. `key` is stripped from params before the module runs, so it is
never reflected back.

### (b) Full HMAC signature — for clients that can compute an HMAC

Every signed request carries three extra params:

| param   | meaning                                                            |
|---------|-------------------------------------------------------------------|
| `ts`    | unix seconds; must be within `TS_WINDOW_SEC` (default ±120 s).     |
| `nonce` | single-use string, 8–128 chars; replay of a seen nonce is refused.|
| `sig`   | hex HMAC-SHA256 of the canonical string (below).                  |

**Canonical string (verified against `kernel.mjs` `canonical()` and `test/discovery.test.mjs`):**

```
canonical = "v1" + "\n" + <path> + "\n" + <params>

<path>    = the request path, e.g. "/"
<params>  = every query param EXCEPT `sig`, each as encodeURIComponent(key)
            "=" encodeURIComponent(value), the resulting "k=v" strings sorted
            lexicographically, joined with "&".
sig       = hex( HMAC_SHA256( door-key, canonical ) )
```

Notes derived from the code:

- Only `sig` is excluded from the canonical string. `ts`, `nonce`, `op`, and every other
  param (including `key` if present) ARE part of what is signed.
- Sorting is by the already-encoded `k=v` pair (`Array.prototype.sort` default order).
- The signature is a lowercase hex digest.

Reference JS that reproduces the server's form exactly (`node:crypto`, zero deps):

```js
import crypto from "node:crypto";
function sign(doorKey, path, params) {                 // params: {op, ts, nonce, ...}
  const enc = (s) => encodeURIComponent(String(s));
  const pairs = Object.entries(params)
    .filter(([k]) => k !== "sig")
    .map(([k, v]) => `${enc(k)}=${enc(v)}`)
    .sort();
  const canonical = `v1\n${path}\n${pairs.join("&")}`;
  return crypto.createHmac("sha256", doorKey).update(canonical).digest("hex");
}
// then request:  `${path}?` + new URLSearchParams({ ...params, sig }).toString()
```

`test/discovery.test.mjs` (`signedUrl`) is the canonical worked example — it calls the
kernel's own `canonical()` + `hmacHex()` and appends `sig`.

**Auth error codes** (HTTP 401 body `error`): `no_sig` (no `sig` and no `key`),
`no_ts`, `bad_ts`, `ts_expired`, `bad_nonce`, `no_secret_server` (bridge is ASLEEP),
`bad_sig`, `bad_key`, `replay`.

---

## Operator CLI

`server.mjs` is the control plane — a process on the host IS the operator.

| Command                          | Effect                                                                                           |
|----------------------------------|--------------------------------------------------------------------------------------------------|
| `node server.mjs`                | Start the HTTP server. Prints the ASLEEP/ACTIVE banner.                                           |
| `node server.mjs issue [name…]`  | Mint a fresh door-key (rotates/supersedes the old one). Extra `name` args also rotate those modules' secrets (e.g. `issue github`). Prints the door-key **ONCE**. |
| `node server.mjs kill`           | Wipe the door-key + every known module secret (`<name>:token`) from the store. Bridge → ASLEEP.  |
| `node server.mjs show`           | Print state (door-key present?, per-module surfaces + whether a secret is stored). NEVER prints secret values. |

`issue github` mints a GitHub installation token (App flow) or stores the static
`GITHUB_TOKEN` (see the `github` module). Re-running `issue` is idempotent-by-rotation:
the previous door-key stops working.

---

## Module catalog

Every `modules/*.mjs` file (except `_`-prefixed helpers and `*.test.mjs`) is auto-loaded
in **sorted filename order**; dispatch is first-`match`-wins. "Public" ops skip auth;
"Protected" ops require the door-key.

| Op / module    | Access    | What it does                                                                                                   |
|----------------|-----------|---------------------------------------------------------------------------------------------------------------|
| `ping`         | Public    | Liveness probe. `?op=ping` → `{ok,pong,time,t}` (echoes optional `t` back). Answers even while ASLEEP.         |
| `echo`         | Public    | Reflector. `?op=echo&msg=<text>` → `{ok,msg,len}`. `sig`/`key` are stripped before it runs.                    |
| `info`         | Public    | Discovery card. `?op=info` → version, `allow_hosts`, live op catalog, GitHub stance, and `public_ops` list.    |
| `ops`          | Public    | Op-name index. `?op=ops` → `{count, ops:[…], detail:[{op,public,background}]}`.                                |
| `hash`         | Protected | Pure compute. `?op=hash&s=<text>` → `{ok,alg:"sha256",hex,len}`. 1 MB input cap. No core capability.           |
| `secure_echo`  | Protected | Auth-gate proof. `?op=secure_echo&…` → reflects params post-auth; proves `sig`/`key`/`secret`/`token`/`password` are never echoed. |
| `fetch`        | Protected | Bare HTTPS proxy demo. `?op=fetch&t=https://<allowlisted-host>/path` → GET via `core.proxy`; returns the response envelope. No injected secret. |
| `github`       | Protected | GitHub proxy + secret injection. `?op=github&t=https://api.github.com/…` → injects `Authorization: Bearer <stored token>` and forwards via `core.proxy`. Client never sends a token. Has a `rotate` hook (mints App installation token, or stores static `GITHUB_TOKEN`). Only matches when the `t=` host is `api.github.com`. |
| `run`          | Protected | Exec-class. `?op=run&name=<vetted>` → runs `EXEC_DIR/<name>` via `core.exec` with EMPTY args. Name must match `^[a-z0-9_-]+$`. Returns `{exit_code,stdout,truncated}`. **Off** unless `EXEC_ENABLED=1`. |
| `temp`         | Protected | Exec-class. `?op=temp` → runs the fixed `scripts/temp.sh` (CPU temp in °C) via `core.exec`. No client input reaches the shell. **Off** unless `EXEC_ENABLED=1`. |
| `telegram`     | Background| No data plane (no `match`/`handle`). A `start()` long-poll daemon: watches Telegram `getUpdates`, and on an operator `/issue` gesture calls `core.control.rotate(['door','github'])`. **Optional** — off (no-op) when `TELEGRAM_TOKEN` is empty. The daemon is fire-and-forget (`boot()` does not await it), so a present token never blocks the HTTP listener. Operator identity enforced by the kernel. |

The `github` module targets `api.github.com`; the `telegram` daemon polls
`api.telegram.org`. Both hosts must be in `ALLOW_HOSTS` for those modules to work (they
are in the default allowlist).

Non-module files in `modules/`: `_template.mjs`, `CONTRACT.md`, `_test_exec_modules.mjs`
(helpers/docs, skipped by the loader).

---

## Config / env

Copy `.env.example` → `.env`, `chmod 600`. `server.mjs` loads this `.env` itself (for the
server AND the operator CLI) via a tolerant parser: full-line `#` comments and blank lines are
ignored, an unquoted trailing ` # comment` is stripped, a value wrapped in matching quotes is
kept literal, and a real environment variable always wins. Write values **bare** (`KEY=value`);
multi-word values like `ALLOW_HOSTS` need no quotes. All values below are read by `kernel.mjs`
`loadConfig` (globals) or by a module's `<NAME>_*` namespace. Per-module secrets are
exposed to a module ONLY as its frozen `<NAME>_` view (e.g. `github` sees
`GITHUB_TOKEN` as `env.TOKEN`); modules never read `process.env`.

| Var                 | Required?          | Default (code)         | Purpose                                                                 |
|---------------------|--------------------|------------------------|-------------------------------------------------------------------------|
| `PORT`              | no                 | `8787`                 | TCP port. If co-hosting multiple gateways on one host, give each a **unique** port (a `bridge-mta`-style service may already own 8787). |
| `BIND`              | no (set for LAN)   | `127.0.0.1`            | Bind address. Set to the Pi's **LAN IP**, never `0.0.0.0`.             |
| `STORE_PATH`        | no                 | `./get-hub-store.json` | JSON store (door-key + module secrets), written `0600`.               |
| `ALLOW_HOSTS`       | no                 | `api.github.com api.telegram.org` | Proxy host allowlist (space/comma sep). `core.proxy` refuses everything else. |
| `KEY_TTL_SEC`       | no                 | `3600`                 | Door-key / minted-secret TTL on issue.                                 |
| `TS_WINDOW_SEC`     | no                 | `120`                  | Signed-`ts` clock skew / replay window (± seconds). **Tight by default** (was 3600) — security-relevant under public exposure. |
| `NONCE_TTL_SEC`     | no                 | `TS_WINDOW_SEC` (120)  | How long a used nonce is remembered (in-memory).                       |
| `NONCE_MAX`         | no                 | `100000`               | Hard cap on the in-memory nonce set (bounded ring) — bounds authed-flood memory. |
| `ALLOW_KEY_PARAM`   | no                 | `true`                 | Allow the degraded `?key=` form. `0`/`false` refuses it (`key_param_disabled`) so the raw secret never rides in a URL. |
| `DO_MAX_RESP`       | no                 | `100000`               | Max proxied response bytes (then truncated).                          |
| `PROXY_TIMEOUT_MS`  | no                 | `10000`                | Per-hop outbound HTTPS timeout.                                        |
| `PROXY_MAX_REDIRECT`| no                 | `3`                    | Max same-host redirects followed (cross-host never followed).        |
| `UA`                | no                 | `get-hub/1.0`          | Outbound `User-Agent`.                                                 |
| `OPERATOR_CHATS`    | no*                | (empty; alias `TELEGRAM_WHITELIST`) | Telegram chat-ids trusted as 1:1 operator DMs.           |
| `OPERATOR_SENDERS`  | no* (req. for groups) | (empty)             | Telegram sender (user) ids authorized to trigger `rotate`.            |
| `EXEC_ENABLED`      | no                 | `0` (off)              | `1`/`true` enables `core.exec`. Needed by `run`/`temp`.               |
| `EXEC_DIR`          | if exec on         | (empty)                | Directory of vetted scripts. Required for exec to work. Under systemd use an **absolute** path (e.g. `/home/<user>/get-hub/scripts`), never `./scripts`. |
| `EXEC_TIMEOUT_MS`   | no                 | `10000`                | Exec wall-clock timeout (then SIGKILL).                               |
| `EXEC_MAX_OUT`      | no                 | `65536`                | Max captured stdout bytes.                                            |
| `EXEC_MAX_ARGS`     | no                 | `16`                   | Max argv length (`run`/`temp` pass 0 args anyway).                   |
| `EXEC_MAX_ARG_LEN`  | no                 | `4096`                 | Max length of any single argv token.                                 |
| `HTTP_HEADERS_TIMEOUT_MS`  | no          | `8000`                 | Max time to receive all request headers (DoS bound).                 |
| `HTTP_REQUEST_TIMEOUT_MS`  | no          | `15000`                | Max time to receive the full request.                                |
| `HTTP_KEEPALIVE_TIMEOUT_MS`| no          | `5000`                 | Keep-alive idle timeout.                                             |
| `HTTP_MAX_CONNECTIONS`     | no          | `256`                  | Max simultaneous TCP connections.                                   |
| `HTTP_SOCKET_TIMEOUT_MS`   | no          | `20000`                | Per-socket inactivity timeout before destroy.                       |
| `HTTP_MAX_URL_LEN`         | no          | `2048`                 | Over-long request URL → `414` before it reaches the kernel.         |
| `GITHUB_TOKEN`      | optional           | (empty)                | Static GitHub token, injected as `Bearer`. Used if no App creds.     |
| `GITHUB_APP_ID`     | optional           | (empty)                | GitHub App id (App-JWT flow).                                        |
| `GITHUB_INSTALL_ID` | optional           | (empty)                | GitHub App installation id.                                          |
| `GITHUB_APP_PEM`    | optional           | (empty)                | App private key PEM, INLINE (module can't read files).              |
| `GITHUB_APP_PEM_FILE` | optional         | (empty)                | Path to PEM; kernel reads it at boot into `GITHUB_APP_PEM` (`*_FILE` convention). |
| `TELEGRAM_TOKEN`    | optional           | (empty)                | Bot token for the `telegram` daemon. Empty → daemon is a no-op.      |
| `TELEGRAM_WHITELIST`| optional (legacy)  | (empty)                | Legacy alias for `OPERATOR_CHATS`.                                   |

\* Operator identity vars are only needed if you use the Telegram operator trigger. Any
`<VAR>_FILE=/path` (with `<VAR>` unset) is expanded to the file contents by the kernel at
boot — a generic convention for large/multiline secrets, used above by `GITHUB_APP_PEM_FILE`.

See [`.env.example`](.env.example) for the full annotated list.

---

## Security notes

- **LAN-only bind.** Bind to a LAN IP (or `127.0.0.1`), never `0.0.0.0`. Put any public
  exposure behind a tunnel/reverse proxy — do not rebind to the world.
- **Public exposure.** Default posture is LAN/trusted. To go internet-facing, get-hub MUST sit
  behind a hardened HTTPS reverse proxy that enforces per-IP limits (the kernel can't) — see the
  **"Public exposure (internet-facing)"** section in [`DEPLOY.md`](DEPLOY.md).
- **`.env` is the only home for real secrets** — `chmod 600`, gitignored. Never commit a
  real token/key/PEM (I5). The store file (`get-hub-store.json`) is also written `0600`.
- **exec is OFF by default** (`EXEC_ENABLED=0`). Only enable it with a curated `EXEC_DIR`
  of vetted, argument-free scripts. `core.exec` path-locks the script under `EXEC_DIR`
  (realpath, no symlink/`..` escape), spawns `shell:false` with an arg array, and applies
  a timeout + output cap.
- **Proxy SSRF clamp.** `core.proxy` is the ONE outbound boundary: HTTPS-only, host
  allowlist, DNS pinned to a pre-vetted **public** IP (blocks private/loopback/link-local/
  metadata + IPv6 embedded-v4 tricks), rejects non-443 ports, and never follows a
  cross-host redirect (so an injected `Authorization` header can never leak off-host).
- **Secret scrubbing.** Logs and error bodies pass through a scrubber that redacts GitHub
  tokens, Telegram bot tokens, door-keys, `Bearer` headers, PEM blocks, and secrets in
  URLs (I9). Stack traces never reach a response body.
- **Modules are TRUSTED code** — first-party, operator-authored/reviewed, exactly like
  nginx modules or a server's own route handlers (SPEC §5.9). get-hub does NOT sandbox a
  hostile module; the "zero-vuln" guarantee is against the **external fetch-only
  attacker**, not against malicious code you dropped into `modules/`.

For the complete contract, invariants (I1–I12), and threat model, read
[`SPEC.md`](SPEC.md).
