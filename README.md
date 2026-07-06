# bridge-mta

**One HTTPS URL that gives a fetch-only LLM chat access to your private APIs.**

A browser LLM chat can often do exactly one thing to the outside world: open a URL
(a built-in "web fetch"). No tool-calling, no MCP, no plugins. `bridge-mta` turns
that single capability into a controlled gateway to your private tools and data.

The bridge is a tiny dispatcher. The client GETs one URL, the bridge routes it by
an `op=` parameter, and the load-bearing op — `do` — is a signed outgoing HTTPS
proxy with a host allowlist that injects server-side credentials the client never
sees. Keys are short-lived (~1h) and rotate through a 2-button Telegram bot.

> **Design principle:** build for the weakest client — a chat that can only open a
> link — and it works everywhere. That is why everything is GET-only and URL-only.

There are **three deployments** (pick one; see §3):
- **Universal Linux server** (`server-node/`) — **start here.** A zero-dependency
  Node 18+ port of the full mechanism (HMAC, `op=do`, host allowlist, GitHub JWT).
  Runs on any Linux with Node, no Cloudflare account, no PHP host. Keys are minted
  by a CLI (`node server.mjs issue`) instead of the Telegram bot, so an agent can
  bootstrap it blind. **→ [`server-node/README.md`](server-node/README.md)**
- **Cloudflare Worker** (`src/index.js`) — self-sufficient: HMAC auth, KV key
  rotation, on-edge GitHub App JWT minting. Downside: `*.workers.dev` is blocked
  inside some LLM sandboxes.
- **PHP port** (`php/bridge.php`) — a weaker token-mode variant for any PHP host on
  a normal domain. Downside: static access key, no HMAC, no JWT, no bot. This is
  the variant proven end-to-end from a locked-down web-fetch-only agent.

---

## Table of contents
1. [Overview — what & why](#1-overview)
2. [Threat model & security posture](#2-threat-model)
3. [Which deployment to pick](#3-which-deployment)
4. [Prerequisites](#4-prerequisites)
5. [Secrets & config](#5-secrets--config)
6. [GitHub App walkthrough (optional plug)](#6-github-app)
7. [Deploy A — Cloudflare Worker](#7-deploy-a-worker)
8. [Telegram bot wiring (setWebhook)](#8-telegram-wiring)
9. [Deploy B — PHP port](#9-deploy-b-php)
10. [Activation & key lifecycle](#10-activation--lifecycle)
11. [Auth spec (canonical signing)](#11-auth-spec)
12. [`op=do` parameter reference](#12-op-do-reference)
13. [Extending the bridge](#13-extending)
14. [Agent usage prompt](#14-agent-prompt)
15. [Smoke test](#15-smoke-test)
16. [Troubleshooting](#16-troubleshooting) · [License](#license)

---

## 1. Overview

The bridge exposes an `OPS` registry keyed by `op=`:

| op | auth | purpose |
|----|------|---------|
| `ping` `info` `echo` `ops` | public | health / edge info / registry list |
| `secure_echo` | signed | proves your signature works |
| **`do`** | signed | **outgoing HTTPS proxy** — the actual mechanism |

`op=do` fetches a target URL on your behalf and returns the response. It enforces a
host allowlist (SSRF guard), https-only, `redirect: manual`, a 10s timeout, and a
100 KB response cap. When the target is `api.github.com` and the client did not send
its own `Authorization`, the Worker injects a GitHub **installation token** pulled
from KV — the client never sees it.

Empty KV = **"secure idle"**: signed ops return `401 no_secret_server` until you
press ⚡ in the Telegram bot. Public ops always work.

## 2. Threat model

Read this before deploying. The bridge hands a remote LLM real access.

- **Server-side credential injection.** On the Worker the GitHub token lives only in
  KV and never returns to the client. Keep it that way for any credential you add.
- **SSRF guard.** `op=do` only reaches hosts in `ALLOW_HOSTS`. Never widen this to a
  wildcard — that turns the bridge into an open proxy. Keep https-only and
  `redirect: manual`.
- **`key=` / `gh=` in the URL is a deliberate weakness.** The token-mode path (and
  the PHP port) put a live secret in the query string, so it leaks into browser
  history, server logs, and `Referer`, and has no anti-replay. It exists only so
  GET-only clients that cannot compute an HMAC can still authenticate. Mitigate with
  **short TTL** and the **💀 kill** button. Prefer the full HMAC path when the client
  can sign.
- **Blast radius.** Point any injected credential at a **throwaway / least-privilege**
  scope, not your real data. If you use the GitHub plug, give the App the minimum
  permissions and the fewest repos possible — a token that can write to all your
  repos in the hands of an LLM is a large risk.
- **Never commit secrets.** Real values go into Worker secrets / `php/config.php`
  (gitignored), never into tracked files.

## 3. Which deployment

| | Cloudflare Worker | PHP port |
|-|-------------------|----------|
| Auth | HMAC-SHA256 **or** `key=` | `key=` only |
| Key rotation | Telegram bot + KV, ~1h TTL | manual / per-request `gh=` |
| GitHub token | minted on-edge from App PEM | client passes `gh=` (or file fallback) |
| Reachable from LLM sandboxes | `*.workers.dev` sometimes **blocked** | yes, on a normal domain |
| Honest upstream status | no (returns raw status in body) | yes (`ok` = 2xx + reason) |

**Rule of thumb:** use the **Worker** for the full mechanism; add the **PHP port** on
a normal domain when your target LLM sandbox blocks `*.workers.dev`.

## 4. Prerequisites

**Worker:** a Cloudflare account; `npm i -g wrangler`; `wrangler login`.
A KV namespace (created in §7). A Telegram bot token from **@BotFather** and your
numeric Telegram id (message **@userinfobot**). Optionally a GitHub App (§6).

**PHP port:** any PHP 8.x host with `curl` (a normal HTTPS domain). No Cloudflare,
no bot, no KV.

## 5. Secrets & config

Copy `.env.example` and read the notes there. The Worker reads these as **secrets**
(via `wrangler secret put`), not from a file.

| name | where | required | how to get |
|------|-------|----------|-----------|
| `TG_TOKEN` | Worker secret | bot | @BotFather |
| `TG_WEBHOOK_SECRET` | Worker secret | bot | `openssl rand -hex 16` (you choose) |
| `TG_OWNER_IDS` | Worker secret | bot | @userinfobot (numeric ids) |
| `GITHUB_APP_ID` | Worker secret | GitHub plug | App settings |
| `GITHUB_INSTALL_ID` | Worker secret | GitHub plug | install URL |
| `GITHUB_APP_PEM` | Worker secret | GitHub plug | App private key, **PKCS#8** (§6) |
| `ALLOW_HOSTS` | Worker secret (optional) | no | you choose; defaults in code |
| `NONCES` KV id | `wrangler.toml` | yes | `wrangler kv namespace create NONCES` |
| `ACCESS_KEY` | `php/config.php` | PHP | you choose (random) |
| `GH_TOKEN` | `php/config.php` | PHP (optional) | usually passed per-request via `gh=` |

## 6. GitHub App

Skip this section entirely if you are not using the GitHub plug.

1. GitHub → Settings → Developer settings → **GitHub Apps → New GitHub App**.
2. Permissions: **least privilege**. For read-only repo contents, set *Repository
   permissions → Contents → Read-only*. Add write only if you truly need it.
3. Create, then **Install** it on your account/org and select the **fewest repos**
   possible (ideally a throwaway workspace repo).
4. Capture **App ID** (App general page) and **Installation ID** (the install URL is
   `github.com/settings/installations/<INSTALL_ID>`).
5. Generate a private key — GitHub gives you **PKCS#1** PEM. The Worker needs
   **PKCS#8**. Convert:
   ```bash
   openssl pkcs8 -topk8 -nocrypt -in app.private-key.pem -out app.pkcs8.pem
   ```
6. Store the three values (§7).

## 7. Deploy A — Worker

```bash
# from the repo root (the Worker lives at the top level: src/, wrangler.toml)
npm i -g wrangler        # if needed
wrangler login

# 1. Create the KV namespace and paste its id into wrangler.toml (NONCES binding).
wrangler kv namespace create NONCES
#   → copy the printed id → edit wrangler.toml → replace REPLACE_WITH_YOUR_KV_NAMESPACE_ID

# 2. Set the secrets (bot; add the GitHub three only if you use the plug).
wrangler secret put TG_TOKEN
wrangler secret put TG_WEBHOOK_SECRET
wrangler secret put TG_OWNER_IDS
wrangler secret put GITHUB_APP_ID          # optional
wrangler secret put GITHUB_INSTALL_ID      # optional
wrangler secret put GITHUB_APP_PEM < app.pkcs8.pem   # optional; paste PKCS#8

# 3. Deploy.
wrangler deploy
```

`wrangler deploy` prints your Worker URL (`https://<name>.<subdomain>.workers.dev`).
Verify: `curl -A c/1 "https://<worker>/?op=ping"` → `{"ok":true,"pong":true,...}`.

## 8. Telegram wiring

Without this step the bot receives nothing and ⚡/💀 do nothing.

Pick the same `TG_WEBHOOK_SECRET` you set in §7 and register the webhook — the bridge
checks **both** the URL path and the `X-Telegram-Bot-Api-Secret-Token` header, so
`secret_token` is mandatory:

```bash
curl "https://api.telegram.org/bot<TG_TOKEN>/setWebhook" \
  --data-urlencode "url=https://<worker>/tg/<TG_WEBHOOK_SECRET>" \
  --data-urlencode "secret_token=<TG_WEBHOOK_SECRET>"
```

Confirm: `curl "https://api.telegram.org/bot<TG_TOKEN>/getWebhookInfo"` — `url` set,
`pending_update_count` 0. Then open the bot, send `/start`, and you get the ⚡/💀
keyboard. (One bot = webhook **or** polling, never both.)

## 9. Deploy B — PHP port

```bash
cd php
cp config.example.php config.php     # set ACCESS_KEY to a random value
# upload bridge.php + config.php to your PHP host, e.g. https://example.com/bridge.php
```

- Auth: clients pass `?key=<ACCESS_KEY>`.
- GitHub token: pass a fresh one per request as `&gh=ghs_...` (installation tokens
  live ~1h), or set `GH_TOKEN` in `config.php` as a fallback.
- Add `&format=raw` when the caller is an Exa-backed `web_fetch` — it returns empty
  for `application/json`, so the bridge sends `text/plain` instead.
- No JWT minting here: the token is not auto-refreshed.

## 10. Activation & lifecycle

The Worker ships **asleep**: with empty KV, signed ops return `401 no_secret_server`.

- **⚡ Issue keys** (Telegram) — mints a fresh Bridge HMAC + a fresh GitHub token,
  revokes the previous GitHub token, writes both to KV with ~1h TTL. Idempotent:
  press it again for fresh keys. It replies with one copy-paste block.
- **💀 Kill keys** — revokes and deletes both immediately; the bridge goes back to
  sleep.

Three key **types** are easy to confuse — keep them straight:
- **Bridge HMAC** (`bridge-...`) — signs Worker requests (or used as `key=`).
- **PHP ACCESS_KEY** (your `config.php` value) — the PHP port's `key=`.
- **GitHub token** (`ghs_...`) — injected upstream; never used as `key=`.

**Non-Telegram bootstrap (for automation / agents that cannot press a button):** you
can populate the HMAC secret directly and activate the signed path without the bot:
```bash
wrangler kv key put --binding=NONCES hmac:current "bridge-$(openssl rand -hex 24)" --ttl 3600
```
(The GitHub plug still needs the bot's ⚡ or a separate token; this only unlocks
HMAC-signed `op=do`.)

## 11. Auth spec

Signed requests carry `ts`, `nonce`, `sig` plus the op's params. The signature is
HMAC-SHA256 (hex) over a canonical string:

```
canonical = "v1" + "\n" + path + "\n" + sorted_urlencoded_params_without_sig
```

- `path` is always `/`.
- Every param **except `sig`** is `encodeURIComponent`'d on key and value, sorted by
  key, joined with `&`.
- `ts` — unix seconds; must be within **±3600 s** of now (1-hour window).
- `nonce` — random, 8–128 chars; single-use, remembered in KV for anti-replay.
- Compare is constant-time.

> This supersedes the old `BRIDGE_API.md`, which listed a 60 s window and an
> `env HMAC_SECRET`. The shipped code uses a **3600 s** window and a **KV-only**
> secret. See `docs/API.md` and `clients/` for working signers.

**Degraded mode:** a GET-only client may instead pass `key=<current Bridge HMAC>`
directly (no `ts`/`nonce`/`sig`). Read §2 first — this leaks the key into the URL.

## 12. `op=do` reference

`GET /?op=do&t=<target>&m=<method>&p=<payload>&c=<0|1>&h=<headers>` + auth.

| param | meaning |
|-------|---------|
| `t` | target URL, **`encodeURIComponent`'d**. A raw `#` becomes a fragment and drops your `sig` → always 401. |
| `m` | HTTP method (default GET). |
| `p` | request body, base64url. |
| `c` | `1` = `p` is `deflate-raw`-compressed (native). |
| `h` | extra headers, base64url of a JSON object. |
| `gh` | (PHP only) GitHub token to inject. |

Guards: allowlist (`ALLOW_HOSTS`), https-only, `redirect: manual`, 10 s timeout,
**100 KB response cap** (large bodies are truncated — use small `per_page` and
paginate; a big body is *not* an error). On `api.github.com` with no client
`Authorization`, the Worker injects the KV GitHub token.

## 13. Extending

**Add an op** — extend the `OPS` registry in `src/index.js`:
```js
const OPS = {
  // ...
  async my_op(params, env, request) {
    return ok({ hello: params.name || "world" });
  },
};
// make it public (no signature) by adding to PUBLIC_OPS:
const PUBLIC_OPS = new Set(["ping", "info", "echo", "ops", "my_op"]);
```
Then `wrangler deploy`.

**Point at your own API** — set `ALLOW_HOSTS` (secret/env) to your hostnames. This is
the main knob for reuse. GitHub is just the first plug; per-host credential injection
for other backends is on the roadmap (see `docs/PROPOSALS.md`).

## 14. Agent prompt

`docs/AGENT_PROMPT.md` is a ready-to-paste English prompt for a weak, fetch-only LLM:
it hard-codes anti-flailing rules (don't probe random endpoints, a big body isn't
empty, stop on `token_expired`), a banned-endpoint list, and the `format=raw` note.
Weak models burn their ~1h token by flailing without it.

## 15. Smoke test

A blind check that a deploy works — full expected JSON in `docs/SMOKE_TEST.md`:

```bash
B="https://<worker>"; UA="-A smoke/1"
curl $UA "$B/?op=ping"                 # {"ok":true,"pong":true,...}
curl $UA "$B/?op=info"                 # colo / country / v:"0.3.0"
curl $UA "$B/?op=do&t=x"               # 401 no_sig  (do is signed)
# signed do → api.github.com/zen expecting 200, host-not-allowed → 403, bad-sig → 401
```
Use a signer from `clients/` for the signed cases.

## 16. Troubleshooting

| error (HTTP) | cause → fix |
|--------------|-------------|
| `no_sig` (401) | signed op without `sig` → sign it, or use `key=`. |
| `no_ts` / `bad_ts` (401) | missing/non-numeric `ts` → send unix seconds. |
| `ts_expired` (401) | clock off by >1h → fix system time; resend fresh `ts`+`nonce`. |
| `bad_nonce` (401) | nonce length not 8–128 → use a random 16-char nonce. |
| `bad_sig` (401) | canonical mismatch → check §11; is `t` `encodeURIComponent`'d? |
| `replay` (401) | nonce reused → new nonce per request. |
| `no_secret_server` (401) | KV empty (asleep) → press ⚡ or §10 bootstrap. |
| `host_not_allowed` (403) | target not in `ALLOW_HOSTS` → add it. |
| `bad_target` / `only_https` (400) | `t` not a valid https URL / not encoded. |
| `bad_key` (PHP 401) | wrong `ACCESS_KEY`. |
| `token_expired` (PHP) | GitHub token dead → supply fresh `gh=`. |
| bot silent after deploy | `setWebhook` not run or wrong `secret_token` (§8). |
| ⚡ 500 / "GitHub не выдан" | GitHub App misconfig / PEM not PKCS#8 (§6). |

## License

MIT — see [LICENSE](LICENSE). Not affiliated with Cloudflare, GitHub, or Telegram.
**Never commit real secrets.**
