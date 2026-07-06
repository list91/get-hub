# bridge-mta — universal Linux server (`server-node/`)

**One HTTPS URL that gives a fetch-only LLM chat controlled access to your private
APIs — running on any Linux box with Node.js. Zero dependencies.**

This is a self-contained port of the [bridge-mta](../README.md) mechanism. It needs
no Cloudflare account and no PHP host — only Node 18+. It replaces the Cloudflare
Worker's building blocks with local equivalents:

| Worker (Cloudflare)        | This server (any Linux)              |
|----------------------------|--------------------------------------|
| KV namespace               | a JSON file (`bridge-store.json`)     |
| Web Crypto (`subtle`)      | `node:crypto`                         |
| Worker fetch handler       | `node:http` server                    |
| Telegram ⚡/💀 buttons      | CLI `issue` / `kill` / `show`         |

The security mechanism is **identical**: an `op=` dispatcher, HMAC-SHA256 request
signing with a timestamp window + single-use nonce (anti-replay), and one
load-bearing op — `do` — a signed outgoing HTTPS proxy restricted to a **host
allowlist** that injects server-side credentials the client never sees.

---

## What you need

- A Linux host with **Node.js ≥ 18** (`node --version`). Nothing else.
- Outbound HTTPS from that host to the APIs you want to reach.
- No secrets are required to prove the mechanism works. GitHub token injection is an
  **optional** add-on (§6); everything else runs without any credential.

---

## 1. Get the code

Clone the repo and enter this directory:

```bash
git clone https://github.com/list91/bridge-mta.git
cd bridge-mta/server-node
```

(If you only have this folder, that is enough — it is self-contained.)

## 2. Configure

```bash
cp .env.example .env
```

Open `.env` and set **`ALLOW_HOSTS`** to the exact hostnames `op=do` may reach
(space-separated, in quotes). Everything else has safe defaults. Example:

```bash
ALLOW_HOSTS="api.github.com api.telegram.org"
```

Leave `GITHUB_APP_ID` / `GITHUB_INSTALL_ID` / `GITHUB_APP_PEM_PATH` **blank** unless
you want GitHub token injection (§6). The bridge runs fine without them.

## 3. Start the server

```bash
set -a; . ./.env; set +a      # load .env into the shell
node server.mjs
```

You should see:

```
bridge-mta node-0.1.0 on http://127.0.0.1:8787  allow=api.github.com,api.telegram.org  store=./bridge-store.json
state: ASLEEP — run `node server.mjs issue` to activate
```

It binds to **127.0.0.1** only. Nothing is exposed to the network yet — that is
deliberate (see §7 for public HTTPS). Leave it running; open a second shell for the
next steps.

## 4. Smoke-test the public ops (no key needed)

Three ops are public and need no signature — use them to confirm the server is up:

```bash
curl 'http://127.0.0.1:8787/?op=ping'
curl 'http://127.0.0.1:8787/?op=info'
curl 'http://127.0.0.1:8787/?op=ops'
```

Expected:

```json
{"ok":true,"pong":true,"time":...}
{"ok":true,"version":"node-0.1.0","time":...,"allow_hosts":["api.github.com","api.telegram.org"]}
{"ok":true,"commands":["do","echo","info","ops","ping","secure_echo"]}
```

The public ops are: **`ping`** (health), **`info`** (version + allowlist), **`ops`**
(list commands), **`echo`** (returns its `msg` param, e.g. `?op=echo&msg=hi` →
`{"ok":true,"msg":"hi"}`). `secure_echo` and `do` are protected (need a key).

A request to a protected op **without** a key must be rejected:

```bash
curl 'http://127.0.0.1:8787/?op=do&t=https://api.github.com/zen'
# {"ok":false,"error":"no_sig"}
```

## 5. Activate a key and use protected ops

Mint a Bridge HMAC secret. This is the CLI replacement for the Telegram ⚡ button
and is what makes blind bootstrap possible:

```bash
node server.mjs issue
```

Output (with no GitHub creds configured):

```json
{
  "hmac": "bridge-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "gh": "none (no App creds)"
}
```

Copy the `hmac` value. Re-running `issue` is idempotent-by-rotation: it **mints a
fresh key and supersedes the old one** (and revokes/re-mints the GitHub token if
configured), so the previous `hmac` stops working. `kill` wipes it entirely.

There are two ways to authenticate a request:

**(a) Degraded key-in-URL** — for clients that cannot compute an HMAC (a plain
web-fetch chat). Pass `key=<hmac>`:

```bash
HMAC='bridge-...'   # paste the value from `issue`
curl "http://127.0.0.1:8787/?op=secure_echo&key=$HMAC&hello=world"
# {"ok":true,"secured":true,"params":{...}}
```

**(b) Full HMAC signature** — for clients that can sign. Use the reference signers in
[`../clients/`](../clients/) (`sign.sh`, `sign.py`, `sign.mjs`):

```bash
BRIDGE_URL="http://127.0.0.1:8787" BRIDGE_SECRET="$HMAC" ../clients/sign.sh secure_echo hello=world
```

Now drive the load-bearing op — a signed proxy to an allowlisted host. `api.github.com`
is on the default allowlist and `/zen` needs no credential, so this proves the full
path end-to-end **without any secret**:

```bash
curl "http://127.0.0.1:8787/?op=do&key=$HMAC&t=https://api.github.com/zen"
# {"ok":true,"upstream_status":200,"error":null,"hint":null,"fetched_at":"...","body":"..."}
```

A host **not** on the allowlist must be refused:

```bash
curl "http://127.0.0.1:8787/?op=do&key=$HMAC&t=https://example.com/"
# {"ok":false,"error":"host_not_allowed","host":"example.com"}
```

Manage the key lifecycle:

```bash
node server.mjs show     # is a key present?
node server.mjs kill     # revoke + delete (server goes back to ASLEEP)
```

While the server is ASLEEP (no key), protected ops are refused: a **signed** request
returns `no_secret_server`, while a **degraded `key=`** request returns `no_sig` (the
`key=` branch only engages once a secret exists). Either way, nothing gets through
until you `issue`.

**That is the whole mechanism.** Everything above works with no credentials.

## 6. Built-in GitHub routing

The bridge ships as a **router with GitHub interaction built in.** You do not wire any
integration — you only hand it a **key (a GitHub token), and that key governs the
rights.** A read-only token → the bridge can only read; a read-write token → it can
also write. The token is injected server-side as `Authorization: Bearer` for any
`op=do` to `api.github.com` with no `Authorization` header — **the client never sees
it.** Two optional bridge-side clamps narrow it further (below).

Give the bridge a token — two ways:

**(A) Static token — simplest.** Put a Personal Access Token or (preferred)
fine-grained token in `.env`:

```bash
# .env:  GITHUB_TOKEN=github_pat_...
```

Re-source `.env` and restart (`set -a; . ./.env; set +a` then restart the process,
or `systemctl --user restart bridge-mta`) — no App, no JWT. Your minted HMAC key
persists in `bridge-store.json` across restarts, so you do **not** need to re-`issue`.
Use a **least-privilege** token
(fine-grained, read-only, scoped to just the repos you expose): whoever holds the
bridge key can act as this token, so do not hand it broad `admin`/`repo` scope in
production.

**(B) GitHub App — auto-rotating.** For self-minted short-lived (~1h) tokens, register
a GitHub App and convert its private key to PKCS#8:

```bash
openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pkcs8.pem
# .env:  GITHUB_APP_ID=...  GITHUB_INSTALL_ID=...  GITHUB_APP_PEM_PATH=./app.pkcs8.pem
```

Then `node server.mjs issue` also mints a fresh GitHub token (a minted App token
takes precedence over `GITHUB_TOKEN`).

Verify injection without leaking the secret — a private repo the token can read
returns `404` when fetched directly, but `200` through the bridge:

```bash
curl "http://127.0.0.1:8787/?op=do&key=$HMAC&t=https://api.github.com/repos/OWNER/PRIVATE_REPO"
# {"ok":true,"upstream_status":200,"body":"{... \"private\":true ...}"}   ← token stayed server-side
```

(URL-encode `t` if the target contains reserved characters like `&`, `#`, `?`, or a
query string — safe unencoded above because a plain repo path has none. The
`clients/` signers encode it for you.)

### Narrowing rights at the bridge (both optional)

Beyond the token's own scopes, two `.env` knobs let the bridge enforce tighter
limits — useful when the token is broader than you'd like:

```bash
# .env
GITHUB_MODE=readonly                       # refuse POST/PUT/PATCH/DELETE to GitHub
GITHUB_REPOS="list91/bridge-mta owner/x"   # only allow /repos/<these>; everything else 403
```

- `GITHUB_MODE` — default `readwrite` (rights follow the token). Set `readonly` and the
  bridge rejects every mutating method to `api.github.com` with `github_readonly`,
  even if the token could write.
- `GITHUB_REPOS` — default empty (any repo the token can reach). When set, an `op=do`
  to GitHub must target `/repos/<owner>/<repo>` for a listed repo, else
  `repo_not_allowed`.

The active policy is visible on the public `info` op, so a client/agent can discover
what it's allowed to do:

```bash
curl 'http://127.0.0.1:8787/?op=info'
# {"ok":true,...,"github":{"enabled":true,"mode":"readonly","repos":["list91/bridge-mta"]}}
```

Either GitHub path is the only step that needs a real secret — skip it to run
credential-free.

## 7. (Optional) Run persistently + expose publicly

For a systemd service and public-HTTPS options (Tailscale Funnel / Caddy / Cloudflare
Tunnel), see [`DEPLOY.md`](DEPLOY.md). Keep the server bound to `127.0.0.1` and put
the tunnel/reverse-proxy in front of it.

---

## Auth spec (for writing your own signer)

```
canonical = "v1\n" + path + "\n" + <params sorted, urlencoded, joined by '&', 'sig' excluded>
sig       = hex( HMAC_SHA256( secret, canonical ) )
```

Every signed request carries `ts` (unix seconds, ±3600 s window), `nonce`
(8–128 chars, single-use), and `sig`. See [`docs/API.md`](../docs/API.md) for the
full reference and [`../clients/`](../clients/) for working implementations.
