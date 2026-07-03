# Deploy get-hub on a Raspberry Pi (LAN, persistent) over ssh

Operations companion to [`README.md`](README.md). Do the README first to understand the
mechanism. This file is the concrete LAN deploy: clone to `~/get-hub`, configure `.env`,
mint the door-key, install a `--user` systemd service, and verify end-to-end.

Everything below runs **over ssh** to a Raspberry Pi on your LAN. Requirements: **Node ≥ 18**
on the Pi (`node --version`) and its LAN IP (call it `PI_IP`, e.g. `192.168.0.101`).

**Pick a `PORT` up front** (default `8787`). Examples below use `8788` so they don't collide
with a `bridge-mta`-style service that may already own `8787`. Set the same value in `.env`.
Every `curl` below uses `$PORT` — export it in your shell first:

```bash
PORT=8788        # your chosen port; must match PORT in .env
PI_IP=192.168.0.101
```

**Deploy flow at a glance:** clone/obtain → `cp .env.example .env` → edit `.env` (BIND, PORT,
secrets) → `chmod 600 .env` → `node server.mjs issue [github]` (mints the door-key; reads
`.env` itself) → install `get-hub.service` (`--user`, `enable-linger`, no `EnvironmentFile`) →
`systemctl --user enable --now get-hub` → verify with a public `ping`/`info` GET + a signed
protected GET.

---

## 1. Get the code onto the Pi

```bash
ssh pi@PI_IP
git clone <repo-url> ~/src/bridge-endpoint-project
cp -r ~/src/bridge-endpoint-project/worker/get-hub ~/get-hub   # stable path the unit expects
cd ~/get-hub
```

(If you already have just the `get-hub/` folder, copy it to `~/get-hub` — it is
self-contained. The systemd unit assumes `~/get-hub`; edit its paths if you use another.)

## 2. Configure `.env` (secrets live ONLY here)

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

Set at minimum (write values **bare** — `server.mjs` loads `.env` itself, so no quoting
gymnastics; multi-word values like `ALLOW_HOSTS` need no quotes):

```bash
BIND=192.168.0.101               # the Pi's LAN IP (your PI_IP) — NOT 0.0.0.0, NOT 127.0.0.1
PORT=8788                        # your chosen port — must match the PORT you export in the shell
ALLOW_HOSTS=api.github.com api.telegram.org   # hosts op=fetch/github may reach — UNQUOTED
```

Optional credentials (skip to run credential-free):

```bash
# GitHub token injection (static token — simplest):
GITHUB_TOKEN=github_pat_REPLACE_ME            # scope it read-only / to specific repos AT GitHub
# …or a GitHub App (auto-rotating ~1h token): GITHUB_APP_ID, GITHUB_INSTALL_ID, GITHUB_APP_PEM(_FILE)

# Telegram operator /issue trigger (optional — off when empty; never blocks startup):
TELEGRAM_TOKEN=123456:REPLACE_ME
OPERATOR_SENDERS=<your-telegram-user-id>      # required to authorize /issue from a group
```

> **`.env` values are bare.** `server.mjs` loads this file itself (for the server AND the
> operator CLI) with a tolerant parser: full-line `#` and blank lines ignored, an unquoted
> trailing ` # comment` stripped, and a value wrapped in matching quotes kept literal. There is
> no `EnvironmentFile` in the unit, so the old systemd quote/`#`-corruption class is gone — just
> write `ALLOW_HOSTS=api.github.com api.telegram.org` (no quotes). A real environment variable
> always wins over `.env`.

> **`EXEC_DIR` must be ABSOLUTE under systemd.** If you enable exec (`EXEC_ENABLED=1`), set
> `EXEC_DIR=/home/<user>/get-hub/scripts` — an absolute path. A relative `./scripts` resolves
> against the unit's WorkingDirectory and is fragile.

**The real GitHub PAT lives ONLY in this Pi `.env` (chmod 600).** It is never committed to
any repo and never appears in any doc.

## 3. Mint the door-key

```bash
cd ~/get-hub
node server.mjs issue          # reads ./.env automatically — GITHUB_TOKEN etc. are picked up
```

To also mint a GitHub installation/static token in the same step, run `node server.mjs issue
github`. No `set -a; . ./.env` first — the CLI loads `.env` itself.

Output ends with:

```
=== DOOR-KEY (shown ONCE — copy now …) ===
bridge-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Copy the `bridge-…` value now — it is shown **once**. It persists in
`get-hub-store.json`, so the service comes up **ACTIVE** after a restart. Re-run `issue` any
time to rotate; `node server.mjs kill` wipes everything (→ ASLEEP).

## 4. Install the `--user` systemd service (persistent, survives reboot)

The shipped `get-hub.service` has **no `EnvironmentFile`** — `server.mjs` loads `%h/get-hub/.env`
itself from its WorkingDirectory. Nothing to wire; just install and start:

```bash
mkdir -p ~/.config/systemd/user
cp ~/get-hub/get-hub.service ~/.config/systemd/user/

# systemctl --user over ssh needs XDG_RUNTIME_DIR pointed at your user runtime dir:
export XDG_RUNTIME_DIR=/run/user/$(id -u)

systemctl --user daemon-reload
systemctl --user enable --now get-hub
loginctl enable-linger "$USER"          # keep the --user service running after you log out
systemctl --user status get-hub
```

Verify the startup banner. `systemctl --user status` shows the last log lines from the unit's
in-memory buffer — the **primary** check on a Pi with no persistent journal:

```bash
systemctl --user status get-hub --no-pager -l
# ● get-hub.service — get-hub signed fetch-only HTTPS gateway
#    Active: active (running) …
#    …
#    get-hub get-hub-1.0.0 on http://192.168.0.101:8788
#      allow_hosts=api.github.com,api.telegram.org  store=./get-hub-store.json
#      modules=echo,fetch,github,hash,info,ops,ping,run,secure_echo,telegram,temp
#      state: ACTIVE — door-key present.
```

If journald persistence is enabled you can also read the full banner with
`journalctl --user -u get-hub -n 20 --no-pager` — but on this Pi that journal is empty, so
rely on `systemctl --user status` above.

If the banner shows `on http://127.0.0.1:8788` (or your host has no journal and status is
empty), `BIND` did not take — re-check `.env` (`BIND=<PI_IP>`, `PORT=<your port>`) and
`systemctl --user restart get-hub`.

## 5. Verify end-to-end (from another LAN machine)

**Public op — no key (proves it's up and LAN-reachable):**

```bash
curl "http://$PI_IP:$PORT/?op=ping"
# {"ok":true,"pong":true,"op":"ping","time":...}

curl "http://$PI_IP:$PORT/?op=info"
# {"ok":true,...,"allow_hosts":["api.github.com","api.telegram.org"],"public_ops":["echo","info","ops","ping"]}
```

**Protected op WITHOUT a key — must be refused:**

```bash
curl "http://$PI_IP:$PORT/?op=hash&s=hello"
# {"ok":false,"error":"no_sig"}
```

**Protected op WITH the degraded `key=` form (paste the door-key from step 3):**

```bash
KEY='bridge-...'
curl "http://$PI_IP:$PORT/?op=hash&s=hello&key=$KEY"
# {"ok":true,"alg":"sha256","hex":"2cf24dba...","len":5}
```

**Protected op WITH a full HMAC signature** (proves the signed path — pure Node, zero deps):

```bash
KEY='bridge-...'
KEY="$KEY" PI_IP="$PI_IP" PORT="$PORT" node -e '
  const crypto = require("node:crypto");
  const key = process.env.KEY, path = "/";
  const params = { op:"hash", s:"hello", ts:String(Math.floor(Date.now()/1000)),
                   nonce: crypto.randomBytes(8).toString("hex") };
  const enc = s => encodeURIComponent(String(s));
  const canonical = "v1\n"+path+"\n"+Object.entries(params)
      .map(([k,v])=>enc(k)+"="+enc(v)).sort().join("&");
  const sig = crypto.createHmac("sha256", key).update(canonical).digest("hex");
  const qs = new URLSearchParams({...params, sig}).toString();
  console.log("http://"+process.env.PI_IP+":"+process.env.PORT+path+"?"+qs);
'
# curl the printed URL -> {"ok":true,"alg":"sha256",...}
```

**GitHub injection (only if you set a GITHUB_TOKEN and ran `issue github`):**

```bash
curl "http://$PI_IP:$PORT/?op=github&key=$KEY&t=https://api.github.com/repos/OWNER/PRIVATE_REPO"
# {"ok":true,"upstream_status":200,"body":"{...\"private\":true...}"}   ← token stayed server-side
```

---

## Notes

- **LAN-only.** Bind to `PI_IP`, never `0.0.0.0`. For public exposure put a tunnel/reverse
  proxy in front and keep `BIND` on the LAN IP.
- **Unique port per gateway.** If you co-host multiple gateways on one host, each needs its
  own `PORT` — a `bridge-mta`-style service may already own `8787`.
- **`.env` is loaded by `server.mjs`,** for both the server and the CLI — no `EnvironmentFile`
  in the unit, no `source .env` before the CLI. Real/systemd-set env wins over `.env`.
- **Store + `.env` are `0600`.** The door-key persists across restarts in
  `get-hub-store.json`; you do NOT need to re-`issue` after a reboot.
- **exec is off** unless you set `EXEC_ENABLED=1` + `EXEC_DIR` (needed only for `run`/`temp`).
  Under systemd `EXEC_DIR` must be an **absolute** path — with the shipped `scripts/`,
  `EXEC_DIR=/home/<user>/get-hub/scripts` enables `temp`/`uptime`.
- **Logs:** primary is `systemctl --user status get-hub -l` (in-memory buffer). This Pi has no
  persistent journal, so `journalctl --user -u get-hub` returns nothing; use it only if journald
  persistence is enabled. Secrets are scrubbed from logs (I9).
