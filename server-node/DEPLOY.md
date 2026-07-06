# Deploy bridge-mta-node persistently (systemd) + expose publicly

This is the **operations companion** to [`README.md`](README.md). Do the README
first (get code → configure `.env` → `node server.mjs` runs → `issue` a key →
verified). This file only adds: run it as a service, and put it on the public
internet.

The systemd unit below expects the server to live in a stable directory
`~/bridge-mta-node`. If you cloned the repo instead (README §1), either run the
service straight from `~/bridge-mta/server-node` (edit the three `%h/bridge-mta-node`
paths in the unit to match) or copy the folder to the stable path:

```bash
mkdir -p ~/bridge-mta-node
cp -r ~/bridge-mta/server-node/. ~/bridge-mta-node/     # server.mjs, .env, etc.
cd ~/bridge-mta-node
```

The full-HMAC reference signers live in the repo at [`clients/`](../clients/)
(`sign.sh` / `sign.py` / `sign.mjs`) — point them at the server with
`BRIDGE_URL` + `BRIDGE_SECRET`.

## systemd (persistent, survives reboot)
```bash
mkdir -p ~/.config/systemd/user
cp bridge-mta.service ~/.config/systemd/user/
export XDG_RUNTIME_DIR=/run/user/$(id -u)     # needed when driving systemctl --user over ssh
systemctl --user daemon-reload
systemctl --user enable --now bridge-mta
loginctl enable-linger "$USER"                # keep the service up after logout
systemctl --user status bridge-mta
```
The key you minted with `node server.mjs issue` persists in `bridge-store.json`, so
the service comes up ACTIVE after a restart. Re-issue or `kill` any time.

## Public HTTPS — pick one
- **Tailscale Funnel** (no domain, no Cloudflare): `tailscale funnel 8787` →
  `https://<node>.<tailnet>.ts.net`
- **Caddy + domain**: `caddy reverse-proxy --from bridge.example.com --to :8787`
- **Cloudflare Tunnel**: `cloudflared tunnel --url http://localhost:8787`

The server binds `127.0.0.1` by default — expose it **only** through the chosen
tunnel/proxy, never by rebinding to `0.0.0.0`.
