#!/usr/bin/env node
/**
 * bridge-mta — universal self-hosted port (any Linux, Node 18+, ZERO deps).
 *
 * Same mechanism as the Cloudflare Worker: OPS registry, op=do signed HTTPS proxy
 * with host allowlist + server-side GitHub token injection, HMAC-SHA256 signing,
 * anti-replay. Cloudflare primitives are replaced with local equivalents:
 *   KV        -> in-memory Map + a JSON file (STORE_PATH) for hmac:current / kc:gh
 *   subtle    -> node:crypto
 *   Worker fn -> node:http server
 *
 * Run modes:
 *   node server.mjs                 # start the HTTP server
 *   node server.mjs issue           # mint a fresh Bridge HMAC (+ GitHub token if App creds set), print, exit
 *   node server.mjs kill            # revoke+delete both keys, exit
 *   node server.mjs show            # print current key state, exit
 *
 * Config via env (see .env.example):
 *   PORT (default 8787), BIND (default 127.0.0.1), STORE_PATH (default ./bridge-store.json),
 *   ALLOW_HOSTS (space/comma list; default "api.github.com api.telegram.org"),
 *   KEY_TTL_SEC (default 3600), TS_WINDOW_SEC (default 3600),
 *   GITHUB_APP_ID, GITHUB_INSTALL_ID, GITHUB_APP_PEM_PATH (PKCS#8 pem file).
 */
import http from "node:http";
import crypto from "node:crypto";
import zlib from "node:zlib";
import fs from "node:fs";
import { promisify } from "node:util";

const inflateRaw = promisify(zlib.inflateRaw);

const CFG = {
  PORT: parseInt(process.env.PORT || "8787", 10),
  BIND: process.env.BIND || "127.0.0.1",
  STORE_PATH: process.env.STORE_PATH || new URL("./bridge-store.json", import.meta.url).pathname,
  ALLOW_HOSTS: (process.env.ALLOW_HOSTS || "api.github.com api.telegram.org").split(/[,\s]+/).filter(Boolean),
  KEY_TTL_SEC: parseInt(process.env.KEY_TTL_SEC || "3600", 10),
  TS_WINDOW_SEC: parseInt(process.env.TS_WINDOW_SEC || "3600", 10),
  NONCE_TTL_SEC: parseInt(process.env.NONCE_TTL_SEC || "3600", 10),
  DO_MAX_RESP: parseInt(process.env.DO_MAX_RESP || "100000", 10),
  GH_APP_ID: process.env.GITHUB_APP_ID || "",
  GH_INSTALL_ID: process.env.GITHUB_INSTALL_ID || "",
  GH_PEM_PATH: process.env.GITHUB_APP_PEM_PATH || "",
  GH_STATIC_TOKEN: process.env.GITHUB_TOKEN || "", // static PAT alternative to the App flow
  GH_MODE: (process.env.GITHUB_MODE || "readwrite").toLowerCase(), // "readonly" clamps GitHub to GET/HEAD
  GH_REPOS: (process.env.GITHUB_REPOS || "").split(/[,\s]+/).filter(Boolean).map((s) => s.toLowerCase()), // optional repo allowlist; empty = any the token allows
  UA: "bridge-mta-node/1.0",
  VERSION: "node-0.1.0",
};
const SIG_VERSION = "v1";

// ───────────── persistent store (KV replacement) ─────────────
// File holds { "hmac:current": {v, exp}, "kc:gh": {v:{token,expires_at}, exp} }.
// Nonces are in-memory only (lost on restart — acceptable, ts window bounds replay).
function loadStore() {
  try { return JSON.parse(fs.readFileSync(CFG.STORE_PATH, "utf8")); } catch { return {}; }
}
function saveStore(s) {
  fs.writeFileSync(CFG.STORE_PATH, JSON.stringify(s), { mode: 0o600 });
}
function kvGet(key) {
  const s = loadStore();
  const e = s[key];
  if (!e) return null;
  if (e.exp && e.exp < Math.floor(Date.now() / 1000)) { delete s[key]; saveStore(s); return null; }
  return e.v;
}
function kvPut(key, v, ttlSec) {
  const s = loadStore();
  s[key] = { v, exp: ttlSec ? Math.floor(Date.now() / 1000) + ttlSec : 0 };
  saveStore(s);
}
function kvDel(key) { const s = loadStore(); delete s[key]; saveStore(s); }

const nonces = new Map(); // nonce -> expiry epoch sec
function nonceSeen(n) {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, exp] of nonces) if (exp < now) nonces.delete(k);
  if (nonces.has(n)) return true;
  nonces.set(n, now + CFG.NONCE_TTL_SEC);
  return false;
}

// ───────────── HMAC + canonical ─────────────
function canonical(path, params) {
  const enc = (s) => encodeURIComponent(String(s));
  const pairs = Object.entries(params)
    .filter(([k]) => k !== "sig")
    .map(([k, v]) => `${enc(k)}=${enc(v)}`)
    .sort();
  return `${SIG_VERSION}\n${path}\n${pairs.join("&")}`;
}
function hmacHex(secret, msg) {
  return crypto.createHmac("sha256", secret).update(msg).digest("hex");
}
function ctEqual(a, b) {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function getHmacSecret() { return kvGet("hmac:current") || ""; }

function verifyRequest(path, params) {
  if (!params.sig) return { ok: false, err: "no_sig" };
  if (!params.ts) return { ok: false, err: "no_ts" };
  const ts = parseInt(params.ts, 10);
  if (!Number.isFinite(ts)) return { ok: false, err: "bad_ts" };
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > CFG.TS_WINDOW_SEC) return { ok: false, err: "ts_expired" };
  const nonce = params.nonce || "";
  if (nonce.length < 8 || nonce.length > 128) return { ok: false, err: "bad_nonce" };
  const secret = getHmacSecret();
  if (!secret) return { ok: false, err: "no_secret_server" };
  if (!ctEqual(params.sig, hmacHex(secret, canonical(path, params)))) return { ok: false, err: "bad_sig" };
  if (nonceSeen(nonce)) return { ok: false, err: "replay" };
  return { ok: true };
}

// ───────────── GitHub App JWT (RS256) → installation token ─────────────
function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function githubNow() {
  try {
    const r = await fetch("https://api.github.com/zen", { headers: { "User-Agent": CFG.UA } });
    const d = r.headers.get("date");
    if (d) { const t = Math.floor(new Date(d).getTime() / 1000); if (t > 0) return t; }
  } catch {}
  return Math.floor(Date.now() / 1000);
}
async function issueGithub() {
  if (!CFG.GH_APP_ID || !CFG.GH_INSTALL_ID || !CFG.GH_PEM_PATH) return null;
  const pem = fs.readFileSync(CFG.GH_PEM_PATH, "utf8");
  const now = await githubNow();
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(CFG.GH_APP_ID) }));
  const data = `${header}.${payload}`;
  const sig = b64url(crypto.sign("RSA-SHA256", Buffer.from(data), pem));
  const jwt = `${data}.${sig}`;
  const r = await fetch(`https://api.github.com/app/installations/${CFG.GH_INSTALL_ID}/access_tokens`, {
    method: "POST",
    headers: { Authorization: `Bearer ${jwt}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": CFG.UA },
  });
  const text = await r.text();
  if (r.status !== 200 && r.status !== 201) throw new Error(`GitHub ${r.status}: ${text.slice(0, 200)}`);
  const d = JSON.parse(text);
  return { token: d.token, expires_at: d.expires_at };
}
async function revokeGithub(token) {
  try {
    await fetch("https://api.github.com/installation/token", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": CFG.UA },
    });
  } catch {}
}
function randToken(prefix) { return prefix + crypto.randomBytes(24).toString("hex"); }

// ───────────── key lifecycle (CLI, replaces the Telegram ⚡/💀) ─────────────
async function issueKeys() {
  const oldGh = kvGet("kc:gh");
  if (oldGh && oldGh.token) await revokeGithub(oldGh.token);
  let gh = null, ghErr = null;
  try { gh = await issueGithub(); } catch (e) { ghErr = String(e).slice(0, 200); }
  const hmac = randToken("bridge-");
  kvPut("hmac:current", hmac, CFG.KEY_TTL_SEC);
  if (gh) {
    const ttl = Math.max(60, Math.floor(new Date(gh.expires_at).getTime() / 1000) - Math.floor(Date.now() / 1000));
    kvPut("kc:gh", gh, ttl);
  }
  return { hmac, gh: gh ? "issued" : `none (${ghErr || "no App creds"})` };
}
async function killKeys() {
  const oldGh = kvGet("kc:gh");
  if (oldGh && oldGh.token) await revokeGithub(oldGh.token);
  kvDel("kc:gh"); kvDel("hmac:current");
}

// ───────────── OPS ─────────────
const OPS = {
  async ping() { return ok({ pong: true, time: Date.now() }); },
  async echo(p) { return ok({ msg: p.msg || "" }); },
  async info() {
    const ghToken = CFG.GH_STATIC_TOKEN || (kvGet("kc:gh") || {}).token;
    return ok({
      version: CFG.VERSION,
      time: Date.now(),
      allow_hosts: CFG.ALLOW_HOSTS,
      github: { enabled: !!ghToken, mode: CFG.GH_MODE, repos: CFG.GH_REPOS.length ? CFG.GH_REPOS : "any" },
    });
  },
  async ops() { return ok({ commands: Object.keys(OPS).sort() }); },
  async secure_echo(p) { const s = { ...p }; delete s.sig; delete s.key; return ok({ secured: true, params: s }); },
  async do(p) {
    let target;
    try { target = new URL(p.t || ""); } catch { return err(400, "bad_target"); }
    if (target.protocol !== "https:") return err(400, "only_https");
    if (!CFG.ALLOW_HOSTS.includes(target.hostname)) return err(403, "host_not_allowed", { host: target.hostname });
    const method = (p.m || "GET").toUpperCase();

    let body;
    if (p.p) {
      try {
        let buf = Buffer.from(String(p.p).replace(/-/g, "+").replace(/_/g, "/"), "base64");
        if (p.c === "1") buf = await inflateRaw(buf);
        body = buf;
      } catch { return err(400, "bad_payload"); }
    }

    const headers = { "User-Agent": CFG.UA };
    if (p.h) {
      try { Object.assign(headers, JSON.parse(Buffer.from(String(p.h).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString())); }
      catch { return err(400, "bad_headers"); }
    }
    if (target.hostname === "api.github.com") {
      // Built-in GitHub policy: rights come from the token; optionally clamp to
      // read-only and/or restrict to an allowlist of repos.
      if (CFG.GH_MODE === "readonly" && method !== "GET" && method !== "HEAD")
        return err(403, "github_readonly", { method, hint: "This bridge is configured GITHUB_MODE=readonly; only GET/HEAD are allowed to GitHub." });
      if (CFG.GH_REPOS.length) {
        const m = target.pathname.match(/^\/repos\/([^\/]+)\/([^\/]+)/i);
        const repo = m ? `${m[1]}/${m[2]}`.toLowerCase() : null;
        if (!repo || !CFG.GH_REPOS.includes(repo))
          return err(403, "repo_not_allowed", { repo: repo || target.pathname, allowed: CFG.GH_REPOS, hint: "Path must target /repos/<owner>/<repo> for an allowlisted repo." });
      }
      if (!headers.Authorization) {
        const gh = kvGet("kc:gh");
        const tok = (gh && gh.token) ? gh.token : CFG.GH_STATIC_TOKEN; // App-minted token wins; else static PAT
        if (tok) { headers.Authorization = `Bearer ${tok}`; if (!headers.Accept) headers.Accept = "application/vnd.github+json"; }
      }
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    let r;
    try {
      r = await fetch(target.toString(), {
        method, headers,
        body: method === "GET" || method === "HEAD" ? undefined : body,
        redirect: "manual", signal: ctrl.signal,
      });
    } catch (e) { clearTimeout(timer); return err(502, "upstream_failed", { detail: String(e).slice(0, 150) }); }
    clearTimeout(timer);

    const text = await r.text();
    // honest status mapping (unlike the CF worker; matches the PHP port + PROPOSALS P2)
    const okStatus = r.status >= 200 && r.status < 300;
    let error = null, hint = null;
    if (!okStatus) {
      if (r.status === 401) { error = "token_expired"; hint = "GitHub token invalid/expired — supply a fresh one."; }
      else if (r.status === 404) { error = "not_found"; hint = "Not found or no access (private without permission)."; }
      else if (r.status === 403 || r.status === 429) { error = /rate limit/i.test(text) ? "rate_limited" : "forbidden"; hint = "GitHub refused/limited — retry later."; }
      else if (r.status >= 500) { error = "upstream_error"; hint = `Upstream server error ${r.status}.`; }
      else { error = "upstream_error"; hint = `Unexpected upstream status ${r.status}.`; }
    }
    return json(200, { ok: okStatus, upstream_status: r.status, error, hint, fetched_at: new Date().toISOString(), body: text.slice(0, CFG.DO_MAX_RESP) });
  },
};
const PUBLIC_OPS = new Set(["ping", "info", "echo", "ops"]);

// ───────────── response helpers ─────────────
const SEC_HEADERS = { "Cache-Control": "no-store, private, no-cache", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow" };
function json(status, obj) { return { status, body: JSON.stringify(obj) }; }
function ok(data) { return json(200, { ok: true, ...data }); }
function err(status, error, extra = {}) { return json(status, { ok: false, error, ...extra }); }

// ───────────── HTTP server ─────────────
async function handle(req) {
  if (req.method !== "GET") return err(405, "method_not_allowed");
  const url = new URL(req.url, "http://x");
  const params = Object.fromEntries(url.searchParams);
  const op = params.op || "";
  if (!op) return ok({ pong: true, msg: "bridge alive", v: CFG.VERSION, time: Date.now() });
  if (PUBLIC_OPS.has(op)) return OPS[op](params);

  const live = params.key ? getHmacSecret() : "";
  if (!(live && params.key === live)) {
    const v = verifyRequest("/", params);
    if (!v.ok) return err(401, v.err);
  }
  const handler = OPS[op];
  if (!handler) return err(400, "unknown_op", { op, available: Object.keys(OPS).sort() });
  try { return await handler(params); } catch (e) { return err(500, "op_failed", { detail: String(e).slice(0, 200) }); }
}

function serve() {
  const srv = http.createServer(async (req, res) => {
    let out;
    try { out = await handle(req); } catch (e) { out = err(500, "internal", { detail: String(e).slice(0, 150) }); }
    res.writeHead(out.status, { "Content-Type": "application/json; charset=utf-8", ...SEC_HEADERS });
    res.end(out.body);
  });
  srv.listen(CFG.PORT, CFG.BIND, () => {
    console.log(`bridge-mta ${CFG.VERSION} on http://${CFG.BIND}:${CFG.PORT}  allow=${CFG.ALLOW_HOSTS.join(",")}  store=${CFG.STORE_PATH}`);
    console.log(getHmacSecret() ? "state: ACTIVE (hmac present)" : "state: ASLEEP — run `node server.mjs issue` to activate");
  });
}

// ───────────── CLI ─────────────
const cmd = process.argv[2];
if (cmd === "issue") { issueKeys().then((r) => { console.log(JSON.stringify(r, null, 2)); process.exit(0); }); }
else if (cmd === "kill") { killKeys().then(() => { console.log("killed"); process.exit(0); }); }
else if (cmd === "show") { console.log(JSON.stringify({ hmac: getHmacSecret() ? "present" : null, gh: kvGet("kc:gh") ? "present" : null }, null, 2)); process.exit(0); }
else serve();
