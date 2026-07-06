#!/usr/bin/env node
// Minimal bridge-mta signed client (Node 18+ / browser-compatible crypto.subtle).
//
//   BRIDGE_URL="https://<worker>" BRIDGE_SECRET="bridge-..." \
//     node sign.mjs do t=https://api.github.com/zen

const BASE = (process.env.BRIDGE_URL || "").replace(/\/$/, "");
const SECRET = process.env.BRIDGE_SECRET || "";
const UA = process.env.BRIDGE_UA || "bridge-client/1.0";

function nonce() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function signedUrl(op, kw = {}) {
  const params = {
    op,
    ...Object.fromEntries(Object.entries(kw).map(([k, v]) => [k, String(v)])),
    ts: String(Math.floor(Date.now() / 1000)), // ±3600s window
    nonce: nonce(),
  };
  const qs = Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .sort().join("&");
  const canonical = `v1\n/\n${qs}`;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  const sig = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${BASE}/?${qs}&sig=${sig}`;
}

async function call(op, kw = {}) {
  const r = await fetch(await signedUrl(op, kw), { headers: { "User-Agent": UA } });
  return r.json();
}

const [op, ...rest] = process.argv.slice(2);
if (!op) { console.error("usage: sign.mjs <op> [k=v ...]"); process.exit(1); }
const kw = Object.fromEntries(rest.map(a => a.split(/=(.*)/s).slice(0, 2)));
console.log(JSON.stringify(await call(op, kw)));
