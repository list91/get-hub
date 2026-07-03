/**
 * Regression tests for the PUBLIC-EXPOSURE hardening (audit run w633n2bv8). Each targets one of the
 * four blockers that a LAN deployment hid but a public endpoint exposes:
 *   1. bounded nonce set  — unbounded Map + full-scan sweep → OOM / O(n^2) DoS under an authed flood
 *   2. door-key cache     — synchronous readFileSync of the store on every auth → event-loop DoS
 *   3. ALLOW_KEY_PARAM    — the raw secret rides in the ?key= URL; a hardened deploy must force-sign
 *   4. tight TS_WINDOW    — a captured signed URL must not be replayable for an hour
 */
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, loadModules, createKernel, _internals } from "../kernel.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODULES = path.join(__dirname, "..", "modules");

function tmpStore(tag) {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), `gethub-${tag}-`)), "store.json");
}
async function kernelWith(envOverrides) {
  const env = { ...process.env, STORE_PATH: tmpStore("hard"), ...envOverrides };
  const cfg = loadConfig(env);
  const modules = await loadModules(MODULES);
  return { cfg, kernel: createKernel(cfg, modules) };
}
// canonical signer matching kernel.canonical(): v1\n<path>\n<sorted k=v except sig>
function signUrl(pathStr, params, secret) {
  const p = { ...params };
  delete p.sig;
  const canon = "v1\n" + pathStr + "\n" +
    Object.keys(p).map((k) => encodeURIComponent(k) + "=" + encodeURIComponent(p[k])).sort().join("&");
  const sig = crypto.createHmac("sha256", secret).update(canon).digest("hex");
  const qs = Object.entries({ ...params, sig }).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
  return `${pathStr}?${qs}`;
}

// ── 1. Nonce set is a BOUNDED ring: NONCE_MAX cap evicts oldest; recent nonce still detected ──────
test("nonce: NONCE_MAX bounds the set — oldest evicted, recent replay still caught (no unbounded heap)", async () => {
  const { kernel } = await kernelWith({ NONCE_MAX: "5", NONCE_TTL_SEC: "300" });
  const store = kernel.store;
  const seen = [];
  for (let i = 0; i < 12; i++) seen.push(store.nonceSeen("n" + i)); // 12 fresh nonces, cap 5
  assert.ok(seen.every((s) => s === false), "each fresh nonce is first-seen (false)");
  // the most recent nonce is still remembered → genuine replay is caught
  assert.equal(store.nonceSeen("n11"), true, "recent nonce within cap → detected as replay");
  // the oldest was evicted by the cap → it is forgotten (re-usable), proving the set never grows past cap
  assert.equal(store.nonceSeen("n0"), false, "oldest nonce evicted by NONCE_MAX → set is bounded, not unbounded");
});

// ── 2. Door-key is cached in memory: rotate/kill stay coherent, but a raw disk edit is NOT re-read ──
test("door-key cache: coherent on rotate/del, and NOT re-read from disk per call", async () => {
  const { cfg, kernel } = await kernelWith({});
  const store = kernel.store;
  store.set("hmac:current", "bridge-AAAA", 300);
  assert.equal(kernel.getDoorKey(), "bridge-AAAA", "rotate (set) is reflected via cache");

  // Tamper the store FILE directly with a different value. If getDoorKey re-read the disk every call
  // (the DoS bug), we'd see the tampered value; with the cache we must still see the cached one.
  const raw = JSON.parse(fs.readFileSync(cfg.STORE_PATH, "utf8"));
  raw["hmac:current"] = { v: "bridge-TAMPERED", exp: 0 };
  fs.writeFileSync(cfg.STORE_PATH, JSON.stringify(raw));
  assert.equal(kernel.getDoorKey(), "bridge-AAAA", "value served from cache, NOT re-read from disk each call");

  store.del("hmac:current");
  assert.equal(kernel.getDoorKey(), "", "kill (del) invalidates the cache → empty");
});

// ── 3. ALLOW_KEY_PARAM=0 force-signs: the degraded ?key= form is rejected; the signed form still works ─
test("ALLOW_KEY_PARAM=0 disables the ?key= URL form but the HMAC form still authenticates", async () => {
  const { kernel } = await kernelWith({ ALLOW_KEY_PARAM: "0" });
  kernel.store.set("hmac:current", "bridge-KEYDISABLED", 300);
  const secret = "bridge-KEYDISABLED";

  const rKey = await kernel.handleRequest({ url: "/?op=hash&s=x&key=" + secret, method: "GET" });
  assert.equal(rKey.status, 401);
  assert.equal(rKey.body.error, "key_param_disabled", "?key= form refused when disabled — secret must not ride the URL");

  const ts = Math.floor(Date.now() / 1000);
  const url = signUrl("/", { op: "hash", s: "x", ts: String(ts), nonce: "noncehard01" }, secret);
  const rSig = await kernel.handleRequest({ url, method: "GET" });
  assert.equal(rSig.status, 200, "signed form still works when ?key= is disabled");
  assert.equal(rSig.body.ok, true);
});

// sanity: with the flag DEFAULT (on), the ?key= form still works (product's core data path preserved)
test("ALLOW_KEY_PARAM default ON: ?key= form works (browser-LLM data path preserved)", async () => {
  const { kernel } = await kernelWith({});
  kernel.store.set("hmac:current", "bridge-KEYON", 300);
  const r = await kernel.handleRequest({ url: "/?op=hash&s=x&key=bridge-KEYON", method: "GET" });
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
});

// ── 4. TS_WINDOW default is TIGHT (not a 1-hour public replay window) ──────────────────────────────
test("TS_WINDOW default is tight (<=300s) so a captured signed URL is not replayable for an hour", async () => {
  const { cfg } = await kernelWith({});
  assert.ok(cfg.TS_WINDOW_SEC <= 300, `default ts window ${cfg.TS_WINDOW_SEC}s must be tight for public exposure`);
  assert.ok(cfg.NONCE_TTL_SEC <= cfg.TS_WINDOW_SEC, "nonce retention is coupled to (not longer than) the ts window");
});

// a signed URL with a ts beyond the (now tight) window is rejected as expired
test("signed URL with ts older than TS_WINDOW is ts_expired (replay window is bounded)", async () => {
  const { kernel } = await kernelWith({ TS_WINDOW_SEC: "120" });
  kernel.store.set("hmac:current", "bridge-TSWIN", 300);
  const oldTs = Math.floor(Date.now() / 1000) - 600; // 10 min ago, window 120s
  const url = signUrl("/", { op: "hash", s: "x", ts: String(oldTs), nonce: "nonceold001" }, "bridge-TSWIN");
  const r = await kernel.handleRequest({ url, method: "GET" });
  assert.equal(r.status, 401);
  assert.equal(r.body.error, "ts_expired");
});
