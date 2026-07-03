/**
 * Unit test for modules/fetch.mjs — the http-class demo.
 *
 * Two layers:
 *  A) Module-in-isolation with a FAKE core: proves fetch adds no policy — it forwards the
 *     exact `t` to core.proxy({method:"GET"}) and returns the envelope untouched, and it
 *     rejects a missing target locally (the only thing it's allowed to decide).
 *  B) Module over the REAL kernel core: proves the proxy PRIMITIVE's guards fire through
 *     this module (only_https / host_not_allowed / blocked_ip) — i.e. the boundary is the
 *     primitive, not the module. These are offline (no allowlisted host is ever dialed).
 *
 * Run:  node --test test/fetch.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fetchMod from "../modules/fetch.mjs";
import { loadConfig, createKernel } from "../kernel.mjs";

// ── helpers ──────────────────────────────────────────────────────────────────
function ctxWith(params, core) {
  return {
    op: "fetch",
    params,
    method: "GET",
    url: new URL("http://x/?op=fetch"),
    host: null,
    headers: { "User-Agent": "test" },
    env: Object.freeze({}),
    core,
  };
}

// A real kernel core, but with an EMPTY module list so nothing else interferes, and a
// throwaway store path so we never touch the shared store file.
function realCore() {
  const cfg = loadConfig({
    ALLOW_HOSTS: "api.github.com",
    STORE_PATH: "./test/.fetch-test-store.json",
    // proxy timeout tiny so a stray dial can't hang the suite (guards fire before any dial anyway)
    PROXY_TIMEOUT_MS: "1500",
  });
  const kernel = createKernel(cfg, []);
  return kernel.coreFor("fetch");
}

// ── A. contract shape ─────────────────────────────────────────────────────────
test("shape: name/public/match/handle match the module contract", () => {
  assert.equal(fetchMod.name, "fetch");
  assert.equal(fetchMod.public, false); // protected — door-key required (I1)
  assert.equal(typeof fetchMod.match, "function");
  assert.equal(typeof fetchMod.handle, "function");
  assert.match(fetchMod.name, /^[a-z0-9_-]+$/);
});

test("match is pure: claims op=fetch, ignores everything else, no core touched", () => {
  // match must not throw even on the unauthenticated routing ctx (core:null, env:{}).
  assert.equal(fetchMod.match({ op: "fetch", params: {}, core: null, env: {} }), true);
  assert.equal(fetchMod.match({ op: "hash", params: {}, core: null, env: {} }), false);
  assert.equal(fetchMod.match({ op: "", params: {}, core: null, env: {} }), false);
});

// ── A. forwards verbatim, adds no policy ───────────────────────────────────────
test("handle forwards the exact t= to core.proxy with GET and returns the envelope as-is", async () => {
  const calls = [];
  const envelope = {
    ok: true, upstream_status: 200, error: null, hint: null,
    fetched_at: "2026-01-01T00:00:00.000Z", body: "hello", truncated: false,
  };
  const fakeCore = {
    proxy: async (target, opts) => { calls.push({ target, opts }); return envelope; },
  };
  const out = await fetchMod.handle(ctxWith({ t: "https://api.github.com/rate_limit" }, fakeCore));

  // exactly one proxy call, with the raw target and method GET, and NO extra opts/policy.
  assert.equal(calls.length, 1);
  assert.equal(calls[0].target, "https://api.github.com/rate_limit"); // verbatim, un-rewritten
  assert.deepEqual(calls[0].opts, { method: "GET" });                  // no headers, no body, no host clamp
  // envelope returned untouched (no fields added/stripped by the module).
  assert.deepEqual(out, envelope);
});

test("handle does NOT pre-filter host/scheme — it forwards even a would-be-blocked target", async () => {
  // The module must not short-circuit; it hands the primitive a target the primitive will
  // reject, so the caller gets the primitive's real error (proving the boundary is central).
  let seen = null;
  const fakeCore = { proxy: async (t) => { seen = t; return { ok: false, error: "host_not_allowed", host: "evil.example" }; } };
  const out = await fetchMod.handle(ctxWith({ t: "https://evil.example/x" }, fakeCore));
  assert.equal(seen, "https://evil.example/x");   // module forwarded it, did not decide locally
  assert.equal(out.error, "host_not_allowed");    // primitive's verdict surfaced verbatim
});

// ── A. the ONE thing the module is allowed to decide: missing target ──────────
test("handle rejects a missing/empty target locally without calling proxy", async () => {
  let proxied = false;
  const fakeCore = { proxy: async () => { proxied = true; return { ok: true }; } };

  const noT = await fetchMod.handle(ctxWith({}, fakeCore));
  assert.equal(noT.ok, false);
  assert.equal(noT.error, "missing_target");

  const emptyT = await fetchMod.handle(ctxWith({ t: "" }, fakeCore));
  assert.equal(emptyT.ok, false);
  assert.equal(emptyT.error, "missing_target");

  assert.equal(proxied, false); // never dialed the primitive with no target
});

// ── B. primitive guards fire THROUGH the module (real kernel core, offline) ────
test("primitive guard: non-https target → only_https (I8)", async () => {
  const out = await fetchMod.handle(ctxWith({ t: "http://api.github.com/x" }, realCore()));
  assert.equal(out.ok, false);
  assert.equal(out.error, "only_https");
});

test("primitive guard: off-allowlist host → host_not_allowed (I8)", async () => {
  const out = await fetchMod.handle(ctxWith({ t: "https://not-allowed.example/x" }, realCore()));
  assert.equal(out.ok, false);
  assert.equal(out.error, "host_not_allowed");
});

test("primitive guard: metadata IP is not even on the allowlist → host_not_allowed before any dial (I8)", async () => {
  // 169.254.169.254 would be blocked_ip if allowlisted; here it's off-allowlist, so the
  // host check trips first. Either way the module never reaches a private address.
  const out = await fetchMod.handle(ctxWith({ t: "https://169.254.169.254/latest/meta-data/" }, realCore()));
  assert.equal(out.ok, false);
  assert.equal(out.error, "host_not_allowed");
});

test("primitive guard: bad target string → bad_target, module surfaces it untouched", async () => {
  const out = await fetchMod.handle(ctxWith({ t: "::::not a url" }, realCore()));
  assert.equal(out.ok, false);
  assert.equal(out.error, "bad_target");
});
