/**
 * Unit tests for the discovery/health surface modules:
 *   ping, info, ops, echo (public)  +  secure_echo (protected, auth-gated).
 *
 * Drives the REAL kernel (kernel.mjs) with the REAL modules dir — no mocks of the security
 * path. Uses node:test. Run:  node --test test/discovery.test.mjs   (from get-hub/).
 *
 * Covers:
 *  - each public op answers WITHOUT a door-key (even ASLEEP),
 *  - echo reflects ?msg=,
 *  - ops/info list the catalog and expose github-policy visibility,
 *  - secure_echo is REJECTED unauthenticated (kernel gate I1),
 *  - secure_echo ACCEPTED with a valid HMAC sig AND the door-key value is NOT reflected (I9),
 *  - secure_echo via degraded key= form is accepted but `key` is stripped from the echo.
 */
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, loadModules, createKernel } from "../kernel.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_MODULES = path.join(__dirname, "..", "modules");

// Isolate the modules under test: copy ONLY the discovery surface into a private temp dir and
// load from there. This keeps the test independent of whatever sibling agents drop into
// modules/ in parallel (e.g. github.mjs, *.test.mjs fixtures) so a broken sibling module can't
// fail OUR unit test. (info/ops now source their catalog from ctx.discovery — a kernel-built
// live view — so there is no _registry helper to copy.)
const OWNED = ["ping.mjs", "info.mjs", "ops.mjs", "echo.mjs", "secure_echo.mjs"];
const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "gethub-disc-"));
for (const f of OWNED) fs.copyFileSync(path.join(SRC_MODULES, f), path.join(FIXTURE_DIR, f));

// Fresh kernel per test, with an isolated temp store so we can mint a door-key.
async function makeKernel(extraEnv = {}) {
  const env = {
    ...process.env,
    STORE_PATH: path.join(FIXTURE_DIR, `.store-${crypto.randomBytes(6).toString("hex")}.json`),
    // info/ops now report the kernel's REAL global config via ctx.discovery — version comes
    // from cfg.VERSION and allow_hosts from the global ALLOW_HOSTS (not per-module INFO_* env).
    ALLOW_HOSTS: "api.github.com api.telegram.org",
    ...extraEnv,
  };
  const cfg = loadConfig(env);
  const modules = await loadModules(FIXTURE_DIR);
  const kernel = createKernel(cfg, modules);
  return { cfg, kernel, storePath: env.STORE_PATH };
}

// Minimal fake req the kernel.handleRequest expects (it only reads .url and .method).
const req = (url, method = "GET") => ({ url, method });

// Sign a request the way the kernel's canonical() does, so the HMAC path is exercised for real.
function signedUrl(kernel, doorKey, pathStr, params) {
  const all = { ...params };
  const canonical = kernel.canonical(pathStr, all);
  const sig = kernel.hmacHex(doorKey, canonical);
  const qs = new URLSearchParams({ ...all, sig }).toString();
  return `${pathStr}?${qs}`;
}

test("ping: public, answers pong without a door-key", async () => {
  const { kernel } = await makeKernel();
  assert.equal(kernel.isAsleep(), true, "no door-key => ASLEEP");
  const r = await kernel.handleRequest(req("/?op=ping&t=abc123"));
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
  assert.equal(r.body.pong, true);
  assert.equal(r.body.t, "abc123");
});

test("echo: reflects ?msg= and reports length", async () => {
  const { kernel } = await makeKernel();
  const r = await kernel.handleRequest(req("/?op=echo&msg=" + encodeURIComponent("hi there")));
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
  assert.equal(r.body.msg, "hi there");
  assert.equal(r.body.len, "hi there".length);
});

test("echo: missing msg => empty string, not undefined", async () => {
  const { kernel } = await makeKernel();
  const r = await kernel.handleRequest(req("/?op=echo"));
  assert.equal(r.body.msg, "");
  assert.equal(r.body.len, 0);
});

test("ops: lists sorted op names + public/protected detail", async () => {
  const { kernel } = await makeKernel();
  const r = await kernel.handleRequest(req("/?op=ops"));
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
  assert.ok(Array.isArray(r.body.ops));
  // catalog must include the discovery surface we built
  for (const op of ["ping", "info", "ops", "echo", "secure_echo"]) {
    assert.ok(r.body.ops.includes(op), `ops should list ${op}`);
  }
  // sorted + deduped
  assert.deepEqual(r.body.ops, [...r.body.ops].sort());
  const se = r.body.detail.find((d) => d.op === "secure_echo");
  assert.equal(se.public, false, "secure_echo must be reported as protected");
});

test("info: version + allow_hosts + live op catalog + github policy visibility", async () => {
  const { kernel } = await makeKernel();
  const r = await kernel.handleRequest(req("/?op=info"));
  assert.equal(r.status, 200);
  // version + allow_hosts come from the kernel's REAL global config (ctx.discovery), not INFO_*.
  assert.equal(r.body.version, "get-hub-1.0.0", "version comes from kernel cfg.VERSION");
  assert.deepEqual(r.body.allow_hosts, ["api.github.com", "api.telegram.org"]);
  // live op catalog reflects the actually-loaded modules.
  assert.ok(r.body.ops.some((o) => o.op === "secure_echo" && o.public === false));
  assert.ok(r.body.public_ops.includes("info"));
  // github policy visibility: no per-service policy at the bridge; token scoped at GitHub.
  assert.equal(r.body.github_policy.bridge_side_policy, "none");
  assert.equal(r.body.github_policy.built_in, true);
});

test("info: allow_hosts reflects the configured global ALLOW_HOSTS", async () => {
  const { kernel } = await makeKernel({ ALLOW_HOSTS: "api.github.com" });
  const r = await kernel.handleRequest(req("/?op=info"));
  assert.deepEqual(r.body.allow_hosts, ["api.github.com"]);
});

test("secure_echo: REJECTED without auth (kernel gate I1)", async () => {
  const { kernel } = await makeKernel();
  const r = await kernel.handleRequest(req("/?op=secure_echo&a=1"));
  assert.equal(r.status, 401, "protected op must 401 unauthenticated");
  assert.ok(r.body.error);
  assert.notEqual(r.body.ok, true);
});

test("secure_echo: ACCEPTED with valid HMAC sig; sig NOT reflected (I9)", async () => {
  const { kernel } = await makeKernel();
  // mint a door-key via the operator control plane
  const res = await kernel.control.rotate(["door-key"], {});
  const doorKey = res._doorKey;
  assert.ok(doorKey, "door-key minted");

  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(8).toString("hex");
  const url = signedUrl(kernel, doorKey, "/", { op: "secure_echo", a: "1", b: "two", ts: String(ts), nonce });
  const r = await kernel.handleRequest(req(url));

  assert.equal(r.status, 200, "valid sig => 200");
  assert.equal(r.body.ok, true);
  assert.equal(r.body.authenticated, true);
  assert.equal(r.body.sig_present, false, "kernel stripped sig before handle");
  assert.equal(r.body.key_present, false);
  // business params survive; no secret leaks
  assert.equal(r.body.params.a, "1");
  assert.equal(r.body.params.b, "two");
  const flat = JSON.stringify(r.body);
  assert.ok(!flat.includes(doorKey), "door-key value must never appear in the response");
  assert.ok(!("sig" in r.body.params) && !("key" in r.body.params));
});

test("secure_echo: bad sig => 401 bad_sig (proven guard preserved)", async () => {
  const { kernel } = await makeKernel();
  await kernel.control.rotate(["door-key"], {});
  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(8).toString("hex");
  const url = `/?op=secure_echo&a=1&ts=${ts}&nonce=${nonce}&sig=deadbeef`;
  const r = await kernel.handleRequest(req(url));
  assert.equal(r.status, 401);
  assert.equal(r.body.error, "bad_sig");
});

test("secure_echo: degraded key= form accepted; key stripped from echo (I9)", async () => {
  const { kernel } = await makeKernel();
  const res = await kernel.control.rotate(["door-key"], {});
  const doorKey = res._doorKey;
  const url = `/?op=secure_echo&a=1&key=${encodeURIComponent(doorKey)}`;
  const r = await kernel.handleRequest(req(url));
  assert.equal(r.status, 200, "correct key= => accepted");
  assert.equal(r.body.ok, true);
  assert.equal(r.body.key_present, false, "kernel stripped key before handle");
  assert.ok(!JSON.stringify(r.body).includes(doorKey), "door-key value not reflected");
});

test("match() is pure: routing works on the unauthenticated ctx (core:null, env:{})", async () => {
  const { kernel } = await makeKernel();
  // A protected op still ROUTES (match runs on unauth ctx) then gets rejected by auth,
  // proving match never touched core/env (else it would throw on null core).
  const r = await kernel.handleRequest(req("/?op=secure_echo"));
  assert.equal(r.status, 401); // routed to secure_echo, then auth-rejected — not 404
});
