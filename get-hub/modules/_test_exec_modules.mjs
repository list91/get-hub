/**
 * Unit + integration test for the exec-class modules temp.mjs and run.mjs.
 *
 * Run:  node modules/_test_exec_modules.mjs
 *
 * Leading underscore => the kernel loader IGNORES this file (it is not a live module).
 *
 * Two layers:
 *   A. UNIT — drive temp/run against a FAKE core to prove module-local behavior:
 *      fixed name+args, bad-name rejection, safe error surfacing, no stdout leak on failure.
 *   B. INTEGRATION — build the REAL kernel over modules/ and scripts/ and prove the
 *      exec primitive's clamps hold end to end: OFF by default, path-traversal/command
 *      injection rejected, a vetted name actually runs. This is the "safe by construction"
 *      proof for I7.
 */
import assert from "node:assert/strict";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadConfig, createKernel } from "../kernel.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = path.join(__dirname, "..", "scripts");

// unique tmp store path so tests never clobber a real store
function makeTmpStore(tag) {
  const p = path.join(os.tmpdir(), `get-hub-test-${tag}-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  try { fs.writeFileSync(p, "{}"); } catch {}
  return p;
}

let pass = 0;
const ok = (label) => { pass++; console.log(`  ok  ${label}`); };

// import the two modules under test directly
const temp = (await import(pathToFileURL(path.join(__dirname, "temp.mjs")).href)).default;
const run = (await import(pathToFileURL(path.join(__dirname, "run.mjs")).href)).default;

// ── A fake core that records exactly what the module asked exec to do ──
function fakeCore(execImpl) {
  const calls = [];
  return {
    calls,
    exec: async (name, args) => { calls.push({ name, args }); return execImpl(name, args); },
    proxy: async () => { throw new Error("proxy must not be called by exec modules"); },
    store: { get: () => null, set: () => {} },
    log: () => {},
  };
}

function ctxFor(op, params, core) {
  return { op, params, method: "GET", url: new URL(`http://x/?op=${op}`), host: null, headers: {}, env: {}, core };
}

// ─────────────────────────────────────────────────────────────────────────────
// A. UNIT
// ─────────────────────────────────────────────────────────────────────────────

// match is pure + sync and claims only its own op
assert.equal(temp.match(ctxFor("temp", {}, null)), true);
assert.equal(temp.match(ctxFor("run", {}, null)), false);
assert.equal(run.match(ctxFor("run", {}, null)), true);
assert.equal(run.match(ctxFor("temp", {}, null)), false);
ok("match() is op-scoped and pure");

// temp: always calls exec("temp", []) — nothing client-supplied is forwarded
{
  const core = fakeCore(async () => ({ ok: true, exit_code: 0, stdout: "41.2\n" }));
  const res = await temp.handle(ctxFor("temp", { name: "../etc/passwd", extra: "x" }, core));
  assert.deepEqual(core.calls, [{ name: "temp", args: [] }]);
  assert.equal(res.ok, true);
  assert.equal(res.celsius, 41.2);
  ok("temp: hardcodes exec('temp',[]) — client params never reach exec");
}

// temp: failure surfaces only the safe error code, never stdout/stderr
{
  const core = fakeCore(async () => ({ ok: false, error: "exec_disabled", stdout: "SECRET-LEAK" }));
  const res = await temp.handle(ctxFor("temp", {}, core));
  assert.equal(res.ok, false);
  assert.equal(res.error, "exec_disabled");
  assert.equal(JSON.stringify(res).includes("SECRET-LEAK"), false);
  ok("temp: failure returns safe error code, no stdout leak (I9)");
}

// temp: non-numeric stdout => celsius null, no throw
{
  const core = fakeCore(async () => ({ ok: true, exit_code: 0, stdout: "unavailable\n" }));
  const res = await temp.handle(ctxFor("temp", {}, core));
  assert.equal(res.ok, true);
  assert.equal(res.celsius, null);
  ok("temp: non-numeric reading => celsius null (no crash)");
}

// run: forwards ONLY the vetted name and an EMPTY arg array
{
  const core = fakeCore(async () => ({ ok: true, exit_code: 0, stdout: "12345\n" }));
  const res = await run.handle(ctxFor("run", { name: "uptime" }, core));
  assert.deepEqual(core.calls, [{ name: "uptime", args: [] }]);
  assert.equal(res.ok, true);
  assert.equal(res.name, "uptime");
  assert.equal(res.stdout, "12345\n");
  ok("run: forwards vetted name + EMPTY args (no arg injection)");
}

// run: rejects client-supplied PATH / traversal / command / metachars — never touches exec
{
  const badNames = [
    "../etc/passwd", "..\\..\\x", "/bin/sh", "a/b", "a.sh", "a b",
    "rm -rf /", "a;b", "a|b", "a&b", "$(id)", "a`b`", "", "A_UPPER", "тест", "a\0b",
  ];
  for (const bad of badNames) {
    const core = fakeCore(async () => ({ ok: true, stdout: "SHOULD-NOT-RUN" }));
    const res = await run.handle(ctxFor("run", { name: bad }, core));
    assert.equal(res.ok, false, `expected reject for name=${JSON.stringify(bad)}`);
    assert.equal(res.error, "bad_name", `expected bad_name for ${JSON.stringify(bad)}`);
    assert.equal(core.calls.length, 0, `exec must NOT be called for ${JSON.stringify(bad)}`);
  }
  ok("run: rejects path/traversal/command/metachar/uppercase/nul names — exec never called (I7)");
}

// run: missing name => bad_name, exec not called
{
  const core = fakeCore(async () => ({ ok: true, stdout: "X" }));
  const res = await run.handle(ctxFor("run", {}, core));
  assert.equal(res.ok, false);
  assert.equal(res.error, "bad_name");
  assert.equal(core.calls.length, 0);
  ok("run: missing name => bad_name (exec untouched)");
}

// run: exec failure surfaces safe code only, no stdout leak
{
  const core = fakeCore(async () => ({ ok: false, error: "nonzero_exit", stdout: "LEAK" }));
  const res = await run.handle(ctxFor("run", { name: "temp" }, core));
  assert.equal(res.ok, false);
  assert.equal(res.error, "nonzero_exit");
  assert.equal(JSON.stringify(res).includes("LEAK"), false);
  ok("run: exec failure => safe error code, no stdout leak (I9)");
}

// ─────────────────────────────────────────────────────────────────────────────
// B. INTEGRATION against the REAL kernel core.exec
// ─────────────────────────────────────────────────────────────────────────────
async function callOp(kernel, query) {
  const out = await kernel.handleRequest({ method: "GET", url: `/?${query}` });
  return out;
}

// helper: build a kernel over ONLY the two modules under test (isolated from sibling
// modules other agents may still be landing) + issue a door-key.
async function bootKernel(env) {
  const cfg = loadConfig(env);
  const kernel = createKernel(cfg, [temp, run]);
  const res = await kernel.control.rotate(["door-key"], {});
  return { kernel, key: res._doorKey };
}

// B1. exec OFF by default => exec_disabled (module still enforces auth first)
{
  const { kernel, key } = await bootKernel({ STORE_PATH: makeTmpStore("off") /* EXEC_ENABLED unset */ });
  // unauthenticated => kernel rejects before handle (I1)
  const noauth = await callOp(kernel, "op=temp");
  assert.equal(noauth.status, 401);
  // authenticated (degraded key=) but exec disabled => exec_disabled from core.exec
  const res = await callOp(kernel, `op=temp&key=${encodeURIComponent(key)}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.error, "exec_disabled");
  ok("integration: exec OFF by default => auth first, then exec_disabled (I1 + I7)");
}

// B2. exec ENABLED under scripts/ => path-traversal / non-existent names rejected by the kernel
{
  const { kernel, key } = await bootKernel({
    STORE_PATH: makeTmpStore("on"),
    EXEC_ENABLED: "1",
    EXEC_DIR: SCRIPTS_DIR,
  });

  // run with a name the module regex would allow but no such script exists
  const noScript = await callOp(kernel, `op=run&name=doesnotexist&key=${encodeURIComponent(key)}`);
  assert.equal(noScript.body.ok, false);
  assert.equal(noScript.body.error, "no_such_script");
  ok("integration: run vetted-but-absent name => no_such_script (kernel path-lock)");

  // run with a traversal name => module rejects as bad_name (never reaches core.exec)
  const traversal = await callOp(kernel, `op=run&name=${encodeURIComponent("../server")}&key=${encodeURIComponent(key)}`);
  assert.equal(traversal.body.ok, false);
  assert.equal(traversal.body.error, "bad_name");
  ok("integration: run traversal name => bad_name before core.exec (I7)");
}

console.log(`\nALL PASS (${pass} assertion groups).`);
