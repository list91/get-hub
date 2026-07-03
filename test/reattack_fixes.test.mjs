/**
 * Regression tests for the two bypasses that survived the FIRST remediation and were caught by
 * the adversarial re-attack workflow (run w8acdbbov). Both fixes live in the kernel (modules stay
 * policy-free); these tests attempt the exact working exploit and assert it now FAILS.
 *
 *  1. control-rotate CROSS-SURFACE CAPABILITY CAPTURE (CRITICAL):
 *     an evil module caches the PRIVILEGED core it receives in start() into a module-scope
 *     closure, then its (public) handle() calls the captured control.rotate(["door-key"],{},null)
 *     to mint + exfiltrate the raw door-key. FIX: the module-facing control.rotate coerces a
 *     null assertion to a non-operator identity, so a captured rotate can never self-authorize.
 *
 *  2. envFor PREFIX-CONTAINMENT collision (HIGH):
 *     envFor selects env keys by k.startsWith("NAME_"), so module "git" (GIT_*) swallows module
 *     "git-hub"'s GIT_HUB_TOKEN. The old guard only rejected EXACT normalized twins. FIX: the
 *     loader rejects any two modules whose env prefixes are in a prefix relationship.
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
const PING = path.join(__dirname, "..", "modules", "ping.mjs");

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gethub-${tag}-`));
}

// ── 1. Cross-surface capability capture must NOT yield the door-key ──────────────
test("control: evil module capturing privileged core in start() cannot mint/exfil door-key from handle()", async () => {
  const dir = tmpDir("capture");
  fs.copyFileSync(PING, path.join(dir, "ping.mjs"));
  // The exact exploit shape the re-attack proved: cache the privileged rotate in a closure via
  // start(), then invoke it from a PUBLIC handle() with a null (would-be CLI) assertion.
  fs.writeFileSync(path.join(dir, "evil.mjs"), `
    let mint = null;
    export default {
      name: "pwn",
      public: true,
      match(ctx) { return ctx.op === "pwn"; },
      async start(core) { const c = core["con" + "trol"]; mint = c["rot" + "ate"].bind(c); },
      async handle(ctx) {
        const r = await mint(["door-key"], {}, null);   // try to self-authorize as the CLI
        return { ok: true, minted: r && r._doorKey ? r._doorKey : null, raw: r };
      },
    };
  `);

  const env = { ...process.env, STORE_PATH: path.join(dir, `.store-${crypto.randomBytes(4).toString("hex")}.json`) };
  const cfg = loadConfig(env);
  const modules = await loadModules(dir);
  const kernel = createKernel(cfg, modules);
  await kernel.boot(); // runs evil.start() → caches the privileged core

  // an operator (host CLI) mints a real door-key so there IS one to steal
  const res = await kernel.control.rotate(["door-key"], {});
  const doorKey = res._doorKey;
  assert.ok(doorKey && doorKey.startsWith("bridge-"), "a real door-key exists in the store");

  // anonymous public GET reaches the evil handle()
  const r = await kernel.handleRequest({ url: "/?op=pwn", method: "GET" });
  assert.equal(r.status, 200);
  // the captured rotate was refused → no minted key handed back
  assert.equal(r.body.minted, null, "handle() must NOT receive a minted door-key");
  assert.equal(r.body.raw && r.body.raw.error, "not_operator", "kernel refuses the null-assertion self-auth");
  // and the LIVE door-key value never appears anywhere in the response
  assert.ok(!JSON.stringify(r.body).includes(doorKey), "door-key value must never reach the client");
});

// ── 2. env-namespace prefix-containment collision must be rejected at load ────────
// fname is explicit so distinct module NAMES that would sanitize to the same filename
// (e.g. "secure-echo"/"secure_echo") don't clobber each other on disk.
function writeMinModule(dir, name, fname) {
  fs.writeFileSync(path.join(dir, `${fname}.mjs`), `
    export default { name: "${name}", public: true, match(c){return c.op==="${name}";}, async handle(){return {ok:true};} };
  `);
}

test("loadModules: 'git' + 'git-hub' rejected — GIT_* would swallow GIT_HUB_* (I6 containment)", async () => {
  const dir = tmpDir("envcontain");
  writeMinModule(dir, "git", "m_git");
  writeMinModule(dir, "git-hub", "m_githyphenhub");
  await assert.rejects(loadModules(dir), /collision/i, "prefix-containment must be rejected at load");
});

test("loadModules: exact normalized twins 'secure-echo' + 'secure_echo' still rejected (I6)", async () => {
  const dir = tmpDir("envtwin");
  writeMinModule(dir, "secure-echo", "m_secure_hyphen");
  writeMinModule(dir, "secure_echo", "m_secure_under");
  await assert.rejects(loadModules(dir), /collision/i, "twin collision must be rejected at load");
});

test("loadModules: non-colliding siblings 'git' + 'github' load fine (GITHUB_ !startsWith GIT_)", async () => {
  const dir = tmpDir("envok");
  writeMinModule(dir, "git", "m_git");
  writeMinModule(dir, "github", "m_github");
  const mods = await loadModules(dir);
  assert.equal(mods.length, 2, "GIT_ and GITHUB_ are not in a prefix relationship — both load");
});

// ── EXTERNAL (fetch-only attacker) hardening — must hold regardless of module trust ──────────

// 3. SSRF: IPv6 embedded-IPv4 families, incl. the SIIT/RFC6052 translated form ::ffff:0:a.b.c.d
//    (hextet[4]=0xffff) that slipped the earlier top-6-zero check.
test("isBlockedIp: IPv6 embedded-IPv4 internal targets blocked across mapped/compatible/translated", () => {
  const b = _internals.isBlockedIp;
  for (const ip of [
    "::ffff:0:169.254.169.254", // SIIT translated metadata — the bypass
    "::ffff:0:127.0.0.1",       // SIIT loopback
    "::ffff:0:10.0.0.1",        // SIIT private
    "::ffff:169.254.169.254",   // mapped metadata
    "::169.254.169.254",        // compatible metadata
  ]) assert.equal(b(ip), true, `${ip} must be blocked (internal via IPv6-embedded v4)`);

  for (const ip of [
    "::ffff:0:8.8.8.8",         // SIIT PUBLIC — must NOT over-block
    "2606:4700:4700::1111",     // real public v6
  ]) assert.equal(b(ip), false, `${ip} is public — must NOT be blocked`);
});

// 4. Secret scrub: the telegram module builds the URL via encodeURIComponent(token), so ':' →
//    '%3A'. The scrub must redact both the raw-colon and percent-encoded forms.
test("scrub: telegram bot-token redacted in both raw ':' and percent-encoded '%3A' URL forms", () => {
  const token = "123456789:AAEabcdefghijklmnopqrstuvwxyz0123456789";
  const raw = `https://api.telegram.org/bot${token}/getUpdates`;
  const enc = `https://api.telegram.org/bot${encodeURIComponent(token)}/getUpdates`;
  const secretHalf = "AAEabcdefghijklmnopqrstuvwxyz0123456789";
  assert.ok(!_internals.scrub(raw).includes(secretHalf), "raw-colon token must be scrubbed");
  assert.ok(!_internals.scrub(enc).includes(secretHalf), "percent-encoded (%3A) token must be scrubbed");
});

// ── DEPLOY blockers caught by the blind Pi deploy (must not regress) ─────────────────────

// 5. boot() must NOT await a never-returning start() — a background daemon (telegram long-poll)
//    that never resolves would otherwise hang boot() and the HTTP listener would never bind.
test("boot: a module whose start() never resolves does not block boot()", async () => {
  const dir = tmpDir("bootblock");
  fs.copyFileSync(PING, path.join(dir, "ping.mjs"));
  // start() never returns (like a real long-poll loop); if boot() awaited it, this test would hang.
  fs.writeFileSync(path.join(dir, "daemon.mjs"), `
    export default {
      name: "daemon",
      // background-only: no handle → not a data-plane vector
      start(core) { return new Promise(() => {}); },   // never resolves
    };
  `);
  const env = { ...process.env, STORE_PATH: path.join(dir, `.store-${crypto.randomBytes(4).toString("hex")}.json`) };
  const cfg = loadConfig(env);
  const modules = await loadModules(dir);
  const kernel = createKernel(cfg, modules);
  // A 2s watchdog turns a hang (regression) into a clear failure instead of a stuck test.
  const guard = new Promise((_, rej) => setTimeout(() => rej(new Error("boot() hung on start()")), 2000));
  await Promise.race([kernel.boot(), guard]);
  // boot returned → server would proceed to listen(); public op still answers
  const r = await kernel.handleRequest({ url: "/?op=ping", method: "GET" });
  assert.equal(r.status, 200, "kernel serves after boot despite a never-returning daemon start()");
});

// 6. server.mjs loadDotEnv: tolerant parse the blind deploy needed — inline "# comment" stripped,
//    quotes honored, blank/#-lines skipped, real env NOT overridden. (Blocker 1+2 root fix.)
test("loadDotEnv: strips inline comments, honors quotes, never overrides real env", async () => {
  const { loadDotEnv } = await import("../server.mjs");
  const dir = tmpDir("dotenv");
  const envFile = path.join(dir, ".env");
  fs.writeFileSync(envFile,
    "# a full-line comment\n" +
    "\n" +
    "PORT=8788                 # inline comment must be stripped\n" +
    "KEY_TTL_SEC=3600\n" +
    'ALLOW_HOSTS="api.github.com api.telegram.org"\n' +
    "TELEGRAM_TOKEN=\n" +           // genuinely empty — must stay empty (not a comment string)
    "GH_ALREADY_SET=fromfile\n" +
    "bad line without equals\n"
  );
  const save = { ...process.env };
  try {
    process.env.GH_ALREADY_SET = "fromenv"; // real env must win
    delete process.env.PORT; delete process.env.KEY_TTL_SEC;
    delete process.env.ALLOW_HOSTS; delete process.env.TELEGRAM_TOKEN;
    loadDotEnv(envFile);
    assert.equal(process.env.PORT, "8788", "inline # comment stripped from unquoted value");
    assert.equal(process.env.KEY_TTL_SEC, "3600");
    assert.equal(process.env.ALLOW_HOSTS, "api.github.com api.telegram.org", "quoted multi-word value kept literal, no # confusion");
    assert.equal(process.env.TELEGRAM_TOKEN, "", "empty value stays EMPTY — telegram daemon must stay off (Blocker 1)");
    assert.equal(process.env.GH_ALREADY_SET, "fromenv", "real env is never overridden");
  } finally {
    for (const k of ["PORT", "KEY_TTL_SEC", "ALLOW_HOSTS", "TELEGRAM_TOKEN", "GH_ALREADY_SET"]) {
      if (k in save) process.env[k] = save[k]; else delete process.env[k];
    }
  }
});
