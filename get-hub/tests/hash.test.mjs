/**
 * Unit test for modules/hash.mjs — the compute-class worked example.
 *
 *   node --test tests/hash.test.mjs
 *
 * Zero deps: node:test + node:assert + node:crypto (built-ins). Tests the module in
 * isolation — no kernel, no server — by calling match/handle with hand-built ctx objects
 * exactly as the kernel would (params already stripped of sig/key; core:null in match).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import hash from "../modules/hash.mjs";

// A handle-time ctx: only ctx.params matters for this module (no core/env/host used).
const ctx = (params) => ({
  op: "hash", params, method: "GET", url: new URL("http://x/?op=hash"),
  host: null, headers: {}, env: {}, core: null,
});

test("contract shape: name/public + pure match, has handle", () => {
  assert.equal(hash.name, "hash");
  assert.match(hash.name, /^[a-z0-9_-]+$/);
  assert.equal(hash.public, false); // protected
  assert.equal(typeof hash.match, "function");
  assert.equal(typeof hash.handle, "function");
  // no control/background surfaces — pure data plane
  assert.equal(hash.rotate, undefined);
  assert.equal(hash.start, undefined);
});

test("match is pure/sync and claims only op=hash", () => {
  assert.equal(hash.match({ op: "hash" }), true);
  assert.equal(hash.match({ op: "ping" }), false);
  assert.equal(hash.match({ op: "" }), false);
  // match must not be async (I2): calling it returns a boolean, not a Promise.
  assert.equal(hash.match({ op: "hash" }) instanceof Promise, false);
});

test("hashes a known vector correctly (matches node:crypto)", async () => {
  const s = "hello";
  const expected = crypto.createHash("sha256").update(s, "utf8").digest("hex");
  const r = await hash.handle(ctx({ s }));
  assert.equal(r.ok, true);
  assert.equal(r.alg, "sha256");
  assert.equal(r.hex, expected);
  assert.equal(r.hex.length, 64);
  assert.equal(r.len, 5);
  // "hello" sha256 golden constant — independent cross-check.
  assert.equal(r.hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
});

test("empty string is a valid input (sha256 of '')", async () => {
  const r = await hash.handle(ctx({ s: "" }));
  assert.equal(r.ok, true);
  assert.equal(r.len, 0);
  assert.equal(r.hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("utf-8 multibyte is hashed by bytes, not code units", async () => {
  const s = "Привет"; // Cyrillic → 12 UTF-8 bytes, 6 JS chars
  const expected = crypto.createHash("sha256").update(s, "utf8").digest("hex");
  const r = await hash.handle(ctx({ s }));
  assert.equal(r.hex, expected);
  assert.equal(r.len, s.length); // len reports JS string length (chars), documented as such
});

test("missing s → safe error, no throw", async () => {
  assert.deepEqual(await hash.handle(ctx({})), { ok: false, error: "missing_s" });
  // non-string s (kernel params are strings, but be defensive) also rejected
  assert.deepEqual(await hash.handle(ctx({ s: 123 })), { ok: false, error: "missing_s" });
});

test("oversized input → capped, no DoS", async () => {
  const big = "a".repeat(1_000_001);
  assert.deepEqual(await hash.handle(ctx({ s: big })), { ok: false, error: "input_too_large" });
  // exactly at the cap is still accepted
  const atCap = "a".repeat(1_000_000);
  const r = await hash.handle(ctx({ s: atCap }));
  assert.equal(r.ok, true);
  assert.equal(r.len, 1_000_000);
});

test("handle touches no core capability (safe with core:null)", async () => {
  // ctx.core is null here; if the module tried core.* it would throw. It must not.
  const r = await hash.handle(ctx({ s: "x" }));
  assert.equal(r.ok, true);
});
