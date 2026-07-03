#!/usr/bin/env node
/**
 * lint.test.mjs — corner-case suite for the build-gate module linter (SPEC §6.1 / I11).
 *
 * The linter is itself part of the security gate: a FALSE NEGATIVE here (a bad module the
 * linter fails to catch) is a build blocker, because such a module would ship. So this suite
 * feeds the linter DELIBERATELY BAD sample modules — path-traversal names, unicode homoglyph
 * hosts, aliased imports, re-export tricks, dynamic import(), process.env bypass, exec shell
 * strings / client paths — and asserts the linter catches EACH (with the right rule).
 *
 * It also asserts the linter does NOT false-POSITIVE: every real module in modules/ passes,
 * and a set of KNOWN-GOOD sample shapes (node:crypto compute, telegram-style start-only,
 * validated exec name) stay clean.
 *
 * Run:  node lint.test.mjs      (exit 0 = every probe caught + every good module clean)
 * Zero deps: node:assert + the linter's exported lintSource / lintDir.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lintSource, lintDir } from "./lint.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

let pass = 0, fail = 0;
function test(name, fn) {
  try { fn(); console.log("ok   -", name); pass++; }
  catch (e) { console.error("FAIL -", name, "\n      ", e.message); fail++; process.exitCode = 1; }
}

// Assert the linter produced at least one finding of the given rule for `src`.
function expectCaught(name, src, rule) {
  test(name, () => {
    const f = lintSource(src, name + ".mjs");
    const rules = f.map((x) => x.rule);
    assert.ok(
      f.length > 0,
      `expected a finding but got NONE (false negative!). This bad module would SHIP.`
    );
    if (rule) {
      assert.ok(
        rules.includes(rule),
        `expected rule ${rule} but got [${rules.join(",")}]  msgs: ${f.map((x) => x.msg).join(" | ")}`
      );
    }
  });
}

// Assert the linter produced ZERO findings for `src` (known-good shape).
function expectClean(name, src) {
  test(name, () => {
    const f = lintSource(src, name + ".mjs");
    assert.equal(
      f.length, 0,
      `expected CLEAN but got findings (false positive): ${f.map((x) => `[${x.rule}] ${x.msg}`).join(" | ")}`
    );
  });
}

// A minimal valid module scaffold we mutate per probe.
const GOOD = `export default {
  name: "good",
  public: false,
  match(ctx) { return ctx.op === "good"; },
  async handle(ctx) { return { ok: true }; },
};`;

// ─────────────────────────────────────────────────────────────────────────────
// SANITY: the good scaffold and all real modules are clean.
// ─────────────────────────────────────────────────────────────────────────────
expectClean("sanity_good_scaffold", GOOD);

test("all real modules pass (no false positives on the shipping set)", () => {
  const { files, findings } = lintDir(path.join(here, "modules"));
  assert.ok(files.length >= 10, `expected the real module set, got ${files.length} files`);
  assert.equal(
    findings.length, 0,
    `real modules must be clean but linter flagged: ${findings.map((x) => `${x.file}[${x.rule}]:${x.msg}`).join(" | ")}`
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// L1 — banned outside-world imports (I3). Every disguise must be caught.
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L1_plain_fs", `import fs from "node:fs";
export default { name:"a", public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

expectCaught("L1_bare_fs_no_prefix", `import fs from "fs";
export default { name:"a", public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

// aliased import — the classic obfuscation (`import cp from ...`)
expectCaught("L1_aliased_child_process", `import cp from "node:child_process";
export default { name:"a", public:false, match(c){return c.op==="a";}, async handle(){ cp.spawn("x"); return{ok:1};} };`, "L1");

// namespace import
expectCaught("L1_namespace_net", `import * as net from "node:net";
export default { name:"a", public:false, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

// named import from banned module
expectCaught("L1_named_from_fs_promises", `import { readFile } from "node:fs/promises";
export default { name:"a", public:false, match(c){return c.op==="a";}, async handle(){ await readFile("/etc/passwd"); return{ok:1};} };`, "L1");

// side-effect import
expectCaught("L1_side_effect_http", `import "node:http";
export default { name:"a", public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

// re-export trick: `export ... from "node:fs"`
expectCaught("L1_reexport_fs", `export { readFileSync } from "node:fs";
export default { name:"a", public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

expectCaught("L1_reexport_star_net", `export * from "node:net";
export default { name:"a", public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

// dynamic import with a string literal
expectCaught("L1_dynamic_import_literal", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const fs = await import("node:fs"); return { ok: !!fs }; } };`, "L1");

// dynamic import with a COMPUTED specifier (concatenation to dodge the string scan)
expectCaught("L1_dynamic_import_computed", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const m = await import("node:"+"fs"); return { ok:!!m }; } };`, "L1");

// require() of a banned module (CJS interop escape)
expectCaught("L1_require_child_process", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const cp = require("child_process"); cp.exec("id"); return {ok:1}; } };`, "L1");

// createRequire escape hatch
expectCaught("L1_createRequire", `import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
export default { name:"a", public:false, match(c){return c.op==="a";},
  async handle(){ const fs = require("fs"); return {ok:!!fs}; } };`, "L1");

// unicode homoglyph in the import specifier (Cyrillic 'с' in "node:сhild_process")
expectCaught("L1_homoglyph_specifier", `import x from "node:сhild_process";
export default { name:"a", public:false, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

// process.binding native escape
expectCaught("L1_process_binding", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const fs = process.binding("fs"); return {ok:!!fs}; } };`, "L1");

// dns is outside-world too
expectCaught("L1_dns", `import dns from "node:dns";
export default { name:"a", public:false, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L1");

// ─────────────────────────────────────────────────────────────────────────────
// L1 false-positive guards: node:crypto and banned WORDS in comments/strings are OK.
// ─────────────────────────────────────────────────────────────────────────────
expectClean("L1_crypto_allowed", `import crypto from "node:crypto";
export default { name:"a", public:false, match(c){return c.op==="a";},
  async handle(c){ return { ok:true, h: crypto.createHash("sha256").update(c.params.s||"").digest("hex") }; } };`);

// a banned token that appears ONLY in a comment or string must NOT trip L1.
expectClean("L1_banned_word_in_comment_only", `// this module does not import node:child_process or node:fs, promise.
export default { name:"a", public:true, match(c){return c.op==="a";},
  async handle(){ return { ok:true, note:"we never touch require('fs') here — it's just text" }; } };`);

// ─────────────────────────────────────────────────────────────────────────────
// L2 — impure / async match (I2).
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L2_match_await", `export default { name:"a", public:false,
  async match(c){ return await Promise.resolve(c.op==="a"); },
  async handle(){return{ok:1};} };`, "L2");

expectCaught("L2_match_references_core", `export default { name:"a", public:false,
  match(c){ return c.op==="a" && !!c.core.store.get("x"); },
  async handle(){return{ok:1};} };`, "L2");

expectCaught("L2_match_does_io_fetch", `export default { name:"a", public:false,
  match(c){ fetch("https://x"); return c.op==="a"; },
  async handle(){return{ok:1};} };`, "L2");

expectCaught("L2_match_dynamic_import", `export default { name:"a", public:false,
  match(c){ import("node:fs"); return c.op==="a"; },
  async handle(){return{ok:1};} };`, "L2");

expectCaught("L2_match_math_random", `export default { name:"a", public:false,
  match(c){ return c.op==="a" && Math.random() > 0.5; },
  async handle(){return{ok:1};} };`, "L2");

expectCaught("L2_match_clock", `export default { name:"a", public:false,
  match(c){ return c.op==="a" && Date.now() % 2 === 0; },
  async handle(){return{ok:1};} };`, "L2");

// arrow-form match with core reference must also be caught
expectCaught("L2_arrow_match_core", `export default { name:"a", public:false,
  match: (c) => c.op==="a" && c.core.proxy,
  async handle(){return{ok:1};} };`, "L2");

// clean: a normal pure match must NOT trip L2 (guard against over-eager purity check).
expectClean("L2_pure_match_ok", `export default { name:"a", public:false,
  match(ctx){ return ctx.op === "a" && ctx.host === "api.github.com"; },
  async handle(){return{ok:1};} };`);

// clean: single-expression arrow match is fine.
expectClean("L2_arrow_expr_match_ok", `export default { name:"a", public:true,
  match: (ctx) => ctx.op === "a",
  async handle(){return{ok:1};} };`);

// ─────────────────────────────────────────────────────────────────────────────
// L3 — process.env bypass (I6).
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L3_process_env_dot", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ return { ok:true, t: process.env.SECRET }; } };`, "L3");

expectCaught("L3_process_env_bracket", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const k="env"; return { ok:true, t: process["env"].SECRET }; } };`, "L3");

// clean: reading ctx.env / core.env is the CORRECT way — must not trip L3.
expectClean("L3_ctx_env_ok", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return { ok:true, v: ctx.env.TOKEN ? "set" : "unset" }; } };`);

// clean: the word "process.env" inside a comment must not trip L3.
expectClean("L3_process_env_in_comment", `export default { name:"a", public:true,
  // never read process.env directly — use ctx.env instead
  match(c){return c.op==="a";},
  async handle(ctx){ return { ok:true }; } };`);

// ─────────────────────────────────────────────────────────────────────────────
// L4 — name: missing / duplicate / bad charset / path traversal / homoglyph.
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L4_missing_name", `export default { public:true,
  match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

expectCaught("L4_path_traversal_name", `export default { name:"../evil",
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

expectCaught("L4_slash_name", `export default { name:"a/b",
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

expectCaught("L4_uppercase_name", `export default { name:"MyMod",
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

expectCaught("L4_space_name", `export default { name:"my mod",
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

expectCaught("L4_empty_name", `export default { name:"",
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

// unicode homoglyph name: Cyrillic 'а' looks like ASCII 'a' but is U+0430.
expectCaught("L4_homoglyph_name", `export default { name:"аdmin",
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

// name that is not a static literal (a variable) — unresolvable, reject.
expectCaught("L4_dynamic_name", `const n = "x"; export default { name: n,
  public:true, match(c){return c.op==="a";}, async handle(){return{ok:1};} };`, "L4");

// duplicate name across files — a DIR-level check. Exercise the real lintDir uniqueness path
// against a throwaway temp dir of two individually-clean modules that share a name.
test("L4_duplicate_name_across_files", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gethub-lint-dup-"));
  try {
    const modA = `export default { name:"dup", public:true,
      match(c){return c.op==="a";}, async handle(){return{ok:1};} };`;
    const modB = `export default { name:"dup", public:true,
      match(c){return c.op==="b";}, async handle(){return{ok:2};} };`;
    fs.writeFileSync(path.join(tmp, "a.mjs"), modA);
    fs.writeFileSync(path.join(tmp, "b.mjs"), modB);
    // a leading-underscore helper and a *.test.mjs must be EXCLUDED from the scan.
    fs.writeFileSync(path.join(tmp, "_helper.mjs"), `export const X = 1;`);
    fs.writeFileSync(path.join(tmp, "a.test.mjs"), `import "./a.mjs";`);

    const { files, findings } = lintDir(tmp);
    assert.deepEqual(files, ["a.mjs", "b.mjs"], `scan set must exclude _* and *.test.mjs, got ${files.join(",")}`);
    const dup = findings.filter((x) => x.rule === "L4" && /duplicate module name/.test(x.msg));
    assert.equal(dup.length, 1, `expected exactly one duplicate-name finding, got ${dup.length}: ${findings.map(f=>f.msg).join(" | ")}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// L5 — dead module (no handle AND no rotate/start).
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L5_dead_no_surfaces", `export default { name:"a", public:false,
  match(c){return c.op==="a";} };`, "L5");

expectCaught("L5_dead_public_no_handle", `export default { name:"a", public:true,
  match(c){return c.op==="a";} };`, "L5");

// clean: start-only module (telegram shape) is NOT dead.
expectClean("L5_start_only_ok", `export default { name:"tg", public:false,
  async start(core){ /* long poll */ } };`);

// clean: rotate-only module is NOT dead.
expectClean("L5_rotate_only_ok", `export default { name:"rot", public:false,
  async rotate({ttl, core}){ core.store.set("token","x",ttl); return { minted:true }; } };`);

// ─────────────────────────────────────────────────────────────────────────────
// L6 — exec misuse: shell string / client-supplied path / template / concat (I7).
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L6_exec_shell_string", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec("bash -c whoami", []); } };`, "L6");

expectCaught("L6_exec_path", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec("/usr/bin/id", []); } };`, "L6");

expectCaught("L6_exec_traversal_path", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec("../../bin/sh", []); } };`, "L6");

expectCaught("L6_exec_template_literal", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ const s=ctx.params.s; return ctx.core.exec(\`run-\${s}\`, []); } };`, "L6");

expectCaught("L6_exec_concat_command", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec("cmd-" + ctx.params.x, []); } };`, "L6");

expectCaught("L6_exec_client_path_param", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec(ctx.params.path, []); } };`, "L6");

expectCaught("L6_exec_client_cmd_param", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec(ctx.params.cmd, []); } };`, "L6");

// direct child_process spawn call (even if the import somehow evaded us) — catch the CALL.
expectCaught("L6_direct_spawn_call", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ spawn("id", []); return {ok:1}; } };`, "L6");

expectCaught("L6_shell_true_option", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(ctx){ return ctx.core.exec("safe", { shell:true }); } };`, "L6");

// clean: a vetted NAME literal is fine.
expectClean("L6_exec_vetted_literal_ok", `export default { name:"temp", public:false,
  match(c){return c.op==="temp";},
  async handle(ctx){ return ctx.core.exec("temp", []); } };`);

// clean: a VALIDATED variable name (run.mjs pattern) is allowed — client passes a name that
// the module regex-validates; we don't statically reject a bare identifier.
expectClean("L6_exec_validated_var_ok", `const RE=/^[a-z0-9_-]+$/;
export default { name:"run", public:false,
  match(c){return c.op==="run";},
  async handle(ctx){ const name=ctx.params.name; if(!RE.test(name)) return {ok:false};
    return ctx.core.exec(name, []); } };`);

// ─────────────────────────────────────────────────────────────────────────────
// L1 (smuggling) — builtin-smuggling escape hatches the earlier linter missed (I3).
// Red-team: each of these bypassed the import/require scan; the build gate must now FAIL them.
// ─────────────────────────────────────────────────────────────────────────────
// process.getBuiltinModule('fs'|'child_process'|'net') — runtime handle to a banned builtin.
expectCaught("L1_getBuiltinModule_fs", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const fs = process.getBuiltinModule("fs"); return { ok:!!fs }; } };`, "L1");

expectCaught("L1_getBuiltinModule_cp", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const cp = process.getBuiltinModule("child_process"); cp.execSync("id"); return {ok:1}; } };`, "L1");

// Function-constructor dynamic import: (async()=>{}).constructor('s','return import(s)')('node:fs')
expectCaught("L1_function_ctor_import", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const imp = (async()=>{}).constructor('s','return import(s)'); const fs = await imp('node:fs'); return {ok:!!fs}; } };`, "L1");

// new Function('return import("node:child_process")')
expectCaught("L1_new_function_import", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const f = new Function('return import("node:child_process")'); return { ok: !!f }; } };`, "L1");

// comment-interrupted static import: import cp /*x*/ from /*y*/ "node:child_process"
expectCaught("L1_comment_interrupted_import", `import cp /*x*/ from /*y*/ "node:child_process";
export default { name:"a", public:false, match(c){return c.op==="a";}, async handle(){ cp.spawn("x"); return {ok:1}; } };`, "L1");

// dotted child_process API call via a smuggled handle: cp.execSync(...)
expectCaught("L1_dotted_execSync_call", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ const cp = globalThis.__cp; return { out: cp.execSync("id").toString() }; } };`, "L6");

// obfuscated process.env read: process['env'].SECRET  (literal "env" hid in a string)
expectCaught("L3_obfuscated_process_bracket_env", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ return { t: process['env'].SECRET }; } };`, "L3");

// globalThis.process.env chain
expectCaught("L3_globalthis_process_env", `export default { name:"a", public:false,
  match(c){return c.op==="a";},
  async handle(){ return { t: globalThis.process.env.SECRET }; } };`, "L3");

// clean guard: getBuiltinModule mentioned only in a comment must not false-positive.
expectClean("L1_getBuiltinModule_in_comment_ok", `export default { name:"a", public:true,
  // we never call process.getBuiltinModule here — ctx.core only
  match(c){return c.op==="a";}, async handle(){ return { ok:true }; } };`);

// ─────────────────────────────────────────────────────────────────────────────
// L2 (strengthened) — match() side effects (I2). Red-team: match must be pure.
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L2_match_store_write", `export default { name:"a", public:false,
  match(c){ c.core && c.core.store.set("x",1); return c.op==="a"; },
  async handle(){return{ok:1};} };`, "L2");

expectCaught("L2_match_new_promise", `export default { name:"a", public:false,
  match(c){ new Promise(r=>r()); return c.op==="a"; },
  async handle(){return{ok:1};} };`, "L2");

// ─────────────────────────────────────────────────────────────────────────────
// L7 — control plane (rotate) in the DATA plane handle() is forbidden (I12).
// Red-team: the exact exploit — a handle that rotates the door-key and exfiltrates it.
// ─────────────────────────────────────────────────────────────────────────────
expectCaught("L7_handle_calls_control_rotate", `export default { name:"evil", public:false,
  match(c){return c.op==="evil";},
  async handle(ctx){ const r = await ctx.core.control.rotate([],{}); return { leaked: r._doorKey }; } };`, "L7");

expectCaught("L7_public_handle_rotate", `export default { name:"evilpub", public:true,
  match(c){return c.op==="evilpub";},
  async handle(ctx){ return await ctx.core.control.rotate([],{}); } };`, "L7");

// clean: a rotate() surface (control plane) legitimately touches core.control — must NOT trip L7.
expectClean("L7_rotate_surface_ok", `export default { name:"tg", public:false,
  async start(core){ await core.control.rotate(["door"],{}); } };`);

expectClean("L7_rotate_hook_ok", `export default { name:"rot", public:false,
  async rotate({ttl, core}){ core.store.set("token","x",ttl); return { minted:true }; } };`);

// ─────────────────────────────────────────────────────────────────────────────
// L4 (twin) — env-namespace '-'/'_' collision detected at DIR level (I6).
// Red-team: "secure-echo" and "secure_echo" would share the SAME env namespace.
// ─────────────────────────────────────────────────────────────────────────────
test("L4_env_namespace_twin_collision", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gethub-lint-twin-"));
  try {
    fs.writeFileSync(path.join(tmp, "a.mjs"), `export default { name:"secure-echo", public:false,
      match(c){return c.op==="se1";}, async handle(){return{ok:1};} };`);
    fs.writeFileSync(path.join(tmp, "b.mjs"), `export default { name:"secure_echo", public:false,
      match(c){return c.op==="se2";}, async handle(){return{ok:2};} };`);
    const { findings } = lintDir(tmp);
    const twin = findings.filter((x) => x.rule === "L4" && /env-namespace collision/.test(x.msg));
    assert.equal(twin.length, 1, `expected one env-twin finding, got ${twin.length}: ${findings.map(f=>f.msg).join(" | ")}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Combo probe: a module that stacks several violations at once — all must surface.
// ─────────────────────────────────────────────────────────────────────────────
test("combo_multi_violation", () => {
  const src = `import cp from "node:child_process";
export default { name:"../BAD name",
  public:false,
  async match(c){ return await c.core.store.get("x"); },
  async handle(ctx){ const t = process.env.SECRET; return ctx.core.exec("sh -c evil", []); } };`;
  const f = lintSource(src, "combo.mjs");
  const rules = new Set(f.map((x) => x.rule));
  for (const r of ["L1", "L2", "L3", "L4", "L6"]) {
    assert.ok(rules.has(r), `combo: expected ${r} in [${[...rules].join(",")}]`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\nlint.test: ${pass} passed, ${fail} failed.`);
if (fail > 0) {
  console.error("lint.test: FAILURES above — the linter has a false negative or false positive.");
  process.exit(1);
}
console.log("lint.test: all probes caught, all good modules clean.");
