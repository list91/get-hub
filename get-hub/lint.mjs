#!/usr/bin/env node
/**
 * lint.mjs — get-hub build-gate module linter (SPEC I11 / §6.1).
 *
 * A STATIC linter over every live module in modules/. It FAILS THE BUILD (process exit 1)
 * on any module that violates the frozen contract (SPEC §2 / §6.1 / modules/CONTRACT.md):
 *
 *   L1  direct import of node:child_process / node:fs / node:net / node:http(s) / node:dns
 *       for its work — must go through ctx.core. Catches aliased imports
 *       (`import cp from "node:child_process"`), namespace/side-effect imports,
 *       `require(...)`, dynamic `import(...)`, and `createRequire` escape hatches. (I3)
 *   L2  a match() that does I/O or references core / await (must be pure + sync). (I2)
 *   L3  reading process.env directly instead of ctx.env. (I6)
 *   L4  missing / duplicate name, or name not matching ^[a-z0-9_-]+$.
 *   L5  a non-public module with no handle AND no rotate/start (dead module).
 *   L6  exec used with a shell string or a client-supplied path (not a vetted name). (I7)
 *   L7  handle() (the data plane) referencing the operator-only control plane
 *       (`core.control` / `.rotate(`) — rotate is unreachable from a client GET. (I12)
 *
 * ZERO runtime deps (Node >=18 built-ins only). Pure static analysis — this linter does NOT
 * import or execute the modules it lints (an unvetted module must never run just to be checked).
 *
 * The analysis is deliberately CONSERVATIVE: it works on a comment/string-stripped view of the
 * source so a banned token hidden in a comment does not false-positive, AND so an aliased or
 * obfuscated banned import cannot false-negative. A false negative here is a build blocker
 * (a bad module shipping), so every ambiguous case is treated as a violation.
 *
 * Usage:
 *   node lint.mjs                 # lint the default modules/ dir; exit 1 on any finding
 *   node lint.mjs <dir>           # lint an arbitrary dir of *.mjs modules
 *   node lint.mjs --json          # machine-readable report on stdout
 *
 * Programmatic:
 *   import { lintSource, lintDir } from "./lint.mjs";
 *   const findings = lintSource(src, "github.mjs");   // [] === clean
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ── The banned node builtins a module must NOT import for its work (I3). ─────────────────
// node:crypto is INTENTIONALLY ABSENT — it is pure in-process compute (hashing, JWT signing)
// and is explicitly allowed (hash.mjs, github.mjs). The ban is about the OUTSIDE WORLD:
// spawning, the filesystem, raw sockets, outbound http, and DNS resolution.
const BANNED_MODULES = new Set([
  "child_process",
  "fs",
  "fs/promises",
  "net",
  "tls",
  "dgram",
  "http",
  "https",
  "http2",
  "dns",
  "dns/promises",
  "inspector",
  "worker_threads",
  "cluster",
  "v8",
  "vm",
  "repl",
]);

// A module specifier is banned if — after stripping a leading "node:" and any subpath — its
// base names a banned core module. This normalizes "node:fs", "fs", "node:fs/promises",
// "fs/promises" all to the same decision. Bare "fs" (no node: prefix) is still a core import
// in ESM only via the resolver, but we ban it regardless: no legitimate module needs it.
function isBannedSpecifier(raw) {
  if (typeof raw !== "string") return false;
  let s = raw.trim();
  // strip surrounding quotes if a raw token was captured with them
  s = s.replace(/^['"`]|['"`]$/g, "");
  if (s.startsWith("node:")) s = s.slice(5);
  // normalize case; core module names are ascii-lower
  const lower = s.toLowerCase();
  if (BANNED_MODULES.has(lower)) return true;
  // subpath forms: "fs/promises", "dns/promises", "child_process/..." — check the head too
  const head = lower.split("/")[0];
  if (BANNED_MODULES.has(head)) return true;
  // full "fs/promises" style already covered; also block explicit "node:fs" head
  return false;
}

// ── Strip comments and string/template/regex literals to a neutralized view. ─────────────
// This gives us a source where a banned word in a comment or string can't cause a false
// positive, and (crucially) where we can't be fooled into MISSING real code by a token that
// merely LOOKS like it's inside a string. We replace string/comment CONTENT with spaces but
// KEEP structural quotes/positions so import-specifier extraction below can still read the
// literal — so we run specifier extraction on the RAW source and everything-else analysis on
// the STRIPPED source.
function stripCommentsAndStrings(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  let state = "code"; // code | line | block | sq | dq | tpl | regex
  let prev = ""; // last significant non-space code char, for regex disambiguation
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (state === "code") {
      if (c === "/" && c2 === "/") { state = "line"; out += "  "; i += 2; continue; }
      if (c === "/" && c2 === "*") { state = "block"; out += "  "; i += 2; continue; }
      if (c === "'") { state = "sq"; out += " "; i++; continue; }
      if (c === '"') { state = "dq"; out += " "; i++; continue; }
      if (c === "`") { state = "tpl"; out += " "; i++; continue; }
      // regex literal: a '/' that begins a regex (previous significant char permits it)
      if (c === "/" && regexAllowedAfter(prev)) { state = "regex"; out += " "; i++; continue; }
      out += c;
      if (!/\s/.test(c)) prev = c;
      i++;
      continue;
    }
    if (state === "line") {
      if (c === "\n") { state = "code"; out += "\n"; i++; continue; }
      out += c === "\t" ? "\t" : " "; i++; continue;
    }
    if (state === "block") {
      if (c === "*" && c2 === "/") { state = "code"; out += "  "; i += 2; continue; }
      out += c === "\n" ? "\n" : " "; i++; continue;
    }
    if (state === "sq" || state === "dq") {
      const q = state === "sq" ? "'" : '"';
      if (c === "\\") { out += "  "; i += 2; continue; }
      if (c === q) { state = "code"; out += " "; prev = q; i++; continue; }
      out += c === "\n" ? "\n" : " "; i++; continue;
    }
    if (state === "tpl") {
      if (c === "\\") { out += "  "; i += 2; continue; }
      if (c === "`") { state = "code"; out += " "; prev = "`"; i++; continue; }
      // NOTE: we do not fully parse ${...} interpolation; its content is treated as string
      // text (neutralized). That is conservative and safe for our checks.
      out += c === "\n" ? "\n" : " "; i++; continue;
    }
    if (state === "regex") {
      if (c === "\\") { out += "  "; i += 2; continue; }
      if (c === "\n") { state = "code"; out += "\n"; i++; continue; } // unterminated → bail
      if (c === "/") { state = "code"; out += " "; prev = "/"; i++; continue; }
      out += " "; i++; continue;
    }
  }
  return out;
}

// Strip ONLY comments (line + block) from source, preserving string literals and their quotes.
// Used so a comment interrupting an `import … from "x"` statement (a real code token split by a
// `/*…*/`) cannot hide the specifier from the static import extractor. Replaces comment bytes
// with spaces to keep offsets 1:1 with the original.
function stripCommentsOnly(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  let state = "code"; // code | line | block | sq | dq | tpl
  while (i < n) {
    const c = src[i], c2 = src[i + 1];
    if (state === "code") {
      if (c === "/" && c2 === "/") { state = "line"; out += "  "; i += 2; continue; }
      if (c === "/" && c2 === "*") { state = "block"; out += "  "; i += 2; continue; }
      if (c === "'") { state = "sq"; out += c; i++; continue; }
      if (c === '"') { state = "dq"; out += c; i++; continue; }
      if (c === "`") { state = "tpl"; out += c; i++; continue; }
      out += c; i++; continue;
    }
    if (state === "line") { if (c === "\n") { state = "code"; out += "\n"; } else out += c === "\t" ? "\t" : " "; i++; continue; }
    if (state === "block") { if (c === "*" && c2 === "/") { state = "code"; out += "  "; i += 2; continue; } out += c === "\n" ? "\n" : " "; i++; continue; }
    // inside a string: copy verbatim (including escapes) so specifiers survive intact
    if (state === "sq" || state === "dq") {
      const q = state === "sq" ? "'" : '"';
      if (c === "\\") { out += src[i] + (src[i + 1] || ""); i += 2; continue; }
      if (c === q) { state = "code"; }
      out += c; i++; continue;
    }
    if (state === "tpl") { if (c === "\\") { out += src[i] + (src[i + 1] || ""); i += 2; continue; } if (c === "`") state = "code"; out += c; i++; continue; }
  }
  return out;
}

// Heuristic: can a '/' at this point start a regex? (vs be a division operator)
function regexAllowedAfter(prev) {
  if (!prev) return true;
  // after these, '/' is division, not a regex
  if (/[)\]}A-Za-z0-9_$]/.test(prev)) return false;
  return true;
}

// ── Import / require / dynamic-import specifier extraction. ───────────────────────────────
// Returns array of { spec, kind, index } for every module specifier the file pulls in.
// Catches: static `import ... from "x"`, side-effect `import "x"`, `export ... from "x"`,
// dynamic `import("x")`, `require("x")`, `createRequire(...)("x")`.
//
// STATIC import/export forms are extracted from RAW (they are real code — an ESM import
// statement can never be nested inside a string literal, and we need the true specifier text
// to catch aliased/homoglyph specifiers). CALL forms (`require(...)`, dynamic `import(...)`)
// are located on the STRIPPED source so a `require('fs')` that lives only inside a comment or
// a string does NOT false-positive; the literal specifier is then read back from RAW at the
// matched offset so we still see through to the real characters (homoglyphs, etc.).
function extractSpecifiers(raw, stripped) {
  const specs = [];
  const add = (spec, kind, index) => { if (spec != null) specs.push({ spec, kind, index }); };

  // static/side-effect/re-export: import ... from "x"  |  import "x"  |  export ... from "x"
  // Run over a COMMENT-STRIPPED-but-string-preserved view so a comment interrupting the statement
  // (`import cp /*x*/ from /*y*/ "node:child_process"`) cannot hide the specifier. Strings (the
  // specifier literal itself) are preserved intact; only comments become spaces.
  const rawNC = stripCommentsOnly(raw);
  const reFrom = /\b(?:import|export)\b[\s\S]*?\bfrom\s*(['"])([^'"]+)\1/g;
  for (let m; (m = reFrom.exec(rawNC)); ) add(m[2], "static", m.index);
  const reBareImport = /\bimport\s*(['"])([^'"]+)\1/g;
  for (let m; (m = reBareImport.exec(rawNC)); ) add(m[2], "side-effect", m.index);

  // Read the parenthesized argument of a call whose "(" sits at `openIdx` in `stripped`,
  // returning the RAW text of that argument (so string content is preserved) and its literal
  // value if it is a single string literal. Positions align because stripping is 1:1 length.
  const readCallArg = (openIdx) => {
    const close = matchDelim(stripped, openIdx, "(", ")");
    if (close < 0) return null;
    const rawArg = raw.slice(openIdx + 1, close).trim();
    const lit = rawArg.match(/^(['"])([^'"]+)\1$/);
    return { rawArg, litVal: lit ? lit[2] : null };
  };

  // dynamic import(...) — detected on STRIPPED so string/comment occurrences are neutralized.
  const reDyn = /\bimport\s*\(/g;
  for (let m; (m = reDyn.exec(stripped)); ) {
    const openIdx = m.index + m[0].length - 1;
    const a = readCallArg(openIdx);
    if (!a) continue;
    if (a.litVal != null) add(a.litVal, "dynamic", m.index);
    else add({ __expr: a.rawArg }, "dynamic-expr", m.index);
  }

  // require(...) — detected on STRIPPED so a `require('fs')` in a string/comment is ignored.
  const reReq = /\brequire\s*\(/g;
  for (let m; (m = reReq.exec(stripped)); ) {
    const openIdx = m.index + m[0].length - 1;
    const a = readCallArg(openIdx);
    if (!a) continue;
    if (a.litVal != null) add(a.litVal, "require", m.index);
    else add({ __expr: a.rawArg }, "require-expr", m.index);
  }

  return specs;
}

// ── Locate the default-exported module object and slice out its match() body. ────────────
// Works on the STRIPPED source. Returns { hasDefault, matchBody, handlePresent, rotatePresent,
// startPresent, publicTrue, nameValue }. Best-effort structural parse (no full AST, zero-dep).
function analyzeShape(stripped, raw) {
  const res = {
    hasDefault: /\bexport\s+default\b/.test(stripped),
    matchBody: null,
    matchIsArrowExpr: false,
    handlePresent: false,
    rotatePresent: false,
    startPresent: false,
    publicTrue: false,
    nameValue: undefined,
    nameLiteralFound: false,
  };

  // name: "..."  — read from RAW so we get the actual string (stripped blanked it out).
  const nameM = raw.match(/\bname\s*:\s*(['"])([^'"]*)\1/);
  if (nameM) { res.nameValue = nameM[2]; res.nameLiteralFound = true; }
  // a non-literal name (name: someVar) — flag as present-but-unresolvable
  else if (/\bname\s*:/.test(stripped)) { res.nameValue = undefined; res.nameLiteralFound = false; res.nameDynamic = true; }

  // public: true
  res.publicTrue = /\bpublic\s*:\s*true\b/.test(stripped);

  // handle / rotate / start method or property presence (method shorthand OR `x: async? fn`).
  res.handlePresent = /\b(async\s+)?handle\s*(\(|:)/.test(stripped);
  res.rotatePresent = /\b(async\s+)?rotate\s*(\(|:)/.test(stripped);
  res.startPresent = /\b(async\s+)?start\s*(\(|:)/.test(stripped);

  // Extract match() body. Support method shorthand `match(ctx){...}`,
  // `match: (ctx) => {...}`, `match: (ctx) => expr`, `match: function(ctx){...}`.
  res.matchBody = extractMatchBody(stripped);
  if (res.matchBody && res.matchBody.arrowExpr) res.matchIsArrowExpr = true;
  // Extract handle() body (same forms) so we can forbid control-plane use in the data plane (I12).
  res.handleBody = extractNamedBody(stripped, "handle");
  return res;
}

// Extract the body text of a named method/property (handle/rotate/start) — same brace/arrow
// forms as match. Returns { body } or null. Used to scope data-plane-only rules (e.g. I12).
function extractNamedBody(stripped, kw) {
  const keyRe = new RegExp(`\\b${kw}\\s*(:\\s*(async\\s*)?(function\\s*)?)?\\(`, "g");
  let m = keyRe.exec(stripped);
  if (!m) {
    const arrowNoParen = new RegExp(`\\b${kw}\\s*:\\s*(async\\s*)?([A-Za-z_$][\\w$]*)\\s*=>`).exec(stripped);
    if (arrowNoParen) {
      const after = stripped.slice(arrowNoParen.index + arrowNoParen[0].length);
      return sliceArrowOrBrace(after, true);
    }
    return null;
  }
  const parenOpen = m.index + m[0].length - 1;
  const parenClose = matchDelim(stripped, parenOpen, "(", ")");
  if (parenClose < 0) return null;
  let j = parenClose + 1;
  while (j < stripped.length && /\s/.test(stripped[j])) j++;
  if (stripped[j] === "=" && stripped[j + 1] === ">") {
    j += 2;
    while (j < stripped.length && /\s/.test(stripped[j])) j++;
    return sliceArrowOrBrace(stripped.slice(j), true);
  }
  if (stripped[j] === "{") {
    const close = matchDelim(stripped, j, "{", "}");
    if (close < 0) return { body: stripped.slice(j), arrowExpr: false };
    return { body: stripped.slice(j + 1, close), arrowExpr: false };
  }
  return null;
}

// Return { body } for the match method/property, or null. Handles brace bodies and
// single-expression arrow bodies. Uses brace-matching on the stripped source.
function extractMatchBody(stripped) {
  // find `match` used as a method/prop key
  const keyRe = /\bmatch\s*(:\s*(async\s*)?(function\s*)?)?\(/g;
  let m = keyRe.exec(stripped);
  if (!m) {
    // arrow with no parens? `match: ctx => ...`  or `match(ctx)=>` is invalid; also try
    const arrowNoParen = /\bmatch\s*:\s*(async\s*)?([A-Za-z_$][\w$]*)\s*=>/.exec(stripped);
    if (arrowNoParen) {
      const after = stripped.slice(arrowNoParen.index + arrowNoParen[0].length);
      return sliceArrowOrBrace(after, /* startedAtArrow */ true);
    }
    return null;
  }
  // position just after the "(" of the param list — skip to its matching ")"
  const parenOpen = m.index + m[0].length - 1;
  const parenClose = matchDelim(stripped, parenOpen, "(", ")");
  if (parenClose < 0) return null;
  let j = parenClose + 1;
  // skip whitespace
  while (j < stripped.length && /\s/.test(stripped[j])) j++;
  // arrow form: `) => ...`
  if (stripped[j] === "=" && stripped[j + 1] === ">") {
    j += 2;
    while (j < stripped.length && /\s/.test(stripped[j])) j++;
    return sliceArrowOrBrace(stripped.slice(j), true);
  }
  // method form: `) { ... }`
  if (stripped[j] === "{") {
    const close = matchDelim(stripped, j, "{", "}");
    if (close < 0) return { body: stripped.slice(j), arrowExpr: false };
    return { body: stripped.slice(j + 1, close), arrowExpr: false };
  }
  return null;
}

// Given the text right after `=>`, return the body: either a `{...}` block or a single
// expression up to the terminator (',' at depth 0, or the closing of the object).
function sliceArrowOrBrace(after, startedAtArrow) {
  let k = 0;
  while (k < after.length && /\s/.test(after[k])) k++;
  if (after[k] === "{") {
    const close = matchDelim(after, k, "{", "}");
    if (close < 0) return { body: after.slice(k), arrowExpr: false };
    return { body: after.slice(k + 1, close), arrowExpr: false };
  }
  // single-expression arrow body: read until a top-level ',' or ')' or '}' (object end)
  let depth = 0;
  let end = after.length;
  for (let p = k; p < after.length; p++) {
    const ch = after[p];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") { if (depth === 0) { end = p; break; } depth--; }
    else if (ch === "," && depth === 0) { end = p; break; }
  }
  return { body: after.slice(k, end), arrowExpr: true };
}

// Brace/paren matcher on a (stripped) source. Returns index of the matching close, or -1.
function matchDelim(s, openIdx, openCh, closeCh) {
  let depth = 0;
  for (let i = openIdx; i < s.length; i++) {
    if (s[i] === openCh) depth++;
    else if (s[i] === closeCh) { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// ── Non-ASCII / homoglyph guard for the module name and for banned specifiers. ───────────
// A name that passes /^[a-z0-9_-]+$/ can still be spoofed with a homoglyph if we only test a
// unicode-aware regex; our name regex is ASCII-only by construction, so any non-ascii char
// simply fails it. We ALSO scan the whole (raw) source for non-ASCII inside import specifiers
// so a homoglyph host/module (e.g. a Cyrillic 'о' in "node:сhild_process") is flagged rather
// than silently treated as a harmless unknown package.
function hasNonAscii(str) {
  return /[^ -]/.test(String(str));
}

// ── Core linter over a single module's source. Returns an array of findings. ─────────────
export function lintSource(src, filename = "<module>") {
  const findings = [];
  const add = (rule, msg) => findings.push({ file: filename, rule, msg });

  const raw = src;
  const stripped = stripCommentsAndStrings(src);

  // ---- L4: default export present at all ----
  if (!/\bexport\s+default\b/.test(stripped)) {
    add("L4", "no `export default` — a module must default-export one object.");
    // keep going; other checks still informative
  }

  const shape = analyzeShape(stripped, raw);

  // ---- L4: name literal, charset, presence ----
  if (!shape.nameLiteralFound) {
    if (shape.nameDynamic) add("L4", "`name` is not a string literal (must be a static `name: \"...\"`).");
    else add("L4", "missing `name` — every module needs a unique static string name.");
  } else {
    const nm = shape.nameValue;
    if (nm === "") add("L4", "`name` is empty.");
    else if (hasNonAscii(nm)) add("L4", `\`name\` contains non-ASCII/homoglyph characters: ${JSON.stringify(nm)}.`);
    else if (!/^[a-z0-9_-]+$/.test(nm)) add("L4", `\`name\` "${nm}" does not match ^[a-z0-9_-]+$ (path/traversal/dot/space/meta chars are rejected).`);
  }

  // ---- L1 / L3-ish: import & require & dynamic-import specifiers ----
  const specs = extractSpecifiers(raw, stripped);
  for (const s of specs) {
    if (typeof s.spec === "object" && s.spec.__expr != null) {
      // non-literal specifier: import(expr) / require(expr). Could hide a banned module.
      // We cannot statically prove it's safe → CONSERVATIVE: reject dynamic/computed imports.
      add("L1", `computed ${s.kind} specifier \`${s.spec.__expr.slice(0, 60)}\` — dynamic/aliased imports of the outside world are forbidden (use ctx.core). If this is genuinely benign compute, inline it.`);
      continue;
    }
    if (hasNonAscii(s.spec)) {
      add("L1", `import specifier ${JSON.stringify(s.spec)} contains non-ASCII/homoglyph characters — refused.`);
      continue;
    }
    if (isBannedSpecifier(s.spec)) {
      add("L1", `direct ${s.kind} of banned builtin ${JSON.stringify(s.spec)} — reach the outside world only via ctx.core (I3).`);
    }
  }

  // createRequire escape hatch: `import { createRequire } from "node:module"` then require().
  // The require() calls are already caught above; also flag the createRequire import itself as
  // a smell that a module is trying to build its own require. (module is not in BANNED set.)
  if (/\bcreateRequire\b/.test(stripped)) {
    add("L1", "`createRequire` present — building a custom `require` is a banned-import escape hatch (I3).");
  }
  // process.binding / internal bindings
  if (/\bprocess\s*\.\s*binding\b/.test(stripped) || /\bprocess\s*\.\s*dlopen\b/.test(stripped)) {
    add("L1", "`process.binding`/`process.dlopen` — native-binding escape hatch is forbidden (I3).");
  }
  // process.getBuiltinModule('child_process'|'fs'|'net'|...) — a runtime handle to a banned
  // builtin that entirely bypasses the import/require scan (I3). Any use is a build failure.
  if (/\bgetBuiltinModule\b/.test(stripped)) {
    add("L1", "`getBuiltinModule` — obtaining a builtin at runtime bypasses the import clamp; reach the outside world only via ctx.core (I3).");
  }
  // process.mainModule.require(...) / module.createRequire — custom require builders.
  if (/\bmainModule\s*\.\s*require\b/.test(stripped)) {
    add("L1", "`process.mainModule.require` — custom require path is a banned-import escape hatch (I3).");
  }
  // Function-constructor dynamic import: `new Function('return import("node:fs")')` or the
  // `(fn).constructor('s','return import(s)')` idiom that reaches the Function constructor without
  // naming it. The `import(`/`require(` lives inside a STRING (neutralized in `stripped`), so we
  // inspect the RAW argument text of any Function(...) / .constructor(...) call for smuggled
  // import/require/getBuiltinModule/env-read. Any such code-gen is a build failure (I3).
  {
    const scanCtorArgs = (re, label) => {
      for (let m; (m = re.exec(stripped)); ) {
        const open = m.index + m[0].length - 1;
        const close = matchDelim(stripped, open, "(", ")");
        if (close < 0) continue;
        const rawArgs = raw.slice(open + 1, close);
        if (/\bimport\s*\(|\brequire\s*\(|getBuiltinModule|child_process|process\s*\.\s*env|process\s*\[/.test(rawArgs)) {
          add("L1", `${label} building code that imports/requires/reads env — dynamic code-gen escape hatch is forbidden (I3).`);
          return true;
        }
      }
      return false;
    };
    scanCtorArgs(/\bFunction\s*\(/g, "`Function(...)` constructor");
    scanCtorArgs(/\.\s*constructor\s*\(/g, "`(...).constructor(...)` (Function constructor)");
  }

  // ---- L3: process.env read (must use ctx.env) ----
  // Any textual process.env access in code (not comments/strings — we use stripped).
  if (/\bprocess\s*\.\s*env\b/.test(stripped)) {
    add("L3", "reads `process.env` directly — modules must read config only from ctx.env (I6).");
  }
  // Obfuscated process.env access: process['env'], process["env"], globalThis.process.env,
  // process[`env`], process [ 'env' ] — the literal "env" lived in a string so `stripped` blanked
  // it; scan RAW for `process` followed by a bracket-access whose key is the string "env".
  if (/\bprocess\s*\[\s*(['"`])\s*env\s*\1\s*\]/.test(raw)) {
    add("L3", "obfuscated `process['env']` access — forbidden; use ctx.env (I6).");
  }
  // any `.env` bracket/dot read hung off a `process` reference stored in a variable is beyond a
  // static linter; but a direct `globalThis.process` / `global.process` chain to env is caught:
  if (/\b(globalThis|global)\s*\.\s*process\s*\.\s*env\b/.test(stripped) ||
      /\b(globalThis|global)\s*\.\s*process\s*\[\s*(['"`])\s*env\s*\2/.test(raw)) {
    add("L3", "obfuscated `globalThis.process.env` access — forbidden; use ctx.env (I6).");
  }

  // ---- L2: match() purity (pure + sync) ----
  if (shape.matchBody) {
    const b = shape.matchBody.body;
    // await
    if (/\bawait\b/.test(b)) add("L2", "match() contains `await` — match must be pure and synchronous (I2).");
    // reference to core (routing must not touch capabilities; kernel calls match with core:null)
    if (/\bcore\b/.test(b)) add("L2", "match() references `core` — routing must not touch capabilities; it runs on an unauthenticated ctx with core:null (I2).");
    // async keyword on match itself
    if (shape.matchAsync) add("L2", "match() is declared `async` — match must be synchronous (I2).");
    // direct I/O-ish tokens inside match (belt & suspenders; imports already banned, but a
    // module could call a banned thing via a helper — flag obvious I/O calls in match).
    if (/\bfetch\s*\(/.test(b)) add("L2", "match() calls `fetch(` — no I/O in match (I2).");
    if (/\brequire\s*\(/.test(b)) add("L2", "match() calls `require(` — no I/O / module loading in match (I2).");
    if (/\bimport\s*\(/.test(b)) add("L2", "match() uses dynamic `import(` — no I/O in match (I2).");
    if (/\.(exec|proxy|store|control)\b/.test(b)) add("L2", "match() references a core capability (exec/proxy/store/control) — match must be pure routing only (I2).");
    if (/\bMath\s*\.\s*random\b/.test(b)) add("L2", "match() uses Math.random — routing must be deterministic (I2).");
    if (/\bDate\s*\.\s*now\b|\bnew\s+Date\b/.test(b)) add("L2", "match() reads the clock — routing must be deterministic/pure (I2).");
  }
  // detect `async match`
  if (/\basync\s+match\s*\(/.test(stripped)) add("L2", "match() is declared `async` — match must be synchronous (I2).");

  // ---- L2 (strengthened): match() must be side-effect-free (I2). Reject fetch/spawn/store-write/
  //      await/async/proxy anywhere reachable in the match body (belt & suspenders over the above).
  if (shape.matchBody) {
    const b = shape.matchBody.body;
    if (/\.\s*set\s*\(/.test(b)) add("L2", "match() performs a store/state write (`.set(`) — match must be side-effect-free (I2).");
    if (/\bspawn\w*\s*\(|\bexec\w*\s*\(/.test(b)) add("L2", "match() spawns/execs — match must be side-effect-free (I2).");
    if (/\bnew\s+Promise\b|\.then\s*\(/.test(b)) add("L2", "match() creates/awaits async work — match must be pure & synchronous (I2).");
  }

  // ---- L7: control-plane capability in the DATA plane (handle) is forbidden (I12). ----
  // control.rotate is operator-only; the data-plane core handed to handle() must never see it.
  // A handle() that references core.control / .rotate is trying to escalate to the control plane
  // (mint/exfiltrate the door-key). Hard build failure — the runtime also denies it (no capability).
  if (shape.handleBody) {
    const h = shape.handleBody.body;
    if (/\.\s*control\b/.test(h) || /\bcontrol\s*\.\s*rotate\b/.test(h) || /\.\s*rotate\s*\(/.test(h)) {
      add("L7", "handle() references the control plane (`core.control`/`.rotate(`) — rotate is operator-only and unreachable from the data plane; handle() must never invoke it (I12).");
    }
  }
  // Also catch a top-level control.rotate reference outside rotate()/start() surfaces: if a module
  // has a handle AND references core.control anywhere that is not clearly inside rotate/start.
  {
    const rotateBody = extractNamedBody(stripped, "rotate");
    const startBody = extractNamedBody(stripped, "start");
    const allowed = (rotateBody ? rotateBody.body : "") + "\n" + (startBody ? startBody.body : "");
    // find every `.control` occurrence; ensure each is accounted for by rotate/start bodies.
    const controlHits = (stripped.match(/\.\s*control\b/g) || []).length;
    const allowedHits = (allowed.match(/\.\s*control\b/g) || []).length;
    if (shape.handlePresent && controlHits > allowedHits) {
      // some .control reference lives outside rotate()/start() while a handle exists → data-plane reach.
      if (!(shape.handleBody && (/\.\s*control\b/.test(shape.handleBody.body)))) {
        add("L7", "`core.control` referenced outside rotate()/start() in a module that has a data plane — the control plane is operator-only (I12).");
      }
    }
  }

  // ---- L5: dead module (non-public with no handle AND no rotate/start) ----
  if (!shape.publicTrue) {
    if (!shape.handlePresent && !shape.rotatePresent && !shape.startPresent) {
      add("L5", "non-public module with no `handle` AND no `rotate`/`start` — dead module (nothing it can ever do).");
    }
  } else {
    // even a public module needs SOME surface; a public module with no handle is dead too.
    if (!shape.handlePresent && !shape.rotatePresent && !shape.startPresent) {
      add("L5", "public module with no `handle`/`rotate`/`start` — dead module.");
    }
  }

  // ---- L6: exec misuse (shell string / client-supplied path, not a vetted name) (I7) ----
  // Find every core.exec(...) call and inspect its first argument on the stripped source, but
  // read the first-arg literal from raw to see if it's a string literal name.
  lintExecCalls(raw, stripped, add);

  // ---- I9-adjacent smell: a shell invocation anywhere (spawn/exec from a smuggled import) ----
  // Even though the import is banned, catch the CALL form in case a module received a spawner
  // by some other means. `spawn(`, `execSync(`, `exec(` with a string containing a space/`-c`.
  detectShellExec(stripped, raw, add);

  return findings;
}

// Inspect core.exec("name", args) calls. A vetted call passes a NAME literal matching
// ^[a-z0-9_-]+$ (or a validated variable) + an ARRAY of args. Violations:
//   - first arg is a template/concatenation containing shell-ish content or a path
//   - first arg is a string literal that is NOT a bare vetted name (contains '/','\\','..',
//     space, '-c', shell metachar) → a path or command, not a name
function lintExecCalls(raw, stripped, add) {
  // locate ".exec(" occurrences in stripped, then read the corresponding raw slice for the
  // literal first argument.
  const re = /\.exec\s*\(/g;
  for (let m; (m = re.exec(stripped)); ) {
    const open = m.index + m[0].length - 1; // index of "("
    const close = matchDelim(stripped, open, "(", ")");
    if (close < 0) continue;
    const rawArgs = raw.slice(open + 1, close);
    // split off the first argument at the top-level comma
    const firstArg = topLevelFirstArg(rawArgs).trim();

    // string literal?
    const lit = firstArg.match(/^(['"])([\s\S]*)\1$/);
    if (lit) {
      const val = lit[2];
      if (!/^[a-z0-9_-]+$/.test(val)) {
        add("L6", `core.exec first arg ${JSON.stringify(val)} is not a bare vetted name (^[a-z0-9_-]+$) — looks like a path/command, forbidden (I7).`);
      }
      continue;
    }
    // template literal → dynamic command/path construction
    if (/^`/.test(firstArg)) {
      add("L6", "core.exec first arg is a template literal — a computed command/path is forbidden; pass a vetted NAME (I7).");
      continue;
    }
    // string concatenation with '+' at top level → building a path/command
    if (containsTopLevelPlus(firstArg)) {
      add("L6", "core.exec first arg is a concatenation — a computed command/path is forbidden; pass a vetted NAME (I7).");
      continue;
    }
    // a bare identifier (variable). Acceptable IF the module validated it (run.mjs does via
    // VETTED_NAME regex). We can't prove validation statically, so we allow a bare identifier
    // but forbid obvious client-path patterns like ctx.params.t / .path / .cmd.
    if (/\bparams\s*\.\s*(t|path|cmd|command|script|file)\b/.test(firstArg) ||
        /\bparams\s*\[\s*['"](t|path|cmd|command|script|file)['"]\s*\]/.test(firstArg)) {
      add("L6", `core.exec first arg reads a client path/command param (${firstArg.slice(0, 40)}) — the client may pass only a NAME, validated to ^[a-z0-9_-]+$ (I7).`);
    }
  }
}

// Detect direct shell-exec CALLS (in case a spawner leaked in without a banned import token
// we recognized). Flags spawn/exec/execSync/execFile/fork with a shell string.
function detectShellExec(stripped, raw, add) {
  // exec("...string with space or -c...") NOT preceded by core. / ctx.core.
  const re = /(^|[^.\w])(execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/g;
  for (let m; (m = re.exec(stripped)); ) {
    // these functions only exist via child_process (banned import) — flag the call as a smell.
    add("L6", `direct \`${m[2]}(\` call — process spawning must go through ctx.core.exec, never a child_process API (I3/I7).`);
  }
  // DOTTED forms: `cp.execSync(`, `child_process.spawn(`, `foo.execFileSync(` — the child_process
  // API surface accessed via a (smuggled) handle. `.exec(` alone is NOT flagged here (that is the
  // legit core.exec surface, checked in lintExecCalls); but execSync/spawn/etc. never exist on
  // ctx.core, so a dotted call to one is a smuggled child_process handle (I3/I7).
  const reDotted = /\.\s*(execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/g;
  for (let m; (m = reDotted.exec(stripped)); ) {
    add("L6", `dotted \`.${m[1]}(\` call — a child_process API reached via a handle; spawning must go through ctx.core.exec (I3/I7).`);
  }
  // exec("bash -c ...") / exec("sh", ["-c", ...]) style with shell:true
  if (/\bshell\s*:\s*true\b/.test(stripped)) {
    add("L6", "`shell:true` present — exec must be shell:false (no shell interpretation of input) (I7).");
  }
}

// Return the substring of the first top-level (comma-separated) argument.
function topLevelFirstArg(argStr) {
  let depth = 0;
  let inStr = "";
  for (let i = 0; i < argStr.length; i++) {
    const ch = argStr[i];
    if (inStr) {
      if (ch === "\\") { i++; continue; }
      if (ch === inStr) inStr = "";
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") { inStr = ch; continue; }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) return argStr.slice(0, i);
  }
  return argStr;
}

// Is there a top-level (outside strings/parens) `+` in this arg? (string concatenation)
function containsTopLevelPlus(argStr) {
  let depth = 0;
  let inStr = "";
  for (let i = 0; i < argStr.length; i++) {
    const ch = argStr[i];
    if (inStr) {
      if (ch === "\\") { i++; continue; }
      if (ch === inStr) inStr = "";
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") { inStr = ch; continue; }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "+" && depth === 0) return true;
  }
  return false;
}

// ── Directory linter: lint the live module set (skip _* helpers and *.test.mjs). ─────────
// Also enforces cross-file uniqueness of `name` (duplicate name === build fail, L4).
export function lintDir(dir) {
  const entries = fs.readdirSync(dir).filter(
    (f) => f.endsWith(".mjs") && !f.startsWith("_") && !f.endsWith(".test.mjs")
  ).sort();

  const all = [];
  const nameOwners = new Map();    // exact name -> [files]
  const envPrefixes = [];          // { prefix:"NAME_", name, file }  (env-namespace collision, I6)
  for (const f of entries) {
    const full = path.join(dir, f);
    const src = fs.readFileSync(full, "utf8");
    const findings = lintSource(src, f);
    all.push(...findings);
    // collect names for duplicate detection
    const nm = src.match(/\bname\s*:\s*(['"])([^'"]*)\1/);
    if (nm) {
      const key = nm[2];
      if (!nameOwners.has(key)) nameOwners.set(key, []);
      nameOwners.get(key).push(f);
      // env-namespace normalization: uppercase + '-'→'_' + trailing '_' (mirrors kernel envFor).
      // envFor selects keys by PREFIX-CONTAINMENT (k.startsWith("NAME_")), so a collision is any
      // prefix RELATIONSHIP, not only exact twins: "secure-echo"≡"secure_echo" (→SECURE_ECHO_*),
      // AND containment "git"(GIT_*) swallowing "git-hub"(GIT_HUB_*) so `git` reads GIT_HUB_TOKEN.
      envPrefixes.push({ prefix: key.toUpperCase().replace(/-/g, "_") + "_", name: key, file: f });
    }
  }
  for (const [name, owners] of nameOwners) {
    if (owners.length > 1) {
      all.push({ file: owners.join(", "), rule: "L4", msg: `duplicate module name "${name}" across ${owners.length} files — names must be unique.` });
    }
  }
  for (let i = 0; i < envPrefixes.length; i++) {
    for (let j = i + 1; j < envPrefixes.length; j++) {
      const a = envPrefixes[i], b = envPrefixes[j];
      if (a.name === b.name) continue; // exact-name dupe already reported above
      if (a.prefix.startsWith(b.prefix) || b.prefix.startsWith(a.prefix)) {
        all.push({ file: `${a.file}, ${b.file}`, rule: "L4",
          msg: `env-namespace collision: "${a.name}" (${a.prefix}*) & "${b.name}" (${b.prefix}*) — one env prefix contains the other, so one module reads the other's secrets; names must not be in a prefix relationship after normalization (I6).` });
      }
    }
  }
  return { files: entries, findings: all };
}

// ── CLI ─────────────────────────────────────────────────────────────────────────────────
function main(argv) {
  const args = argv.slice(2);
  const json = args.includes("--json");
  const posArgs = args.filter((a) => !a.startsWith("--"));
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dir = posArgs[0] ? path.resolve(posArgs[0]) : path.join(here, "modules");

  let result;
  try {
    result = lintDir(dir);
  } catch (e) {
    console.error(`lint: cannot read module dir ${dir}: ${e.message}`);
    process.exit(2);
  }

  if (json) {
    console.log(JSON.stringify({ dir, ...result }, null, 2));
  } else {
    console.log(`lint: ${result.files.length} module(s) in ${dir}`);
    if (result.findings.length === 0) {
      console.log("lint: OK — 0 findings, build gate PASSES.");
    } else {
      for (const fnd of result.findings) {
        console.error(`  ✗ [${fnd.rule}] ${fnd.file}: ${fnd.msg}`);
      }
      console.error(`lint: ${result.findings.length} finding(s) — build gate FAILS.`);
    }
  }
  process.exit(result.findings.length === 0 ? 0 : 1);
}

// run as CLI only when invoked directly (not when imported by the test suite)
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  main(process.argv);
}
