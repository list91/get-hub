#!/usr/bin/env node
/**
 * get-hub — thin server entry.
 *
 * Loads config from env, builds the kernel + core, auto-loads modules/, starts a
 * node:http server bound to BIND:PORT, and wires the operator CLI (control plane).
 *
 *   node server.mjs               # start the HTTP server (prints ASLEEP/ACTIVE banner)
 *   node server.mjs issue [name…] # mint door-key (+ rotate named modules); prints the key ONCE
 *   node server.mjs kill          # wipe door-key + all module secrets from the store
 *   node server.mjs show          # print current key/module state (never the secret value)
 *
 * The CLI is the operator/control plane (I12): a process on the host IS the operator.
 * The door-key authorizes CALLING the bridge (data plane) — never rotating it.
 *
 * ZERO runtime dependencies. Node >=18 built-ins only.
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, loadModules, createKernel } from "./kernel.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODULES_DIR = path.join(__dirname, "modules");

// ── .env loader (zero-dep, tolerant) ────────────────────────────────────────────
// Loads ./.env into process.env for EVERY entrypoint (serve AND the issue/kill/show CLI),
// so the operator CLI gets the same credentials the server does. This is the single source
// of env — the systemd unit does NOT need an EnvironmentFile (whose inline-# / quote parsing
// differs and silently corrupts values). Real env / systemd-set vars WIN (never overridden).
// Format: `KEY=value` per line; blank lines and lines starting with `#` are ignored; an
// unquoted trailing ` # comment` is stripped; a value wrapped in matching '...' or "..." is
// taken literally (quotes removed, no inner stripping). Missing .env is fine (env may come
// from the real environment).
function loadDotEnv(file) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); }
  catch { return; } // no .env → rely on process.env as-is
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (Object.prototype.hasOwnProperty.call(process.env, key)) continue; // real env wins
    let val = line.slice(eq + 1).trim();
    const q = val[0];
    if ((q === '"' || q === "'") && val[val.length - 1] === q && val.length >= 2) {
      val = val.slice(1, -1); // quoted → literal
    } else {
      const h = val.indexOf(" #"); // unquoted → drop trailing " # comment"
      if (h !== -1) val = val.slice(0, h).trim();
    }
    process.env[key] = val;
  }
}

const SEC_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, private, no-cache",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow",
  "X-Content-Type-Options": "nosniff",
};

async function build() {
  const cfg = loadConfig(process.env);
  const modules = await loadModules(MODULES_DIR);
  const kernel = createKernel(cfg, modules);
  return { cfg, modules, kernel };
}

async function serve() {
  const { cfg, modules, kernel } = await build();
  await kernel.boot();

  const srv = http.createServer(async (req, res) => {
    let out;
    try { out = await kernel.handleRequest(req); }
    catch (e) {
      console.error(`[server] ${kernel.scrub(String(e && e.stack || e))}`);
      out = { status: 500, body: { ok: false, error: "internal" } };
    }
    const payload = JSON.stringify(out.body);
    res.writeHead(out.status, SEC_HEADERS);
    // HEAD: headers only, no body.
    res.end(req.method === "HEAD" ? undefined : payload);
  });

  srv.listen(cfg.PORT, cfg.BIND, () => {
    const asleep = kernel.isAsleep();
    console.log(`get-hub ${cfg.VERSION} on http://${cfg.BIND}:${cfg.PORT}`);
    console.log(`  allow_hosts=${cfg.ALLOW_HOSTS.join(",") || "(none)"}  store=${cfg.STORE_PATH}`);
    console.log(`  modules=${modules.map((m) => m.name).join(",") || "(none)"}`);
    console.log(`  exec=${cfg.EXEC_ENABLED ? "ENABLED (" + (cfg.EXEC_DIR || "no dir!") + ")" : "disabled"}`);
    console.log(asleep
      ? "  state: ASLEEP — public ops answer; protected ops rejected. Run `node server.mjs issue` to activate."
      : "  state: ACTIVE — door-key present.");
  });
}

// ── CLI (control plane, operator-only) ──
async function cliIssue(names) {
  const { kernel } = await build();
  // door-key is always rotated; any extra names rotate those modules' secrets too.
  const res = await kernel.control.rotate(names.length ? ["door-key", ...names] : ["door-key"], {});
  const doorKey = res._doorKey;
  delete res._doorKey;
  console.log(JSON.stringify(res, null, 2));
  if (doorKey) {
    console.log("\n=== DOOR-KEY (shown ONCE — copy now, it is not stored in plaintext-readable logs) ===");
    console.log(doorKey);
  }
  process.exit(0);
}

async function cliKill() {
  const { kernel, modules } = await build();
  kernel.store.del("hmac:current");
  // wipe each module's namespaced secrets we know about (best-effort by convention name:token)
  for (const m of modules) { kernel.store.del(`${m.name}:token`); }
  console.log("killed: door-key + known module secrets wiped");
  process.exit(0);
}

async function cliShow() {
  const { kernel, modules } = await build();
  const state = {
    door_key: kernel.getDoorKey() ? "present" : null,
    state: kernel.isAsleep() ? "ASLEEP" : "ACTIVE",
    modules: modules.map((m) => ({
      name: m.name,
      public: !!m.public,
      surfaces: [
        typeof m.handle === "function" ? "handle" : null,
        typeof m.rotate === "function" ? "rotate" : null,
        typeof m.start === "function" ? "start" : null,
      ].filter(Boolean),
      secret: kernel.store.get(`${m.name}:token`) ? "present" : null,
    })),
  };
  console.log(JSON.stringify(state, null, 2)); // never prints secret VALUES (I9)
  process.exit(0);
}

// Only dispatch when run directly (`node server.mjs …`) — importing this module (e.g. from a
// test) must have NO side effects: no .env load, no port bind, no process.exit.
function main() {
  loadDotEnv(path.join(__dirname, ".env"));
  const cmd = process.argv[2];
  const rest = process.argv.slice(3);
  if (cmd === "issue") cliIssue(rest);
  else if (cmd === "kill") cliKill();
  else if (cmd === "show") cliShow();
  else serve();
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) main();

// exported for tests
export { loadDotEnv };
