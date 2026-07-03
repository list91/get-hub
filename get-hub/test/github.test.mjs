/**
 * github.mjs unit test — real worked example, no toy stubs beyond a fake `core`.
 * Run: node modules/github.test.mjs   (exit 0 = all pass)
 *
 * Covers: shape/purity, token injection (client sends none), not-provisioned,
 * host guard, rotate static (mode 2), rotate App-JWT (mode 1) with a REAL RS256 key +
 * a captured core.proxy that verifies the JWT, and a no-secret-leak assertion across
 * every returned object + every log line.
 */
import crypto from "node:crypto";
import assert from "node:assert/strict";
import gh from "../modules/github.mjs";

let pass = 0;
const t = (name, fn) => { try { fn(); console.log("ok  -", name); pass++; }
  catch (e) { console.error("FAIL-", name, "\n   ", e.message); process.exitCode = 1; } };
const at = async (name, fn) => { try { await fn(); console.log("ok  -", name); pass++; }
  catch (e) { console.error("FAIL-", name, "\n   ", e.message); process.exitCode = 1; } };

// ── fake core: namespaced store + capturing proxy + log sink ─────────────────
function makeCore({ env = {}, proxyImpl } = {}) {
  const kv = new Map();
  const logs = [];
  const calls = [];
  return {
    core: {
      env: Object.freeze({ ...env }),
      store: {
        get: (k) => (kv.has(k) ? kv.get(k).v : null),
        set: (k, v, ttl) => kv.set(k, { v, ttl }),
      },
      log: (m) => logs.push(String(m)),
      proxy: async (url, opts) => {
        calls.push({ url, opts });
        return proxyImpl ? proxyImpl(url, opts) : { ok: false, error: "no_proxy" };
      },
    },
    kv, logs, calls,
  };
}
const SECRET = "ghs_TOTALLYSECRETINSTALLTOKEN_do_not_leak_0123456789";
// A leak check: no assertion may ever contain the raw secret.
const noLeak = (obj, logs) => {
  const blob = JSON.stringify(obj) + "\n" + logs.join("\n");
  assert.ok(!blob.includes(SECRET), "SECRET leaked into response/log: " + blob.slice(0, 120));
};

// ── 1. shape + lint-relevant invariants ──────────────────────────────────────
t("shape: name/public/match/handle/rotate present & correct types", () => {
  assert.equal(gh.name, "github");
  assert.equal(gh.public, false);
  assert.equal(typeof gh.match, "function");
  assert.equal(typeof gh.handle, "function");
  assert.equal(typeof gh.rotate, "function");
});

t("match is pure/sync: routes only op=github @ api.github.com; no core touched", () => {
  // match must never read ctx.core / ctx.env (they are null/{} during routing).
  const routing = { op: "github", host: "api.github.com", core: null, env: {} };
  assert.equal(gh.match(routing), true);
  assert.equal(gh.match({ op: "github", host: "evil.com", core: null, env: {} }), false);
  assert.equal(gh.match({ op: "do", host: "api.github.com", core: null, env: {} }), false);
  assert.equal(gh.match({ op: "github", host: null, core: null, env: {} }), false);
});

// ── 2. handle: token injection, client sends NONE ────────────────────────────
await at("handle: injects Bearer from store; client token absent from request", async () => {
  const { core, calls, logs } = makeCore({
    proxyImpl: async () => ({ ok: true, upstream_status: 200, error: null, body: '{"login":"octocat"}', truncated: false }),
  });
  core.store.set("token", SECRET); // rotate would have done this server-side
  const ctx = {
    op: "github", host: "api.github.com", method: "GET",
    params: { t: "https://api.github.com/user" },   // client provides NO token
    headers: { "User-Agent": "get-hub/1.0" },
    core,
  };
  const out = await gh.handle(ctx);
  assert.equal(out.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://api.github.com/user");
  assert.equal(calls[0].opts.method, "GET");
  // the injected header carried the secret — that is correct (server-side), but the
  // RESPONSE must not: proxy result echoes body, never the request header.
  assert.equal(calls[0].opts.headers.Authorization, `Bearer ${SECRET}`);
  assert.equal(calls[0].opts.headers.Accept, "application/vnd.github+json");
  noLeak(out, logs);
});

await at("handle: HEAD stays HEAD; other methods coerced to GET", async () => {
  const { core, calls } = makeCore({ proxyImpl: async () => ({ ok: true, upstream_status: 200, body: "" }) });
  core.store.set("token", SECRET);
  const base = { op: "github", host: "api.github.com", params: { t: "https://api.github.com/x" }, headers: {}, core };
  await gh.handle({ ...base, method: "HEAD" });
  await gh.handle({ ...base, method: "POST" }); // kernel wouldn't allow, but coerce defensively
  assert.equal(calls[0].opts.method, "HEAD");
  assert.equal(calls[1].opts.method, "GET");
});

await at("handle: not provisioned (no stored token) -> safe error, no proxy call", async () => {
  const { core, calls } = makeCore();
  const out = await gh.handle({
    op: "github", host: "api.github.com", method: "GET",
    params: { t: "https://api.github.com/user" }, headers: {}, core,
  });
  assert.equal(out.ok, false);
  assert.equal(out.error, "github_not_provisioned");
  assert.equal(calls.length, 0);
});

await at("handle: off-host t= rejected before any proxy call", async () => {
  const { core, calls, logs } = makeCore();
  core.store.set("token", SECRET);
  const out = await gh.handle({
    op: "github", host: "api.github.com", method: "GET",
    params: { t: "https://evil.example/steal" }, headers: {}, core,
  });
  assert.equal(out.ok, false);
  assert.equal(out.error, "host_not_allowed");
  assert.equal(calls.length, 0);
  noLeak(out, logs);
});

// ── 3. rotate mode 2: static token ───────────────────────────────────────────
await at("rotate: static GITHUB_TOKEN stored under 'token', not returned", async () => {
  const { core, kv, logs } = makeCore({ env: { TOKEN: SECRET } });
  const res = await gh.rotate({ ttl: 3600, core });
  assert.equal(res.minted, true);
  assert.equal(res.source, "static");
  assert.equal(res.expires_in, 3600);
  assert.equal(kv.get("token").v, SECRET);      // stored server-side
  assert.equal(kv.get("token").ttl, 3600);
  noLeak(res, logs);
});

await at("rotate: no creds at all -> minted:false, safe error", async () => {
  const { core } = makeCore({ env: {} });
  const res = await gh.rotate({ ttl: 3600, core });
  assert.equal(res.minted, false);
  assert.equal(res.error, "no_github_creds");
});

// ── 4. rotate mode 1: App-JWT -> installation token (REAL RS256) ─────────────
await at("rotate: App creds -> mints RS256 JWT, exchanges via proxy, stores install token", async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const expIso = new Date(Date.now() + 3600 * 1000).toISOString();

  let seenJwt = null, seenUrl = null, seenMethod = null;
  const { core, kv, logs } = makeCore({
    env: { APP_ID: "123456", INSTALL_ID: "987", APP_PEM: pem },
    proxyImpl: async (url, opts) => {
      seenUrl = url; seenMethod = opts.method;
      const m = /^Bearer (.+)$/.exec(opts.headers.Authorization || "");
      seenJwt = m ? m[1] : null;
      return { ok: true, upstream_status: 201, error: null,
               body: JSON.stringify({ token: SECRET, expires_at: expIso }), truncated: false };
    },
  });

  const res = await gh.rotate({ ttl: 3600, core });
  assert.equal(res.minted, true);
  assert.equal(res.source, "app_installation");

  // token exchange went to the right endpoint, via POST, through core.proxy (no direct fetch)
  assert.equal(seenUrl, "https://api.github.com/app/installations/987/access_tokens");
  assert.equal(seenMethod, "POST");

  // the JWT the module produced verifies against the REAL public key (proves RS256 signing)
  assert.ok(seenJwt, "no JWT presented to proxy");
  const [h, p, s] = seenJwt.split(".");
  const der = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const verified = crypto.verify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, der);
  assert.equal(verified, true, "JWT signature did not verify against the app public key");
  const claims = JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
  assert.equal(claims.iss, "123456");
  assert.ok(claims.exp - claims.iat <= 600, "JWT exceeds GitHub's 10-min ceiling");

  // install token stored server-side; response/log carry NO secret
  assert.equal(kv.get("token").v, SECRET);
  assert.ok(kv.get("token").ttl >= 60);
  noLeak(res, logs);
});

await at("rotate: App-mint fails -> falls back to static token when present", async () => {
  const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  // valid-looking creds but proxy returns an error => mint throws => fallback
  const goodPem = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });
  const { core, kv, logs } = makeCore({
    env: { APP_ID: "1", INSTALL_ID: "2", APP_PEM: goodPem, TOKEN: SECRET },
    proxyImpl: async () => ({ ok: false, upstream_status: 401, error: "upstream_error", body: '{"message":"Bad credentials"}' }),
  });
  const res = await gh.rotate({ ttl: 3600, core });
  assert.equal(res.minted, true);
  assert.equal(res.source, "static_fallback");
  assert.equal(kv.get("token").v, SECRET);
  noLeak(res, logs);
  // upstream error body must not have leaked into the log
  assert.ok(!logs.join("\n").includes("Bad credentials"));
});

await at("rotate: App-mint fails with no static token -> minted:false, no leak", async () => {
  const goodPem = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });
  const { core, logs } = makeCore({
    env: { APP_ID: "1", INSTALL_ID: "2", APP_PEM: goodPem },
    proxyImpl: async () => ({ ok: false, upstream_status: 500, error: "upstream_error", body: "boom" }),
  });
  const res = await gh.rotate({ ttl: 3600, core });
  assert.equal(res.minted, false);
  assert.equal(res.error, "mint_failed");
  noLeak(res, logs);
});

console.log(`\n${pass} checks passed`);
