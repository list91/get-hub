/**
 * security.test.mjs — red-team suite for the kernel hardening pass.
 *
 * Each test ATTEMPTS a confirmed vulnerability and asserts it now FAILS (the fix holds).
 * Covers the runtime side of: control-plane exposure on the data plane (I12), store-namespace
 * kernel-key read/write (I6), explicit-port SSRF + cross-host redirect credential carry (I8),
 * telegram sender-binding (I12), IPv6-embedded internal IPs (I8), and scrub adjacency (I9).
 *
 * Zero deps: node:test + node:assert + the kernel's own exports. No network (localhost/offline).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import https from "node:https";
import { promises as dns } from "node:dns";
import { EventEmitter } from "node:events";
import { loadConfig, createKernel, _internals } from "../kernel.mjs";

// throwaway store per kernel so we never touch the shared store file.
function tmpStore() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "gethub-sec-"));
  return path.join(d, "store.json");
}
function freshKernel(extraEnv = {}, modules = []) {
  const cfg = loadConfig({
    ALLOW_HOSTS: "api.github.com api.telegram.org",
    STORE_PATH: tmpStore(),
    PROXY_TIMEOUT_MS: "1000",
    ...extraEnv,
  });
  return createKernel(cfg, modules);
}

// ─────────────────────────────────────────────────────────────────────────────
// #1 CRITICAL — control.rotate must NOT be reachable from a data-plane handle().
// A data-plane core (buildCtx / coreFor) must carry NO control capability, so a module's
// handle() cannot mint or exfiltrate the door-key. rotate is only on the privileged core.
// ─────────────────────────────────────────────────────────────────────────────
test("#1 data-plane core has NO control capability (rotate unreachable from handle)", () => {
  const k = freshKernel();
  const dataCore = k.coreFor("evil");
  assert.equal(dataCore.control, undefined, "data-plane core.control must be undefined");
});

test("#1 an evil handle() calling ctx.core.control.rotate() throws (no capability), never leaks a key", async () => {
  // Simulate the exact exploit: a non-public module whose handle mints + returns the door-key.
  const evil = {
    name: "evil",
    public: true, // even worse: unauthenticated
    match: (c) => c.op === "evil",
    async handle(ctx) {
      // control is undefined on the data plane → this must throw, caught by the kernel as 500.
      const r = await ctx.core.control.rotate([], {});
      return { leaked: r._doorKey };
    },
  };
  const k = freshKernel({}, [evil]);
  const before = k.getDoorKey();
  const res = await k.handleRequest({ method: "GET", url: "/?op=evil" });
  // kernel catches the TypeError as a safe 500 module_error — NO door-key in the body.
  assert.equal(res.status, 500);
  assert.equal(res.body.error, "module_error");
  assert.ok(!JSON.stringify(res.body).includes("bridge-"), "no door-key may appear in the response");
  assert.equal(k.getDoorKey(), before, "the door-key must be unchanged (no rotation happened)");
});

test("#1 privileged core (start/rotate surfaces) DOES have control — the control plane still works", () => {
  const k = freshKernel();
  // reach the privileged factory the way boot()/rotate() do: via control on a privileged core.
  // We can't call the private privilegedCoreFor directly, but boot hands it to start(); assert the
  // CLI control plane is intact by rotating the door-key through kernel.control (operator path).
  return k.control.rotate(["door-key"], {}).then((r) => {
    assert.ok(r._doorKey && r._doorKey.startsWith("bridge-"), "operator rotate still mints a key");
    assert.equal(k.getDoorKey(), r._doorKey, "door-key stored");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// #2 CRITICAL — a module named "hmac" must NOT read/forge the kernel door-key at hmac:current.
// The per-module store view reserves the kernel namespace; a colliding key resolves to a no-op.
// ─────────────────────────────────────────────────────────────────────────────
test("#2 coreFor('hmac').store.get('current') does NOT return the door-key", async () => {
  const k = freshKernel();
  await k.control.rotate(["door-key"], {});         // mint a real door-key at hmac:current
  const live = k.getDoorKey();
  assert.ok(live.startsWith("bridge-"), "door-key minted");
  const hmacView = k.coreFor("hmac").store;
  assert.equal(hmacView.get("current"), null, "module 'hmac' must NOT read hmac:current (the door-key)");
});

test("#2 coreFor('hmac').store.set('current', forged) cannot forge the door-key", () => {
  const k = freshKernel();
  return k.control.rotate(["door-key"], {}).then(() => {
    const live = k.getDoorKey();
    const hmacView = k.coreFor("hmac").store;
    const rv = hmacView.set("current", "bridge-attacker-forged");
    assert.equal(rv, false, "write to a reserved kernel key must be refused");
    assert.equal(k.getDoorKey(), live, "the real door-key is unchanged (not forged)");
    // and the forged value must NOT authenticate.
    const auth = k.authenticate("/", { key: "bridge-attacker-forged" });
    assert.equal(auth.ok, false, "the forged key must not authenticate");
  });
});

test("#2 a module's OWN namespaced key still works (isolation, not a total ban)", () => {
  const k = freshKernel();
  const store = k.coreFor("github").store;
  store.set("token", "value123", 60);
  assert.equal(store.get("token"), "value123", "a module can still use its own namespace");
});

// ─────────────────────────────────────────────────────────────────────────────
// #3 HIGH — explicit non-443 port must be rejected BEFORE the allowlist (I8).
// ─────────────────────────────────────────────────────────────────────────────
test("#3 https://api.github.com:22/x is rejected as bad_port (never dials port 22)", async () => {
  const k = freshKernel();
  const proxy = k.coreFor("fetch").proxy;
  const r = await proxy("https://api.github.com:22/x", { method: "GET" });
  assert.equal(r.ok, false);
  assert.equal(r.error, "bad_port", `expected bad_port, got ${r.error}`);
});

test("#3 explicit :443 is still allowed (default port is fine)", async () => {
  const k = freshKernel();
  const proxy = k.coreFor("fetch").proxy;
  // off-allowlist host so we don't dial; but :443 must pass the port gate → reach host check.
  const r = await proxy("https://not-allowed.example:443/x", { method: "GET" });
  assert.equal(r.error, "host_not_allowed", "an explicit :443 passes the port gate (reaches allowlist)");
});

// ─────────────────────────────────────────────────────────────────────────────
// #4 HIGH — a cross-host redirect must NOT be followed (never carry an injected Bearer off-host).
// We stub the proxy's transport by intercepting via a fake upstream is not trivial with the real
// https layer; instead we assert the same-host rule at the unit level through a redirect fixture.
// (The redirect-follow decision is host-equality: locHost === curHost.)
// ─────────────────────────────────────────────────────────────────────────────
// Stub node:https.request so the real proxy loop runs offline. `script` maps a hostname → the
// response it should produce for that hop. Records every hop's { hostname, headers }.
function withStubbedHttps(script, fn) {
  const orig = https.request;
  const origDns = dns.lookup;
  // stub DNS so the offline test never resolves for real; hand back a public-looking IP.
  dns.lookup = async () => [{ address: "140.82.121.6", family: 4 }];
  const hops = [];
  https.request = (opts, cb) => {
    hops.push({ hostname: opts.hostname, port: opts.port, headers: { ...opts.headers } });
    const res = new EventEmitter();
    const spec = script[opts.hostname] || { status: 200, headers: {}, body: "ok" };
    const req = new EventEmitter();
    req.write = () => {};
    req.end = () => {
      // deliver the scripted response asynchronously
      setImmediate(() => {
        res.statusCode = spec.status;
        res.headers = spec.headers || {};
        cb(res);
        setImmediate(() => { res.emit("data", Buffer.from(spec.body || "")); res.emit("end"); });
      });
    };
    req.destroy = () => {};
    req.on = EventEmitter.prototype.on.bind(req);
    return req;
  };
  return Promise.resolve()
    .then(() => fn(hops))
    .finally(() => { https.request = orig; dns.lookup = origDns; });
}

test("#4 a cross-host redirect (GitHub→Telegram) is NOT followed and the Bearer never leaves for the other host", async () => {
  const k = freshKernel();
  const proxy = k.coreFor("github").proxy;
  await withStubbedHttps({
    // hop 0: api.github.com 302 → api.telegram.org (a DIFFERENT allowlisted host)
    "api.github.com": { status: 302, headers: { location: "https://api.telegram.org/evil" }, body: "" },
    // hop 1 (must NEVER happen): if it did, this would 200 and carry the Bearer to Telegram
    "api.telegram.org": { status: 200, headers: {}, body: "SHOULD_NOT_REACH" },
  }, async (hops) => {
    const r = await proxy("https://api.github.com/user", {
      method: "GET",
      headers: { Authorization: "Bearer ghs_SECRETGITHUBTOKEN0123456789abcdef" },
    });
    // The proxy returns the 3xx as-is, flagged not-followed for cross_host.
    assert.equal(r.redirect_not_followed, true, "cross-host redirect must NOT be followed");
    assert.equal(r.reason, "cross_host", `expected reason cross_host, got ${r.reason}`);
    // Exactly ONE hop was made — to api.github.com. Telegram was never dialed.
    const telegramHops = hops.filter((h) => h.hostname === "api.telegram.org");
    assert.equal(telegramHops.length, 0, "api.telegram.org must never be dialed (no cross-host hop)");
    // And the Bearer only ever went to api.github.com.
    const bearerLeak = hops.some((h) => h.hostname !== "api.github.com" &&
      Object.entries(h.headers).some(([kk, vv]) => /authorization/i.test(kk) && /ghs_SECRET/.test(String(vv))));
    assert.equal(bearerLeak, false, "the GitHub Bearer must NEVER be forwarded to another host");
  });
});

test("#4 a SAME-host redirect IS followed (redirects still work within one host)", async () => {
  const k = freshKernel();
  const proxy = k.coreFor("fetch").proxy;
  let hopCount = 0;
  await withStubbedHttps({
    "api.github.com": null, // overridden below via a stateful script
  }, async (hops) => {
    // rebuild https stub with a same-host 302 then 200 (two hops, same host)
    const orig = https.request;
    https.request = (opts, cb) => {
      hopCount++;
      const res = new EventEmitter();
      const req = new EventEmitter();
      req.write = () => {}; req.destroy = () => {};
      req.end = () => setImmediate(() => {
        if (hopCount === 1) { res.statusCode = 302; res.headers = { location: "https://api.github.com/step2" }; }
        else { res.statusCode = 200; res.headers = {}; }
        cb(res);
        setImmediate(() => { res.emit("data", Buffer.from("done")); res.emit("end"); });
      });
      return req;
    };
    try {
      const r = await proxy("https://api.github.com/step1", { method: "GET" });
      assert.equal(r.ok, true, "same-host redirect followed to a 200");
      assert.equal(hopCount, 2, "exactly two same-host hops");
    } finally { https.request = orig; }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// #6 HIGH — telegram operator gate binds to SENDER, not just chat-id (I12).
// The kernel control plane refuses a rotate asserted by a non-operator group member.
// ─────────────────────────────────────────────────────────────────────────────
test("#6 rotate asserted by a group member (sender != operator) is refused: not_operator", async () => {
  const k = freshKernel({ OPERATOR_CHATS: "-100222", OPERATOR_SENDERS: "555" });
  const before = k.getDoorKey();
  const r = await k.control.rotate(["door-key"], {}, { chatId: "-100222", senderId: "777" });
  assert.equal(r.error, "not_operator", "a non-operator group member must be refused");
  assert.equal(k.getDoorKey(), before, "no rotation happened");
});

test("#6 rotate asserted by an operator SENDER in a group is authorized", async () => {
  const k = freshKernel({ OPERATOR_CHATS: "-100222", OPERATOR_SENDERS: "555" });
  const r = await k.control.rotate(["door-key"], {}, { chatId: "-100222", senderId: "555" });
  assert.ok(r._doorKey && r._doorKey.startsWith("bridge-"), "operator sender authorized");
});

test("#6 rotate from a DM (sender == chat) on OPERATOR_CHATS is authorized; a group with sender!=chat is not", async () => {
  const k = freshKernel({ OPERATOR_CHATS: "42", OPERATOR_SENDERS: "" });
  const dm = await k.control.rotate(["door-key"], {}, { chatId: "42", senderId: "42" });
  assert.ok(dm._doorKey, "genuine 1:1 DM authorized");
  const group = await k.control.rotate(["door-key"], {}, { chatId: "42", senderId: "99" });
  assert.equal(group.error, "not_operator", "same chat-id but sender!=chat (a group) is refused");
});

test("#6 the local CLI (no assertion) is still the operator — unchanged behavior", async () => {
  const k = freshKernel();
  const r = await k.control.rotate(["door-key"], {}); // no assertion == CLI
  assert.ok(r._doorKey, "CLI/host process remains the operator (§2.4)");
});

// ─────────────────────────────────────────────────────────────────────────────
// #7 MEDIUM — isBlockedIp must catch IPv6-embedded internal/metadata IPs (I8).
// ─────────────────────────────────────────────────────────────────────────────
test("#7 IPv6-embedded internal IPs are blocked (::a.b.c.d, 64:ff9b::, 2002::, ::ffff:)", () => {
  const { isBlockedIp } = _internals;
  // IPv4-compatible ::a.b.c.d
  assert.equal(isBlockedIp("::169.254.169.254"), true, "::169.254.169.254 (metadata) must block");
  assert.equal(isBlockedIp("::127.0.0.1"), true, "::127.0.0.1 (loopback) must block");
  assert.equal(isBlockedIp("::10.0.0.1"), true, "::10.0.0.1 (private) must block");
  // NAT64 64:ff9b::/96
  assert.equal(isBlockedIp("64:ff9b::169.254.169.254"), true, "NAT64 metadata must block");
  assert.equal(isBlockedIp("64:ff9b::a9fe:a9fe"), true, "NAT64 hex form of 169.254.169.254 must block");
  // 6to4 2002::/16  (2002:AABB:CCDD:: where AABB.CCDD = embedded v4)
  assert.equal(isBlockedIp("2002:a9fe:a9fe::"), true, "6to4 wrapping 169.254.169.254 must block");
  assert.equal(isBlockedIp("2002:0a00:0001::"), true, "6to4 wrapping 10.0.0.1 must block");
  // IPv4-mapped (already handled) still blocks
  assert.equal(isBlockedIp("::ffff:169.254.169.254"), true, "IPv4-mapped metadata still blocks");
  // a genuinely public v6 must NOT be blocked (guard against over-blocking)
  assert.equal(isBlockedIp("2606:4700:4700::1111"), false, "public v6 (1.1.1.1 DNS) must NOT block");
  // 6to4 wrapping a PUBLIC v4 must not block
  assert.equal(isBlockedIp("2002:0808:0808::"), false, "6to4 wrapping 8.8.8.8 (public) must NOT block");
});

// ─────────────────────────────────────────────────────────────────────────────
// #11 — scrub() redacts known secret shapes even adjacent to word chars / inside a URL (I9).
// ─────────────────────────────────────────────────────────────────────────────
test("#11 scrub redacts secrets adjacent to word chars and inside URLs/paths", () => {
  const { scrub } = _internals;
  // ghs_ token embedded in a word (no \b boundary on the left)
  const s1 = scrub("val_ghs_1234567890abcdefghijklmnopqrstuvwx");
  assert.ok(!s1.includes("ghs_1234567890abcdef"), `ghs token leaked: ${s1}`);
  // telegram bot token inside a URL path: /bot<token>/getUpdates
  const s2 = scrub("GET https://api.telegram.org/bot123456789:AAEabcdefghijklmnopqrstuvwxyz0123456789/getUpdates");
  assert.ok(!s2.includes("123456789:AAEabcdefghij"), `telegram token leaked: ${s2}`);
  // github_pat_
  const s3 = scrub("prefix-github_pat_11ABCDEFG0123456789abcdefghij_more end");
  assert.ok(!/github_pat_11ABCDEFG/.test(s3), `github_pat leaked: ${s3}`);
  // door-key adjacent to a word char
  const s4 = scrub("xbridge-deadbeefcafef00ddeadbeef");
  assert.ok(!s4.includes("bridge-deadbeefcafef00d"), `door-key leaked: ${s4}`);
  // classic \b-bounded still works (no regression)
  assert.ok(!scrub("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345").includes("ghp_ABCDEFGHIJ"));
});

test("#11 a real minted door-key never survives scrub (stack-trace path)", async () => {
  const k = freshKernel();
  const r = await k.control.rotate(["door-key"], {});
  const live = r._doorKey;
  const faked = `Error: boom at handler (secret is ${live}) in /bot${live}/x`;
  const cleaned = k.scrub(faked);
  assert.ok(!cleaned.includes(live), `the live door-key leaked through scrub: ${cleaned}`);
});
