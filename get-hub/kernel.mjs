/**
 * get-hub kernel — the fixed, security-bearing core.
 *
 * Lifecycle:  parse(req) -> authenticate(unless public) -> dispatch(first match wins) -> handle
 *
 * The kernel owns: parsing, auth (HMAC + nonce), the module registry/order, the response
 * writer, and the `core` capability object handed to modules. Modules carry ZERO per-service
 * policy — every security clamp (auth, proxy SSRF guards, exec RCE guards) lives HERE, in the
 * three generic primitives, applied uniformly. A module only: match -> inject its env secret
 * -> call a core.* primitive.
 *
 * ZERO runtime dependencies. Node >=18 built-ins only.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import https from "node:https";
import { spawn } from "node:child_process";
import { promises as dns } from "node:dns";
import net from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";

const SIG_VERSION = "v1";
const nowSec = () => Math.floor(Date.now() / 1000);

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
// Global kernel config is drawn from env once, here. Modules NEVER read process.env;
// they get a frozen per-namespace view via ctx.env (§4 / I6).
export function loadConfig(rawEnv = process.env) {
  // File-backed secrets (generic, module-agnostic): any `FOO_FILE=/path` whose `FOO` is
  // unset is expanded to FOO=<file contents>, read HERE in the trusted kernel. This lets a
  // module receive a large/multiline secret (e.g. a GitHub App PEM via GITHUB_APP_PEM_FILE)
  // through its frozen ctx.env WITHOUT the module ever touching node:fs (preserves I3).
  const env = { ...rawEnv };
  for (const k of Object.keys(env)) {
    if (k.endsWith("_FILE") && env[k]) {
      const base = k.slice(0, -"_FILE".length);
      if (!env[base]) {
        try { env[base] = fs.readFileSync(env[k], "utf8"); }
        catch { /* leave unset — the module surfaces its own not-provisioned error */ }
      }
    }
  }
  return {
    PORT: parseInt(env.PORT || "8787", 10),
    BIND: env.BIND || "127.0.0.1",
    STORE_PATH: env.STORE_PATH || fileURLToPath(new URL("./get-hub-store.json", import.meta.url)),
    ALLOW_HOSTS: (env.ALLOW_HOSTS || "api.github.com api.telegram.org")
      .split(/[,\s]+/).filter(Boolean).map((h) => normalizeHost(h)).filter(Boolean),
    KEY_TTL_SEC: parseInt(env.KEY_TTL_SEC || "3600", 10),
    TS_WINDOW_SEC: parseInt(env.TS_WINDOW_SEC || "3600", 10),
    // Operator identity for the control plane (I12), OWNED BY THE KERNEL — not a module.
    // OPERATOR_CHATS: chat-ids that are trusted 1:1 operator channels (a private DM where the
    //   chat IS the operator; sender need not be separately verified).
    // OPERATOR_SENDERS: sender (user) ids authorized to operate. REQUIRED to authorize a
    //   rotate from a SHARED/GROUP chat, where the chat-id is shared by many members and so
    //   cannot itself prove operator identity. Space/comma separated.
    OPERATOR_CHATS: (env.OPERATOR_CHATS || env.TELEGRAM_WHITELIST || "")
      .split(/[,\s]+/).map((s) => s.trim()).filter(Boolean),
    OPERATOR_SENDERS: (env.OPERATOR_SENDERS || "")
      .split(/[,\s]+/).map((s) => s.trim()).filter(Boolean),
    NONCE_TTL_SEC: parseInt(env.NONCE_TTL_SEC || env.TS_WINDOW_SEC || "3600", 10),
    DO_MAX_RESP: parseInt(env.DO_MAX_RESP || "100000", 10),
    EXEC_ENABLED: env.EXEC_ENABLED === "1" || env.EXEC_ENABLED === "true",
    EXEC_DIR: env.EXEC_DIR || "",
    EXEC_TIMEOUT_MS: parseInt(env.EXEC_TIMEOUT_MS || "10000", 10),
    EXEC_MAX_OUT: parseInt(env.EXEC_MAX_OUT || "65536", 10),
    EXEC_MAX_ARGS: parseInt(env.EXEC_MAX_ARGS || "16", 10),
    EXEC_MAX_ARG_LEN: parseInt(env.EXEC_MAX_ARG_LEN || "4096", 10),
    PROXY_TIMEOUT_MS: parseInt(env.PROXY_TIMEOUT_MS || "10000", 10),
    PROXY_MAX_REDIRECT: parseInt(env.PROXY_MAX_REDIRECT || "3", 10),
    UA: env.UA || "get-hub/1.0",
    VERSION: "get-hub-1.0.0",
    _env: env, // raw env kept private to the kernel for per-module namespacing
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Host normalization + IP classification (proxy SSRF primitive, §5.2 / I8)
// ─────────────────────────────────────────────────────────────────────────────
function normalizeHost(h) {
  if (typeof h !== "string" || !h) return "";
  let s = h.trim().toLowerCase();
  if (s.includes("@")) return "";                 // reject embedded credentials
  if (s.includes("/") || s.includes(" ")) return "";
  s = s.replace(/\.$/, "");                        // strip trailing dot (root fqdn)
  try {
    // punycode/IDN → ASCII. new URL lowercases + IDNA-encodes the hostname.
    const u = new URL("https://" + s + "/");
    // reject if URL parsing pulled in a port/user/path that changes host meaning
    if (u.username || u.password || u.port || u.pathname !== "/" || u.search || u.hash) return "";
    return u.hostname.replace(/\.$/, "");
  } catch { return ""; }
}

// Is the literal (already an IP) a blocked private/loopback/link-local/metadata target?
function isBlockedIp(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) {
    const p = ip.split(".").map(Number);
    if (p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = p;
    if (a === 0) return true;                        // 0.0.0.0/8
    if (a === 10) return true;                       // 10/8
    if (a === 127) return true;                      // loopback 127/8
    if (a === 169 && b === 254) return true;         // link-local incl 169.254.169.254 metadata
    if (a === 172 && b >= 16 && b <= 31) return true;// 172.16/12
    if (a === 192 && b === 168) return true;         // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return true;// 100.64/10 CGNAT
    if (a >= 224) return true;                        // multicast / reserved
    return false;
  }
  if (fam === 6) {
    let v = ip.toLowerCase();
    if (v.includes("%")) v = v.split("%")[0];        // strip zone id
    if (v === "::" || v === "::1") return true;      // unspecified / loopback
    if (v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb")) return true; // fe80::/10 link-local
    if (v.startsWith("fc") || v.startsWith("fd")) return true; // fc00::/7 ULA
    if (v.startsWith("ff")) return true;             // multicast

    // Normalize to 8 hextets so embedded-IPv4 forms can be classified uniformly.
    const hextets = expandV6(v);
    if (hextets) {
      // 6to4  2002:AABB:CCDD::/16 — the embedded IPv4 is hextet[1]:hextet[2].
      if (hextets[0] === 0x2002) {
        const embedded = `${(hextets[1] >> 8) & 0xff}.${hextets[1] & 0xff}.${(hextets[2] >> 8) & 0xff}.${hextets[2] & 0xff}`;
        if (isBlockedIp(embedded)) return true;
      }
      // NAT64  64:ff9b::/96 (and 64:ff9b:1::/48) — embedded IPv4 in the last two hextets.
      if (hextets[0] === 0x0064 && hextets[1] === 0xff9b) {
        const embedded = `${(hextets[6] >> 8) & 0xff}.${hextets[6] & 0xff}.${(hextets[7] >> 8) & 0xff}.${hextets[7] & 0xff}`;
        if (isBlockedIp(embedded)) return true;
      }
      // Embedded-IPv4 families — the embedded v4 is ALWAYS the last two hextets [6][7], and the
      // marker lives in hextets[4],[5], each of which is 0 or 0xffff across every real form:
      //   ::a.b.c.d            compatible  -> [4]=0      [5]=0
      //   ::ffff:a.b.c.d       mapped      -> [4]=0      [5]=0xffff
      //   ::ffff:0:a.b.c.d     translated  -> [4]=0xffff [5]=0        (SIIT/RFC6052 — the bypass)
      // Requiring top-4 zero + both markers in {0,0xffff} catches all three without over-blocking.
      const topFour = hextets[0] === 0 && hextets[1] === 0 && hextets[2] === 0 && hextets[3] === 0;
      const marker = (h) => h === 0 || h === 0xffff;
      if (topFour && marker(hextets[4]) && marker(hextets[5])) {
        const embedded = `${(hextets[6] >> 8) & 0xff}.${hextets[6] & 0xff}.${(hextets[7] >> 8) & 0xff}.${hextets[7] & 0xff}`;
        // ::0.0.0.0 / :: already handled; only classify a real embedded v4.
        if (!(hextets[6] === 0 && hextets[7] === 0) && isBlockedIp(embedded)) return true;
      }
    }
    return false;
  }
  return true; // not a recognizable IP → treat as blocked when used as literal
}

// Expand an IPv6 string to an array of 8 numeric hextets (0..0xffff), handling "::"
// compression and a trailing dotted-decimal IPv4 tail. Returns null if unparseable.
function expandV6(v) {
  let tailV4 = null;
  // A trailing dotted-decimal IPv4 (e.g. "::ffff:1.2.3.4" or "::1.2.3.4") becomes two hextets.
  const dotted = v.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) {
    const p = dotted[1].split(".").map(Number);
    if (p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    tailV4 = [(p[0] << 8) | p[1], (p[2] << 8) | p[3]];
    v = v.slice(0, dotted.index);   // strip the dotted tail (keeps any trailing ':')
  }

  // Split on "::" (zero-run compression). At most one allowed.
  const hasCompress = v.includes("::");
  const parts = v.split("::");
  if (parts.length > 2) return null;

  const toHextets = (str) => {
    if (str === "") return [];
    return str.split(":").filter((x) => x !== "").map((h) => {
      if (!/^[0-9a-f]{1,4}$/.test(h)) return NaN;
      return parseInt(h, 16);
    });
  };
  let head = toHextets(parts[0]);
  let tail = hasCompress ? toHextets(parts[1] || "") : [];
  if (tailV4) tail = tail.concat(tailV4);   // the dotted IPv4 occupies the last two hextets
  if (head.some(Number.isNaN) || tail.some(Number.isNaN)) return null;

  let hextets;
  if (hasCompress) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    hextets = [...head, ...Array(missing).fill(0), ...tail];
  } else {
    hextets = [...head, ...tail];
  }
  if (hextets.length !== 8) return null;
  return hextets;
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistent store (KV) + in-memory nonce map
// ─────────────────────────────────────────────────────────────────────────────
// KERNEL-RESERVED namespace prefixes. The door-key lives at "hmac:current"; the kernel
// keeps ALL of its own secrets under these prefixes in a PHYSICALLY SEPARATE map (not the
// module-visible JSON store). A per-module namespaced view can NEVER resolve to one of these
// (see makeStore.moduleView) — namespace isolation is enforced, not cosmetic prefixing (I6).
const RESERVED_PREFIXES = ["hmac:"];
function isReservedKey(key) {
  const k = String(key);
  return RESERVED_PREFIXES.some((p) => k.startsWith(p));
}

function makeStore(cfg) {
  function loadRaw() {
    try { return JSON.parse(fs.readFileSync(cfg.STORE_PATH, "utf8")); } catch { return {}; }
  }
  function saveRaw(s) {
    fs.writeFileSync(cfg.STORE_PATH, JSON.stringify(s), { mode: 0o600 });
  }
  function get(key) {
    const s = loadRaw();
    const e = s[key];
    if (!e) return null;
    if (e.exp && e.exp < nowSec()) { delete s[key]; saveRaw(s); return null; }
    return e.v;
  }
  function set(key, v, ttlSec) {
    const s = loadRaw();
    s[key] = { v, exp: ttlSec ? nowSec() + ttlSec : 0 };
    saveRaw(s);
  }
  function del(key) { const s = loadRaw(); delete s[key]; saveRaw(s); }

  // in-memory nonce map (lost on restart — ts window bounds replay). Kernel-internal.
  const nonces = new Map();
  function nonceSeen(n) {
    const now = nowSec();
    for (const [k, exp] of nonces) if (exp < now) nonces.delete(k);
    if (nonces.has(n)) return true;
    nonces.set(n, now + cfg.NONCE_TTL_SEC);
    return false;
  }

  // Per-module namespaced store view (I6). The module's key is prefixed with `${name}:`,
  // then HARD-CHECKED against the reserved kernel namespace. A module named "hmac" (or any
  // name whose prefix collides with a reserved kernel prefix) can NEVER read or write a
  // kernel-reserved key: any attempt resolves to a rejected no-op, so the door-key at
  // "hmac:current" is unreachable from a module. Isolation is enforced, not cosmetic.
  function moduleView(moduleName) {
    const ns = moduleName + ":";
    const resolve = (k) => ns + String(k);
    return {
      get(k) {
        const full = resolve(k);
        if (isReservedKey(full)) return null;         // reserved kernel key — deny read
        return get(full);
      },
      set(k, v, ttl) {
        const full = resolve(k);
        if (isReservedKey(full)) return false;         // reserved kernel key — deny write (no forge)
        return set(full, v, ttl);
      },
    };
  }

  return { get, set, del, nonceSeen, moduleView };
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret scrubbing for logs + responses (I9)
// ─────────────────────────────────────────────────────────────────────────────
function scrub(msg) {
  let s = typeof msg === "string" ? msg : safeStringify(msg);
  // NOTE: these deliberately do NOT use \b anchors. A \b boundary fails when a secret is
  // adjacent to a word char (e.g. `val_ghs_...`) or embedded in a URL/path (`/bot<token>/`),
  // which let real secrets slip through unredacted (I9). We match the secret SHAPE anywhere.
  s = s
    // GitHub PAT / App tokens: ghp_/ghs_/gho_/ghu_/ghr_ + github_pat_ , adjacent-safe.
    .replace(/gh[posur]_[A-Za-z0-9]{20,255}/g, "gh_***")
    .replace(/github_pat_[A-Za-z0-9_]{20,255}/g, "github_pat_***")
    // Telegram bot token: <digits>:<35+ base64url> — the ':' may be percent-encoded (%3A) because
    // the telegram module builds the URL via encodeURIComponent(token), so match both forms.
    .replace(/[0-9]{6,12}(?::|%3[Aa])[A-Za-z0-9_-]{30,}/g, "***:***")
    // door-keys: bridge-<hex>, adjacent-safe.
    .replace(/bridge-[a-f0-9]{16,}/g, "bridge-***")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]{10,}/gi, "Bearer ***")           // auth headers
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "***PEM***")
    .replace(/([?&](?:key|sig|token|secret)=)[^&\s"']+/gi, "$1***");        // secrets in URLs
  return s;
}
function safeStringify(o) { try { return JSON.stringify(o); } catch { return String(o); } }

// ─────────────────────────────────────────────────────────────────────────────
// HMAC auth (PORTED VERBATIM from proven server.mjs — do NOT weaken)
// ─────────────────────────────────────────────────────────────────────────────
function canonical(pathStr, params) {
  const enc = (s) => encodeURIComponent(String(s));
  const pairs = Object.entries(params)
    .filter(([k]) => k !== "sig")
    .map(([k, v]) => `${enc(k)}=${enc(v)}`)
    .sort();
  return `${SIG_VERSION}\n${pathStr}\n${pairs.join("&")}`;
}
function hmacHex(secret, msg) {
  return crypto.createHmac("sha256", secret).update(msg).digest("hex");
}
function ctEqual(a, b) {
  const ab = Buffer.from(String(a)), bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;      // length leak is unavoidable; content compared constant-time
  return crypto.timingSafeEqual(ab, bb);
}

// ─────────────────────────────────────────────────────────────────────────────
// core.proxy — the ONE outbound-HTTPS boundary (SSRF primitive, §5.2 / I8)
//
// Implemented on node:https (NOT global fetch) so we can pin DNS via a custom `lookup`
// while keeping the real hostname on the request → correct TLS SNI + cert validation +
// Host header. The pinned lookup can only ever hand the socket the pre-vetted public IP,
// which closes the DNS-rebind window (resolve→connect can't drift to a private address).
// ─────────────────────────────────────────────────────────────────────────────
function makeProxy(cfg) {
  async function resolvePinned(hostname) {
    // Literal IP → classify directly (no DNS).
    if (net.isIP(hostname)) {
      if (isBlockedIp(hostname)) return { blocked: true };
      return { ip: hostname, family: net.isIP(hostname) };
    }
    // Resolve DNS; block if ANY resolved address is private; pin the first public one.
    let addrs;
    try { addrs = await dns.lookup(hostname, { all: true }); }
    catch { return { error: "dns_failed" }; }
    if (!addrs.length) return { error: "dns_empty" };
    for (const a of addrs) if (isBlockedIp(a.address)) return { blocked: true };
    return { ip: addrs[0].address, family: addrs[0].family };
  }

  // One https.request hop, connecting ONLY to the pinned IP. hostname stays real (SNI/cert).
  function requestOnce(curUrl, method, headers, body, pin) {
    return new Promise((resolve) => {
      let settled = false;
      const done = (v) => { if (!settled) { settled = true; resolve(v); } };
      const req = https.request(
        {
          protocol: "https:",
          hostname: curUrl.hostname,          // real host → correct SNI + certificate check
          servername: curUrl.hostname,        // explicit SNI
          port: curUrl.port || 443,
          path: curUrl.pathname + curUrl.search,
          method,
          headers,                            // Host derived from hostname; do not override
          timeout: cfg.PROXY_TIMEOUT_MS,
          // Pin: force the socket to the vetted IP. lookup can't drift to a private addr.
          // Honor both callback shapes: `all:true` wants an array, else (err, addr, family).
          lookup: (h, o, cb) => (o && o.all)
            ? cb(null, [{ address: pin.ip, family: pin.family }])
            : cb(null, pin.ip, pin.family),
        },
        (res) => {
          const cap = cfg.DO_MAX_RESP;
          const chunks = [];
          let total = 0, truncated = false;
          res.on("data", (d) => {
            if (truncated) return;
            if (total + d.length > cap) { chunks.push(d.subarray(0, cap - total)); total = cap; truncated = true; res.destroy(); }
            else { chunks.push(d); total += d.length; }
          });
          res.on("end", () => done({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), truncated }));
          res.on("close", () => done({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), truncated }));
          res.on("error", () => done({ error: "upstream_failed" }));
        }
      );
      req.on("timeout", () => { req.destroy(); done({ error: "upstream_timeout" }); });
      req.on("error", () => done({ error: "upstream_failed" }));
      if (body && method !== "GET" && method !== "HEAD") req.write(body);
      req.end();
    });
  }

  async function proxy(targetUrl, opts = {}) {
    let target;
    try { target = new URL(String(targetUrl)); } catch { return { ok: false, error: "bad_target" }; }

    if (target.protocol !== "https:") return { ok: false, error: "only_https" };        // https only (I8)
    if (target.username || target.password) return { ok: false, error: "bad_target" };   // no embedded creds

    // Explicit port that changes host meaning: reject any port other than the https default
    // BEFORE the allowlist check. The allowlist is portless, so an explicit :22/:8080 on an
    // allowlisted host would otherwise pass the allowlist yet dial an arbitrary TCP port on the
    // pinned public IP (I8 §5.2 "reject explicit port that changes host meaning").
    if (target.port && target.port !== "443") return { ok: false, error: "bad_port", port: target.port };

    const host = normalizeHost(target.hostname);
    if (!host) return { ok: false, error: "bad_host" };
    if (!cfg.ALLOW_HOSTS.includes(host)) return { ok: false, error: "host_not_allowed", host };

    const method = String(opts.method || "GET").toUpperCase();
    const baseHeaders = { "User-Agent": cfg.UA, ...(opts.headers || {}) };
    // strip any caller-supplied Host — it's derived from the URL, never client-forgeable.
    for (const k of Object.keys(baseHeaders)) if (k.toLowerCase() === "host") delete baseHeaders[k];

    let curUrl = target;
    let curHost = host;
    for (let hop = 0; hop <= cfg.PROXY_MAX_REDIRECT; hop++) {
      if (!cfg.ALLOW_HOSTS.includes(curHost)) return { ok: false, error: "host_not_allowed", host: curHost };

      const pin = await resolvePinned(curUrl.hostname);       // resolve + pin + block private/rebind (I8)
      if (pin.blocked) return { ok: false, error: "blocked_ip", host: curHost };
      if (pin.error) return { ok: false, error: "dns_failed", host: curHost };

      const r = await requestOnce(curUrl, method, baseHeaders, opts.body, pin);
      if (r.error) return { ok: false, error: r.error, host: curHost };

      // Redirects: follow ONLY when the Location is the SAME host (true no-cross-host, I8 §5.2).
      // Cross-host redirects are NEVER followed — otherwise an injected credential header (e.g.
      // github's `Authorization: Bearer <token>` in baseHeaders) would be re-issued to a
      // DIFFERENT allowlisted host (GitHub→Telegram) and exfiltrate the secret. Same-host-only
      // means baseHeaders can be safely re-sent (the credential stays with its intended host).
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        let loc;
        try { loc = new URL(r.headers.location, curUrl); } catch { return { ok: false, error: "bad_redirect" }; }
        if (loc.protocol !== "https:") return finalize(r, { redirect_not_followed: true, reason: "non_https" });
        // reject a redirect that introduces an explicit non-443 port (same port-meaning rule).
        if (loc.port && loc.port !== "443") return finalize(r, { redirect_not_followed: true, reason: "bad_port" });
        const locHost = normalizeHost(loc.hostname);
        if (!locHost || !cfg.ALLOW_HOSTS.includes(locHost))
          return finalize(r, { redirect_not_followed: true, location_host: locHost || null });
        if (locHost !== curHost)                       // cross-host redirect → do NOT follow (never carry creds off-host)
          return finalize(r, { redirect_not_followed: true, reason: "cross_host", location_host: locHost });
        if (hop === cfg.PROXY_MAX_REDIRECT) return finalize(r, { too_many_redirects: true });
        curUrl = loc; curHost = locHost;
        continue;
      }
      return finalize(r, {});
    }
    return { ok: false, error: "too_many_redirects" };
  }

  function finalize(r, flags) {
    const okStatus = r.status >= 200 && r.status < 300;
    return {
      ok: okStatus,
      upstream_status: r.status,
      error: okStatus ? null : "upstream_error",
      hint: okStatus ? null : `Upstream status ${r.status}.`,
      fetched_at: new Date().toISOString(),
      truncated: !!r.truncated,
      body: r.body,
      ...flags,
    };
  }

  return proxy;
}

// ─────────────────────────────────────────────────────────────────────────────
// core.exec — the ONE shell boundary (RCE primitive, §5.1 / I7)
// OFF by default. Named vetted scripts only, arg-array, no shell, path-locked.
// ─────────────────────────────────────────────────────────────────────────────
function makeExec(cfg) {
  return async function exec(name, args = []) {
    if (!cfg.EXEC_ENABLED) return { ok: false, error: "exec_disabled" };
    if (!cfg.EXEC_DIR) return { ok: false, error: "exec_disabled" };

    // name: vetted, no path, no traversal.
    if (typeof name !== "string" || !/^[a-z0-9_-]+$/.test(name)) return { ok: false, error: "bad_name" };

    // args: array of strings only, capped, no NUL. Never become executable tokens.
    if (!Array.isArray(args)) return { ok: false, error: "bad_args" };
    if (args.length > cfg.EXEC_MAX_ARGS) return { ok: false, error: "too_many_args" };
    const argv = [];
    for (const a of args) {
      const s = String(a);
      if (s.length > cfg.EXEC_MAX_ARG_LEN) return { ok: false, error: "arg_too_long" };
      if (s.includes("\0")) return { ok: false, error: "bad_arg" };
      argv.push(s);
    }

    // Path lock: script must resolve to a real file under EXEC_DIR (realpath, no symlink escape).
    let dirReal, scriptReal;
    try { dirReal = await fsp.realpath(cfg.EXEC_DIR); }
    catch { return { ok: false, error: "exec_dir_missing" }; }
    const candidate = path.join(dirReal, name);
    try { scriptReal = await fsp.realpath(candidate); }
    catch { return { ok: false, error: "no_such_script" }; }
    const rel = path.relative(dirReal, scriptReal);
    if (rel.startsWith("..") || path.isAbsolute(rel)) return { ok: false, error: "path_escape" };
    try { const st = await fsp.stat(scriptReal); if (!st.isFile()) return { ok: false, error: "not_a_file" }; }
    catch { return { ok: false, error: "no_such_script" }; }

    // spawn, shell:false, arg array, timeout, output cap.
    return await new Promise((resolve) => {
      let child;
      try {
        child = spawn(scriptReal, argv, { shell: false, cwd: dirReal, env: {}, stdio: ["ignore", "pipe", "pipe"] });
      } catch { return resolve({ ok: false, error: "spawn_failed" }); }

      let out = "", errOut = "", killed = false, outCap = false;
      const timer = setTimeout(() => { killed = true; try { child.kill("SIGKILL"); } catch {} }, cfg.EXEC_TIMEOUT_MS);
      child.stdout.on("data", (d) => {
        if (out.length < cfg.EXEC_MAX_OUT) out += d.toString("utf8");
        if (out.length >= cfg.EXEC_MAX_OUT) { outCap = true; }
      });
      child.stderr.on("data", (d) => { if (errOut.length < cfg.EXEC_MAX_OUT) errOut += d.toString("utf8"); });
      child.on("error", () => { clearTimeout(timer); resolve({ ok: false, error: "spawn_failed" }); });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (killed) return resolve({ ok: false, error: "timeout" });
        resolve({
          ok: code === 0,
          exit_code: code,
          error: code === 0 ? null : "nonzero_exit",
          stdout: out.slice(0, cfg.EXEC_MAX_OUT),
          truncated: outCap,
        });
      });
    });
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// core object factory — per-module namespaced view (I6)
// ─────────────────────────────────────────────────────────────────────────────
function makeCore(cfg, store, control, proxyFn, execFn) {
  // Build the base (module-agnostic) core once; per-module views wrap store + log.
  //
  // TWO planes, structurally separated (I12):
  //   - DATA plane core (privileged=false): handed to module.handle(), reached by a mere
  //     door-key holder. It has NO `control` capability — a data-plane handle() literally
  //     cannot see or call rotate. This closes the escalation/exfil where a handle rotated the
  //     door-key and returned the raw minted key.
  //   - CONTROL plane core (privileged=true): handed ONLY to the operator surfaces start()
  //     and rotate(). It carries `control.rotate` because those callers ARE the operator
  //     (booted daemon asserting operator identity, or the CLI). The raw _doorKey lives only
  //     on results returned to these privileged callers, never reachable from handle().
  return function forModule(moduleName, { privileged = false } = {}) {
    const base = {
      proxy: proxyFn,
      exec: execFn,
      store: store.moduleView(moduleName),
      log(safeMsg) { console.log(`[${moduleName}] ${scrub(safeMsg)}`); },
      // frozen per-module env view injected by the kernel per-request as ctx.env;
      // also exposed here for start()/rotate() surfaces.
      env: control.envFor(moduleName),
    };
    if (privileged) {
      // Module-facing control surface (start()/rotate()). A module may OBSERVE an operator
      // gesture (e.g. telegram) and forward the RAW identity it saw; the KERNEL decides operator
      // status. Crucially a module must NEVER be able to present the "local CLI" identity
      // (assertion == null), which authorizes UNCONDITIONALLY — only the host process
      // (server.mjs, via the returned kernel.control) may. So we FORCE a non-null assertion here:
      // a module that passes null/undefined is coerced to an empty (non-operator) identity and
      // refused by operatorAuthorized(). This structurally defeats CROSS-SURFACE CAPABILITY
      // CAPTURE — a handle() that stashed this rotate via a start()/rotate() closure still cannot
      // self-authorize, so it can never mint or exfiltrate the door-key. (I12)
      base.control = {
        rotate: (names, ttlMap, assertion) =>
          control.rotate(names, ttlMap, assertion == null ? { chatId: "", senderId: "" } : assertion),
      };
    }
    return base;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-module env isolation (I6): frozen view of only NAMESPACE_* keys.
// e.g. module "github" sees GITHUB_TOKEN, GITHUB_APP_ID, ... as { TOKEN, APP_ID, ... }.
// ─────────────────────────────────────────────────────────────────────────────
function envFor(rawEnv, moduleName) {
  const prefix = moduleName.toUpperCase().replace(/-/g, "_") + "_";
  const view = {};
  for (const [k, v] of Object.entries(rawEnv)) {
    if (k.startsWith(prefix)) view[k.slice(prefix.length)] = v;
  }
  return Object.freeze(view);
}

// ─────────────────────────────────────────────────────────────────────────────
// Module registry — auto-load modules/*.mjs, deterministic order (I11 order)
// ─────────────────────────────────────────────────────────────────────────────
export async function loadModules(dir) {
  let files = [];
  // Load *.mjs, but skip leading-underscore files (templates/helpers) and *.test.mjs
  // (test files may live beside modules and have no default export — must not crash boot).
  try {
    files = fs.readdirSync(dir).filter(
      (f) => f.endsWith(".mjs") && !f.startsWith("_") && !f.endsWith(".test.mjs")
    );
  } catch { files = []; }
  files.sort(); // deterministic dispatch order
  const mods = [];
  const seen = new Set();
  const seenEnvPrefix = new Map(); // normalized env prefix "NAME_" -> module name (collision guard)
  for (const f of files) {
    const url = pathToFileURL(path.join(dir, f)).href;
    const m = (await import(url)).default;
    if (!m || typeof m !== "object") throw new Error(`module ${f}: no default export object`);
    if (typeof m.name !== "string" || !/^[a-z0-9_-]+$/.test(m.name)) throw new Error(`module ${f}: bad name`);
    if (seen.has(m.name)) throw new Error(`module ${f}: duplicate name "${m.name}"`);
    // Env-namespace collision (I6): envFor selects keys by PREFIX-CONTAINMENT
    // (k.startsWith(NAME_)), so two modules whose prefixes are in a prefix RELATIONSHIP leak into
    // each other — not only exact twins ("secure-echo" ≡ "secure_echo" → SECURE_ECHO_*), but also
    // containment ("git" → GIT_* swallows "git-hub" → GIT_HUB_*, so `git` reads GIT_HUB_TOKEN).
    // Reject if the new prefix is a prefix of, or has as a prefix, any already-seen prefix.
    const envPrefix = m.name.toUpperCase().replace(/-/g, "_") + "_";
    for (const [seenPrefix, seenName] of seenEnvPrefix) {
      if (envPrefix.startsWith(seenPrefix) || seenPrefix.startsWith(envPrefix)) {
        throw new Error(`module ${f}: env-namespace collision — "${m.name}" (${envPrefix}*) and "${seenName}" (${seenPrefix}*): one prefix contains the other, secrets would leak (I6)`);
      }
    }
    seenEnvPrefix.set(envPrefix, m.name);
    seen.add(m.name);
    mods.push(m);
  }
  return mods;
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel construction
// ─────────────────────────────────────────────────────────────────────────────
export function createKernel(cfg, modules) {
  const store = makeStore(cfg);

  // Operator-identity gate (I12) — KERNEL-OWNED. A module that observes an inbound operator
  // gesture (e.g. telegram) forwards the raw identity it saw ({ chatId, senderId }); the KERNEL
  // decides whether that identity is the operator. Modules carry ZERO operator policy.
  //
  // Rules:
  //   - No assertion (assertion == null): the caller is the LOCAL CLI/host process, which IS the
  //     operator by §2.4 — always authorized. (CLI passes no assertion.)
  //   - With an assertion: authorize iff the SENDER is a known operator. A chat-id alone is NOT
  //     sufficient for a SHARED/GROUP channel (many members share it); binding to sender-id
  //     (from.id) is required. We accept the sender if EITHER:
  //       (a) senderId ∈ OPERATOR_SENDERS, OR
  //       (b) the channel is a genuine 1:1 operator channel: chatId ∈ OPERATOR_CHATS AND the
  //           chat is a private/direct chat (sender == chat, i.e. a DM — no other member can
  //           impersonate the operator). A group chat-id (sender != chat) never qualifies via (b).
  // Membership via a captured-arithmetic loop, NOT Array.prototype.includes: `.includes` is a
  // mutable global a malicious in-process module could overwrite (Array.prototype.includes = ()=>
  // true) to force-authorize. `===` and index access cannot be polluted, so the gate holds even
  // if a module tampers with prototypes before calling a captured rotate.
  function inList(list, x) {
    if (!Array.isArray(list)) return false;
    for (let i = 0; i < list.length; i++) if (list[i] === x) return true;
    return false;
  }
  function operatorAuthorized(assertion) {
    if (assertion == null) return true;              // local CLI/host = operator (§2.4)
    const chatId = assertion.chatId != null ? String(assertion.chatId) : "";
    const senderId = assertion.senderId != null ? String(assertion.senderId) : "";
    if (senderId && inList(cfg.OPERATOR_SENDERS, senderId)) return true;                // (a)
    if (chatId && senderId && chatId === senderId && inList(cfg.OPERATOR_CHATS, chatId))
      return true;                                                                       // (b) DM
    return false;
  }

  // control plane (I12): rotate the kernel door-key + named modules' rotate hooks.
  const control = {
    envFor: (name) => envFor(cfg._env, name),
    operatorAuthorized,
    async rotate(names, ttlMap = {}, assertion = null) {
      // Enforce operator identity at the kernel boundary (I12). A rotate from a non-operator
      // (e.g. an ordinary member of a whitelisted group) is refused HERE, in the kernel.
      if (!operatorAuthorized(assertion)) return { error: "not_operator" };
      const results = {};
      // rotate kernel door-key unless names explicitly excludes it
      const wantKey = !Array.isArray(names) || names.length === 0 || names.includes("door-key") || names.includes("_key");
      if (wantKey) {
        const ttl = ttlMap["door-key"] ?? ttlMap._key ?? cfg.KEY_TTL_SEC;
        const key = "bridge-" + crypto.randomBytes(24).toString("hex");
        store.set("hmac:current", key, ttl);
        results["door-key"] = { minted: true, expires_in: ttl };
        // return the door-key ONLY to the operator caller (CLI). It is never logged.
        results._doorKey = key;
      }
      const targetNames = Array.isArray(names) && names.length
        ? names.filter((n) => n !== "door-key" && n !== "_key")
        : [];
      for (const name of targetNames) {
        const mod = modules.find((m) => m.name === name);
        if (!mod) { results[name] = { error: "no_such_module" }; continue; }
        if (typeof mod.rotate !== "function") { results[name] = { error: "no_rotate_hook" }; continue; }
        const ttl = ttlMap[name] ?? cfg.KEY_TTL_SEC;
        try {
          // rotate() is an operator/control-plane surface → hand it a PRIVILEGED core.
          results[name] = await mod.rotate({ ttl, core: privilegedCoreFor(name) });
        } catch (e) { results[name] = { error: "rotate_failed" }; console.error(`[kernel] rotate ${name}: ${scrub(String(e))}`); }
      }
      return results;
    },
  };

  const proxyFn = makeProxy(cfg);
  const execFn = makeExec(cfg);
  const coreFactory = makeCore(cfg, store, control, proxyFn, execFn);
  // DATA-plane core (no control) — for module.handle(). CONTROL-plane core (with control) —
  // only for the operator surfaces start()/rotate(). Keeping them distinct is the I12 boundary.
  const coreFor = (name) => coreFactory(name, { privileged: false });
  const privilegedCoreFor = (name) => coreFactory(name, { privileged: true });

  function getDoorKey() { return store.get("hmac:current") || ""; }

  // ── auth (kernel-owned, before dispatch, unbypassable I1/I4) ──
  // Ported verbatim from proven server.mjs verifyRequest, plus degraded key= form.
  function authenticate(pathStr, params) {
    const secret = getDoorKey();
    const hasSig = !!params.sig;
    const hasKey = !!params.key;

    // Degraded key= form (for fetch-only clients that cannot sign).
    if (!hasSig && hasKey) {
      if (!secret) return { ok: false, err: "no_secret_server" };
      if (!ctEqual(params.key, secret)) return { ok: false, err: "bad_key" };
      return { ok: true };
    }

    // Full HMAC form.
    if (!hasSig) return { ok: false, err: "no_sig" };
    if (!params.ts) return { ok: false, err: "no_ts" };
    const ts = parseInt(params.ts, 10);
    if (!Number.isFinite(ts)) return { ok: false, err: "bad_ts" };
    if (Math.abs(nowSec() - ts) > cfg.TS_WINDOW_SEC) return { ok: false, err: "ts_expired" };
    const nonce = params.nonce || "";
    if (nonce.length < 8 || nonce.length > 128) return { ok: false, err: "bad_nonce" };
    if (!secret) return { ok: false, err: "no_secret_server" };
    if (!ctEqual(params.sig, hmacHex(secret, canonical(pathStr, params)))) return { ok: false, err: "bad_sig" };
    // nonce check is LAST (after sig) so an unsigned attacker can't burn nonces.
    if (store.nonceSeen(nonce)) return { ok: false, err: "replay" };
    return { ok: true };
  }

  // ── parse ──
  function parse(req) {
    const url = new URL(req.url, "http://x");
    const params = Object.fromEntries(url.searchParams);
    const op = params.op || "";
    // op=do style host extraction: hostname of the `t=` target, else null.
    let host = null;
    if (params.t) { try { host = normalizeHost(new URL(params.t).hostname) || null; } catch { host = null; } }
    return { url, params, op, method: req.method, pathStr: url.pathname, host };
  }

  // ── dispatch: first module.match wins (I2 — match pure/sync) ──
  function dispatch(ctx) {
    for (const m of modules) {
      let claimed;
      try { claimed = m.match(ctx); } catch { claimed = false; } // match must not throw; treat as no-match
      if (claimed) return m;
    }
    return null;
  }

  // Safe, non-secret discovery view of the LIVE registry + global proxy policy. Built from
  // the actual loaded modules (no hand-maintained manifest → cannot drift). Handed to every
  // module via ctx.discovery so info/ops report the real set. Contains only op names, their
  // public/background flags, optional module-declared desc, the version, and the proxy
  // allow-hosts — all non-sensitive policy the public `info` op is meant to expose (I9).
  const discovery = Object.freeze({
    version: cfg.VERSION,
    allow_hosts: Object.freeze([...cfg.ALLOW_HOSTS]),
    ops: Object.freeze(modules.map((m) => Object.freeze({
      name: m.name,
      public: !!m.public,
      background: typeof m.handle !== "function" && typeof m.start === "function",
      desc: typeof m.desc === "string" ? m.desc : null,
    }))),
  });

  // Build the ctx handed to a module (sig/key stripped from params before handle).
  function buildCtx(parsed, moduleName) {
    const params = { ...parsed.params };
    delete params.sig; delete params.key;
    return {
      op: parsed.op,
      params,
      method: parsed.method,
      url: parsed.url,
      host: parsed.host,
      headers: { "User-Agent": cfg.UA },
      env: envFor(cfg._env, moduleName),
      core: coreFor(moduleName),
      discovery,
    };
  }

  // ── the request lifecycle: parse -> authenticate(unless public) -> dispatch -> handle ──
  async function handleRequest(req) {
    // GET/HEAD only (I10).
    if (req.method !== "GET" && req.method !== "HEAD") return { status: 405, body: { ok: false, error: "method_not_allowed" } };

    const parsed = parse(req);

    // Bare hit (no op): public liveness.
    if (!parsed.op) return { status: 200, body: { ok: true, msg: "get-hub alive", v: cfg.VERSION, time: Date.now() } };

    // Route on an UNAUTHENTICATED ctx first (match is pure/routing-only, I2).
    // The matched module tells us whether the op is public.
    const routeCtx = {
      op: parsed.op, params: parsed.params, method: parsed.method,
      url: parsed.url, host: parsed.host, headers: {}, env: {}, core: null,
    };
    const mod = dispatch(routeCtx);
    if (!mod) return { status: 404, body: { ok: false, error: "no_such_op", op: parsed.op } };

    // Auth-before-handle for non-public ops (I1). Unbypassable — happens here, in the kernel.
    if (!mod.public) {
      const auth = authenticate(parsed.pathStr, parsed.params);
      if (!auth.ok) return { status: 401, body: { ok: false, error: auth.err } };
    }

    // handle runs only now, post-auth, with a real core + frozen env (I3/I6).
    const ctx = buildCtx(parsed, mod.name);
    try {
      const result = await mod.handle(ctx);
      return { status: 200, body: result };
    } catch (e) {
      console.error(`[kernel] module_error ${mod.name}: ${scrub(String(e && e.stack || e))}`);
      return { status: 500, body: { ok: false, error: "module_error" } }; // no stack, no secret (I9)
    }
  }

  // ── boot phase: start each module's background surface once ──
  async function boot() {
    for (const m of modules) {
      if (typeof m.start === "function") {
        // start() is the operator/background surface → hand it a PRIVILEGED core (control.rotate).
        // FIRE-AND-FORGET, never await: a background daemon (e.g. telegram long-poll) legitimately
        // never returns. Awaiting it would block boot() → the caller (server.mjs) would never reach
        // srv.listen() and the HTTP port would never bind. Launch detached; surface errors async.
        Promise.resolve()
          .then(() => m.start(privilegedCoreFor(m.name)))
          .catch((e) => console.error(`[kernel] start ${m.name}: ${scrub(String(e))}`));
      }
    }
  }

  return {
    cfg, store, modules,
    handleRequest, boot,
    authenticate, canonical, hmacHex, // exposed for tests / CLI signing helpers
    control,
    getDoorKey,
    isAsleep: () => !getDoorKey(),
    coreFor,
    // response writer helper for the server entry
    scrub,
  };
}

// exported for the linter + tests
export const _internals = { normalizeHost, isBlockedIp, canonical, hmacHex, ctEqual, scrub, envFor };
