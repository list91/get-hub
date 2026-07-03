/**
 * github.mjs — the flagship http + secret-injection + rotate module.
 *
 * DATA plane (handle): op=github&t=https://api.github.com/...  ->
 *   read the server-side token from the store, inject `Authorization: Bearer <token>`,
 *   forward through core.proxy. The CLIENT never sends a token; the real credential
 *   lives only in the store (minted by rotate) and never enters a URL, a response, or a log.
 *
 * CONTROL plane (rotate): if App creds are present (APP_ID + INSTALL_ID + a PEM), mint a
 *   GitHub App JWT (RSA-SHA256) -> exchange for a ~1h installation token -> store at "token".
 *   Otherwise fall back to the static GITHUB_TOKEN (mode 2). Operator-triggered only (I12).
 *
 * ZERO per-service policy: no GITHUB_MODE, no GITHUB_REPOS, no method/path checks. The
 * bridge stays dumb and generic — scope the token at GitHub if you want it restricted (SPEC §5).
 * Security is entirely inherited from the 3 kernel primitives (auth, core.proxy SSRF clamp).
 *
 * Contract compliance:
 *   - match is pure/sync, touches only ctx (I2).
 *   - the outside world is reached ONLY via core.proxy — no node:fs / node:http / node:net
 *     imported for work (I3). node:crypto is pure compute (JWT signing) and is allowed.
 *   - config read ONLY from ctx.env / core.env (frozen GITHUB_* view), never process.env (I6).
 *   - no secret/token/PEM/stack ever placed in a returned object or a log (I9).
 */
import crypto from "node:crypto"; // pure compute only (RSA-SHA256 signing). NOT an I/O clamp.

const GH_HOST = "api.github.com";
const GH_ACCEPT = "application/vnd.github+json";
const GH_API_VERSION = "2022-11-28";

// base64url without padding — for the JWT header/payload/signature segments.
function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Resolve the PEM the operator supplied. Modules cannot read files (node:fs is a kernel-only
// clamp, I3), so the App private key is delivered INLINE via env: GITHUB_APP_PEM (the full
// PKCS#1/PKCS#8 block). APP_PEM_PATH is accepted for parity but is a no-op here by design —
// the module never touches the filesystem. Returns the PEM string or null.
function resolvePem(env) {
  const pem = env.APP_PEM || "";
  if (pem && /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(pem)) {
    // allow "\n"-escaped single-line PEMs (common when stuffed into a .env value)
    return pem.includes("\n") ? pem : pem.replace(/\\n/g, "\n");
  }
  return null;
}

// Do we have enough to attempt the App-JWT flow (mode 1)?
function hasAppCreds(env) {
  return !!(env.APP_ID && env.INSTALL_ID && resolvePem(env));
}

// Mint a GitHub App JWT (RS256) and exchange it for a short-lived installation token.
// Every outbound call goes through core.proxy => same https-only + allowlist + SSRF pin as
// the data plane. Never uses global fetch or node:http directly (I3/I8).
async function mintInstallationToken(core) {
  const env = core.env;
  const pem = resolvePem(env);
  const appId = String(env.APP_ID);
  const installId = String(env.INSTALL_ID);

  // iat backdated 60s for clock skew; exp within GitHub's 10-min JWT ceiling.
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
  const signingInput = `${header}.${payload}`;
  const sig = b64url(crypto.sign("RSA-SHA256", Buffer.from(signingInput), pem));
  const jwt = `${signingInput}.${sig}`;

  const r = await core.proxy(
    `https://${GH_HOST}/app/installations/${encodeURIComponent(installId)}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: GH_ACCEPT,
        "X-GitHub-Api-Version": GH_API_VERSION,
      },
    }
  );
  if (!r || !r.ok) {
    // r.body may echo GitHub's error text; DO NOT surface it (I9). Return a safe marker.
    const code = r ? r.error || `upstream_${r.upstream_status}` : "proxy_failed";
    throw new Error(`mint_failed:${code}`);
  }
  let parsed;
  try { parsed = JSON.parse(r.body); } catch { throw new Error("mint_failed:bad_json"); }
  if (!parsed || !parsed.token) throw new Error("mint_failed:no_token");
  return { token: parsed.token, expires_at: parsed.expires_at || null };
}

export default {
  name: "github",
  public: false, // door-key required — this reaches a private API.

  // PURE + SYNC (I2). Claim op=github targeting api.github.com. The kernel has already
  // normalized the `t=` hostname into ctx.host for op=do-style routing.
  match(ctx) {
    return ctx.op === "github" && ctx.host === GH_HOST;
  },

  // DATA plane. Inject the stored token, forward via core.proxy. Client sends NO token.
  async handle(ctx) {
    const target = ctx.params.t || "";
    // Defensive: never forward off-host even if routing changed. core.proxy re-checks the
    // allowlist anyway, but claim only what we matched.
    let host;
    try { host = new URL(target).hostname.toLowerCase().replace(/\.$/, ""); }
    catch { return { ok: false, error: "bad_target" }; }
    if (host !== GH_HOST) return { ok: false, error: "host_not_allowed", host };

    const token = ctx.core.store.get("token"); // namespaced -> "github:token"
    if (!token) {
      // ASLEEP for this module: operator hasn't run rotate yet. No token to inject.
      return { ok: false, error: "github_not_provisioned",
               hint: "Operator must rotate the github module to mint/store a token." };
    }

    // Build outbound headers off the kernel-provided bag (starts with User-Agent).
    const headers = { ...ctx.headers, Authorization: `Bearer ${token}`, Accept: GH_ACCEPT };
    // Method: GET/HEAD only reach here (kernel I10); pass ctx.method through unchanged.
    const method = ctx.method === "HEAD" ? "HEAD" : "GET";

    const r = await ctx.core.proxy(target, { method, headers });
    // core.proxy already shaped a safe result; pass it through as-is. It never contains the
    // token (that lived only in the request header, not the response).
    return r;
  },

  // CONTROL plane (operator-only, I12). Mode 1: App-JWT -> installation token (~1h).
  // Mode 2: static GITHUB_TOKEN. Stored server-side at "token"; NEVER returned/logged.
  async rotate({ ttl, core }) {
    const env = core.env;

    if (hasAppCreds(env)) {
      let minted;
      try { minted = await mintInstallationToken(core); }
      catch (e) {
        core.log(`rotate: app-mint failed (${String(e.message || e).slice(0, 40)})`);
        // fall through to static token if available, else report failure
        if (env.TOKEN) {
          core.store.set("token", env.TOKEN, ttl);
          return { minted: true, source: "static_fallback", expires_in: ttl };
        }
        return { minted: false, error: "mint_failed" };
      }
      // Prefer GitHub's real expiry to size the TTL; clamp to >=60s, cap by requested ttl.
      let ttlSec = ttl;
      if (minted.expires_at) {
        const secs = Math.floor(new Date(minted.expires_at).getTime() / 1000) - Math.floor(Date.now() / 1000);
        if (Number.isFinite(secs) && secs > 0) ttlSec = Math.min(ttl || secs, secs);
      }
      ttlSec = Math.max(60, ttlSec || 3600);
      core.store.set("token", minted.token, ttlSec);
      core.log(`rotate: minted installation token, ttl=${ttlSec}s`); // no token in the log
      return { minted: true, source: "app_installation", expires_in: ttlSec };
    }

    if (env.TOKEN) {
      core.store.set("token", env.TOKEN, ttl);
      core.log("rotate: stored static token");
      return { minted: true, source: "static", expires_in: ttl };
    }

    return { minted: false, error: "no_github_creds",
             hint: "Set GITHUB_APP_ID+GITHUB_INSTALL_ID+GITHUB_APP_PEM, or GITHUB_TOKEN." };
  },
};
