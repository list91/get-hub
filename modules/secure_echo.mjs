/**
 * secure_echo — PROTECTED reflector. Proves the kernel auth gate (I1) and secret-stripping.
 *
 * public:false => the kernel runs full auth (HMAC `sig` or degraded `key=`) BEFORE handle is
 * ever called. If we get here, the caller is authenticated. We then echo params back.
 *
 * The whole point of this module is to demonstrate that `sig` AND `key` are NOT present in
 * ctx.params — the kernel strips them in buildCtx() before handle runs. So even though this
 * op requires the door-key, the door-key value is never reflected back to the caller (I9).
 * We defensively re-strip any residual auth-ish keys as belt-and-suspenders.
 */

// Keys we refuse to reflect even if they somehow survived (defense in depth for I9).
const NEVER_ECHO = new Set(["sig", "key", "secret", "token", "password"]);

export default {
  name: "secure_echo",
  public: false, // door-key REQUIRED — kernel auth runs before handle (I1).

  // PURE + SYNC. (I2)
  match(ctx) {
    return ctx.op === "secure_echo";
  },

  async handle(ctx) {
    const src = ctx.params || {};
    const echoed = {};
    let stripped = 0;
    for (const [k, v] of Object.entries(src)) {
      if (NEVER_ECHO.has(k.toLowerCase())) { stripped++; continue; }
      echoed[k] = v;
    }
    return {
      ok: true,
      op: "secure_echo",
      authenticated: true, // we only reach handle() post-auth for a non-public op
      // Proof of the invariant: sig/key are absent because the kernel stripped them.
      sig_present: Object.prototype.hasOwnProperty.call(src, "sig"),
      key_present: Object.prototype.hasOwnProperty.call(src, "key"),
      stripped_sensitive: stripped,
      params: echoed,
    };
  },
};
