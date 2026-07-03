/**
 * get-hub module TEMPLATE. Copy this file, rename it, drop the leading underscore to arm it.
 * Files starting with "_" are NOT loaded (this is a starting point, not a live module).
 *
 * Fill in name/match/handle. Add rotate/start only if you need the control/background planes.
 * Read modules/CONTRACT.md for the full contract + exact core.* signatures.
 */
export default {
  name: "template",          // unique, /^[a-z0-9_-]+$/. Rename me.
  public: false,             // true => no door-key required (health/discovery only).

  // PURE + SYNC. Only inspect ctx to claim routing. No await, no core, no I/O. (I2)
  match(ctx) {
    return ctx.op === "template";
  },

  // Runs only AFTER auth (unless public). Return a plain JSON-serializable object.
  async handle(ctx) {
    // config comes from ctx.env (frozen, your namespace only). Never process.env. (I6)
    // outside world only via ctx.core.proxy / ctx.core.exec. (I3)
    // e.g. const r = await ctx.core.proxy("https://api.example.com/x", { method: "GET" });
    return { ok: true, echo: ctx.params };
  },

  // OPTIONAL control plane — mint this module's secret into the store (operator-triggered).
  // async rotate({ ttl, core }) {
  //   const tok = await mint(core.env);
  //   await core.store.set("token", tok, ttl);
  //   return { minted: true, expires_in: ttl };
  // },

  // OPTIONAL background plane — started once at boot, runs forever.
  // async start(core) { /* long-poll, etc. On operator trigger: core.control.rotate([...], {}) */ },
};
