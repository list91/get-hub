/**
 * echo — public reflector. Returns ?msg= back to the caller.
 *
 * public:true => no door-key needed. Pure compute (no core.*). A trivial worked example of
 * reading ctx.params. The kernel strips `sig`/`key` from params BEFORE handle runs, so even
 * a caller who tucked a secret into those params cannot get it reflected here (I9).
 */
export default {
  name: "echo",
  public: true,

  // PURE + SYNC. (I2)
  match(ctx) {
    return ctx.op === "echo";
  },

  async handle(ctx) {
    const p = ctx.params || {};
    // `msg` is the documented input; default to empty string when absent.
    const msg = typeof p.msg === "string" ? p.msg : (p.msg == null ? "" : String(p.msg));
    return {
      ok: true,
      op: "echo",
      msg,
      len: msg.length,
    };
  },
};
