/**
 * ping — public liveness probe. The simplest worked example of the module contract.
 *
 * public:true => the kernel SKIPS auth (I1 gate applies only to non-public ops), so a
 * caller can confirm the bridge is alive even while it is ASLEEP (no door-key minted).
 * Pure compute, no core.* needed, no secrets — cannot leak anything (I9).
 */
export default {
  name: "ping",
  public: true,

  // PURE + SYNC: only inspects ctx.op. No await, no core, no I/O, no randomness. (I2)
  match(ctx) {
    return ctx.op === "ping";
  },

  async handle(ctx) {
    return {
      ok: true,
      pong: true,
      op: "ping",
      // echo the caller-supplied nonce back if present, so a client can correlate probes.
      // params has sig/key already stripped by the kernel; nothing sensitive here.
      t: (ctx.params && ctx.params.t) || null,
      time: Date.now(),
    };
  },
};
