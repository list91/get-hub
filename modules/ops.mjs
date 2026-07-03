/**
 * ops — public op-name index. Answers "what ops can I call here?".
 *
 * public:true. Pure compute, no core.*. Reads the LIVE registry from ctx.discovery (a frozen
 * non-secret view the kernel builds from the actual loaded modules — cannot drift). Returns
 * only op names + their public/protected + background flags; zero secrets (I9).
 */
export default {
  name: "ops",
  public: true,
  desc: "Lists the op names this bridge exposes and whether each needs the door-key.",

  // PURE + SYNC. (I2)
  match(ctx) {
    return ctx.op === "ops";
  },

  async handle(ctx) {
    const d = ctx.discovery || { ops: [] };
    const ops = Array.isArray(d.ops) ? d.ops : [];
    return {
      ok: true,
      op: "ops",
      count: ops.length,
      ops: ops.map((o) => o.name),
      // richer view: which ops need the door-key vs are public/discovery, and background daemons.
      detail: ops.map((o) => ({ op: o.name, public: o.public, background: o.background })),
    };
  },
};
