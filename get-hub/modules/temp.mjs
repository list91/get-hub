/**
 * temp.mjs — exec-class worked example (server temperature).
 *
 * op=temp -> core.exec("temp", []) -> the vetted scripts/temp.sh reads
 * /sys/class/thermal/thermal_zone0/temp and prints degrees Celsius.
 *
 * WHY this is safe by construction (I7): the module hard-codes BOTH the script
 * name ("temp") and the arg array ([]). The client supplies NOTHING that reaches
 * the shell — no command, no path, no argument. The only thing a caller can do is
 * ask for THIS one fixed reading. exec itself is OFF unless the operator set
 * EXEC_ENABLED=1 + EXEC_DIR (else core.exec returns { ok:false, error:"exec_disabled" }).
 *
 * The module carries ZERO policy of its own — every clamp (name regex, path-lock,
 * arg caps, shell:false, timeout, output cap) lives in the kernel's core.exec.
 */
export default {
  name: "temp",
  public: false, // reading host telemetry needs the door-key.

  // PURE + SYNC: only inspect ctx.op to claim routing. (I2)
  match(ctx) {
    return ctx.op === "temp";
  },

  // Runs only after auth. The name + args are FIXED here; nothing client-supplied
  // is forwarded to core.exec. (I7)
  async handle(ctx) {
    const r = await ctx.core.exec("temp", []);
    if (!r.ok) {
      // Surface only the safe error code — never stdout/stderr/env. (I9)
      return { ok: false, op: "temp", error: r.error || "exec_failed" };
    }
    const raw = (r.stdout || "").trim();
    const celsius = Number.parseFloat(raw);
    return {
      ok: true,
      op: "temp",
      celsius: Number.isFinite(celsius) ? celsius : null,
      raw,
      truncated: !!r.truncated,
    };
  },
};
