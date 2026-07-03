/**
 * run.mjs — exec-class worked example (client picks a vetted script NAME).
 *
 * op=run&name=<vetted> -> core.exec(name, []) -> stdout of scripts/<name>(.sh|…).
 *
 * The client chooses WHICH vetted script to run by NAME only — never a command,
 * never a path, never an argument that becomes an executable token. This is the
 * whole point of the exec class: the caller selects from a fixed menu the operator
 * placed under EXEC_DIR; they cannot introduce a new command.
 *
 * Safety by construction (I7), defense in depth over the kernel's own core.exec clamps:
 *   - We forward ONLY params.name, and only if it matches ^[a-z0-9_-]+$ (same charset
 *     the kernel enforces). Any '/', '\\', '..', '.', NUL, dot-extension, or shell
 *     metacharacter fails the regex here and never reaches core.exec.
 *   - Args are ALWAYS the empty array []. No client value is ever passed as an argv
 *     token, so there is no argument-injection surface either.
 *   - core.exec then realpath-locks the name under EXEC_DIR, rejects symlink/`..`
 *     escape, spawns shell:false, and applies timeout + output cap. exec is OFF
 *     unless EXEC_ENABLED=1 + EXEC_DIR (else { ok:false, error:"exec_disabled" }).
 *
 * The module holds ZERO service policy: it does not know or care what temp.sh /
 * uptime.sh do. Want to restrict what can run? Curate the scripts dir — the bridge
 * stays dumb and generic.
 */

// Same charset the kernel's core.exec enforces. Reject anything with a path
// separator, traversal, dot-extension, whitespace, or shell metacharacter.
const VETTED_NAME = /^[a-z0-9_-]+$/;

export default {
  name: "run",
  public: false, // executing a vetted script needs the door-key.

  // PURE + SYNC. (I2)
  match(ctx) {
    return ctx.op === "run";
  },

  async handle(ctx) {
    const name = ctx.params.name;

    // The client supplies a NAME, nothing else. Validate the shape before touching
    // core.exec so a bad name is a clean 200-body error, not an exec_disabled/bad_name.
    if (typeof name !== "string" || !VETTED_NAME.test(name)) {
      return { ok: false, op: "run", error: "bad_name" };
    }

    // NAME only, EMPTY args. No client value ever becomes an executable/argv token. (I7)
    const r = await ctx.core.exec(name, []);
    if (!r.ok) {
      // Only the safe error code leaves the process — never stdout/stderr/env. (I9)
      return { ok: false, op: "run", name, error: r.error || "exec_failed" };
    }
    return {
      ok: true,
      op: "run",
      name,
      exit_code: r.exit_code,
      stdout: r.stdout || "",
      truncated: !!r.truncated,
    };
  },
};
