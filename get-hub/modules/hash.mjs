/**
 * hash — the compute-class worked example (SPEC §5, table row "compute").
 *
 *   GET ?op=hash&s=<text>   ->  { ok:true, alg:"sha256", hex:"<64-char sha256 of s>", len }
 *
 * Protected (public:false): needs the door-key, like any real op. It is the SIMPLEST
 * protected module — pure CPU, ZERO core capability. No proxy, no exec, no store, no env.
 * It only reads ctx.params and computes with node:crypto in-process.
 *
 * Why node:crypto is allowed here: the I3 clamp is about the OUTSIDE WORLD (network / shell /
 * fs). Pure in-process compute — hashing, JSON, string work — is explicitly fine to do inline
 * (see modules/CONTRACT.md). crypto.createHash performs no I/O; the linter allows node:crypto.
 *
 * No secret ever touches this module: the input `s` is client-supplied plaintext and the
 * output is its digest — nothing sensitive to leak (I9 holds trivially).
 */
import crypto from "node:crypto";

const MAX_INPUT = 1_000_000; // 1 MB cap on the string to hash — a hash op is not a DoS lever.

export default {
  name: "hash",
  public: false, // protected: the simplest thing that still requires the door-key.

  // PURE + SYNC. Claim ?op=hash by inspecting ctx only. No await, no core, no I/O. (I2)
  match(ctx) {
    return ctx.op === "hash";
  },

  // Runs only AFTER kernel auth. Pure compute; returns a plain JSON-serializable object.
  async handle(ctx) {
    const s = ctx.params.s;
    if (typeof s !== "string") return { ok: false, error: "missing_s" };
    if (s.length > MAX_INPUT) return { ok: false, error: "input_too_large" };
    // Hash the UTF-8 bytes of the input. Pure CPU — no core.* needed.
    const hex = crypto.createHash("sha256").update(s, "utf8").digest("hex");
    return { ok: true, alg: "sha256", hex, len: s.length };
  },
};
