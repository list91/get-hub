/**
 * info — public discovery surface. The bridge's "who am I / what do I offer" card.
 *
 * Reports: version, proxy allow-hosts, the LIVE module/op catalog, and the github-policy
 * stance. All of this is public, non-secret metadata (I9). A caller can read it against an
 * ASLEEP bridge with no door-key.
 *
 * SOURCING: version, allow_hosts and the op catalog come from ctx.discovery — a frozen,
 * non-secret view the KERNEL builds from the actual loaded module set + global config. It
 * cannot drift from reality (no hand-maintained manifest) and never exposes a secret. The
 * module reads no process.env and touches no other module's namespace (I6).
 */

// The github stance is a fixed design statement, not a credential and not runtime policy:
// the github module carries NO per-service policy (no GITHUB_MODE/GITHUB_REPOS) — rights are
// governed by the token you scope at GitHub (SPEC §5/§7).
const GITHUB_POLICY = Object.freeze({
  built_in: true,
  bridge_side_policy: "none",
  rights_governed_by: "the GitHub token you provision (scope it read-only / to specific repos at GitHub)",
});

export default {
  name: "info",
  public: true,
  desc: "Discovery card: version, proxy allow-hosts, live op catalog, github stance.",

  // PURE + SYNC. (I2)
  match(ctx) {
    return ctx.op === "info";
  },

  async handle(ctx) {
    const d = ctx.discovery || { version: null, allow_hosts: [], ops: [] };
    const ops = Array.isArray(d.ops) ? d.ops : [];

    return {
      ok: true,
      op: "info",
      service: "get-hub",
      version: d.version || null,
      // proxy host allowlist — the REAL global policy the kernel enforces.
      allow_hosts: Array.isArray(d.allow_hosts) ? d.allow_hosts : [],
      // live op catalog (name + whether the door-key is required + background daemons).
      ops: ops.map((o) => ({ op: o.name, public: o.public, background: o.background, desc: o.desc })),
      // github policy VISIBILITY — the security stance, not a credential.
      github_policy: GITHUB_POLICY,
      // discovery hint for a fetch-only client: which ops it can call with no key.
      public_ops: ops.filter((o) => o.public).map((o) => o.name),
    };
  },
};
