/**
 * fetch.mjs — http class demo module (SSRF surface). Protected (needs door-key).
 *
 * Contract: `?op=fetch&t=https://<allowlisted-host>/path` → GET that URL through the
 * kernel's core.proxy primitive and return the response envelope.
 *
 * DESIGN LAW (SPEC §5, I8): this module carries ZERO per-service policy. It does NOT
 * validate the scheme, the host, the IP, redirects, or the response size — every one of
 * those clamps IS core.proxy, applied uniformly to every http module. fetch only:
 *   1. match op=fetch,
 *   2. read the client's `t=` target,
 *   3. hand it verbatim to core.proxy({ method: "GET" }).
 * The proxy primitive is the ONE boundary; weakening or duplicating it here would be a bug.
 *
 * It adds no secret (unlike github.mjs) — it's the naked http demo: the standard's proof
 * that "give me a URL, get the body" is safe purely because of the primitive, not because
 * the module is clever. (Compare github.mjs, which is fetch + one injected Bearer header.)
 */
export default {
  name: "fetch",
  public: false, // door-key required (I1) — an unauthenticated caller can't drive the proxy.

  // PURE + SYNC (I2): claim op=fetch. Nothing else — no core, no I/O, no host decisions here.
  // (Host allow/deny is the proxy's job, not routing's; we must still route so the caller
  //  gets a real host_not_allowed from the primitive rather than a silent 404.)
  match(ctx) {
    return ctx.op === "fetch";
  },

  // Runs only post-auth. The whole body is "forward t to the primitive".
  async handle(ctx) {
    const t = ctx.params.t;
    if (typeof t !== "string" || t === "") {
      return { ok: false, error: "missing_target", hint: "pass ?t=https://<allowlisted-host>/path" };
    }

    // NO local scheme/host/IP/redirect/size checks — that is precisely what core.proxy is.
    // Pass the raw client string; the primitive parses, normalizes, allowlists, pins DNS,
    // blocks private/metadata IPs, refuses cross-host redirects, and caps the body.
    const r = await ctx.core.proxy(t, { method: "GET" });

    // core.proxy already returns a safe, JSON-serializable envelope with no secret/stack.
    // Return it as-is; add nothing, hide nothing. `target_host` is the primitive's own
    // normalized host echo (present on host_not_allowed / redirect-refusal), safe to surface.
    return r;
  },
};
