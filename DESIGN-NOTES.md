# get-hub — design notes (decisions + rationale)

> Companion to `SPEC.md`. SPEC = *what to build* (frozen contract). This = *why*, the
> decisions taken in design so nothing is lost. Draft, human-readable, load-bearing.

## Essence
get-hub = a **fetch-only gateway**: one GET-only signed HTTPS URL routes to pluggable
**modules**. Built for LLM chats that can only issue GET requests but need controlled
access to private APIs, a shell, or compute — without ever holding the real credentials.
Positioned as a **router with modules built in** (GitHub is just the flagship module).

## Two channels (never conflate them)
- **Control plane** = issuing/rotating keys & secrets. Operator-only. Via local CLI
  (`issue`/`kill`/`show`) or a whitelisted Telegram bot. This is where keys are born.
- **Data plane** = the fetch-only client actually using the bridge (`GET ?op=...`).
  Presents the door-key; never touches control.

## Key model (decided)
- **ONE door-key for the whole bridge** (not per-module). Simple; one secret to rotate.
  Rejected per-module secrets as key-juggling crutch. Future opt-in if per-client scoping
  is ever needed: **scoped-key** (one key carrying an allow-list of op names) — cleaner
  than N secrets, added without breaking anything.
- **Per-op `public` flag** decides *whether a key is needed* — decentralized: each module
  self-declares `public:true` (ping/info/ops — discovery/health, no key) or `false`
  (github/exec/fetch — needs door-key). Scales: 100 modules, same kernel gate; no central
  list to maintain.
- **ASLEEP ≠ off.** ASLEEP = no door-key minted yet. It gates **only** protected ops
  (`no_secret_server`/`no_sig`). Public ops answer always — you can ping a sleeping bridge
  to see it's alive and what it offers. Health/discovery work with zero secret.

## Secret model (decided) — three sourcing modes, one hook
The tension is real, no free lunch: **secret-at-rest ⟷ secret-in-URL ⟷ universality.**
A module optionally implements `rotate` to source its own injected secret. Three modes:

| mode | at-rest | in URL? | when |
|------|---------|---------|------|
| **1. mint ephemeral** (App/OAuth) | only the minting key; issued token is short-lived, scoped, revocable | **no** | **reference / prod** |
| **2. static env** (PAT) | long-lived token on disk (`.env` chmod 600) | **no** | convenience, opt-in |
| **3. caller-supplied** | nothing | **yes** (→ logs) | localhost / throwaway, opt-in |

- **Baseline = mode 1.** Bot/CLI mints a ~1h GitHub token into the store; disk/log leak =
  near-worthless expired token.
- **In modes 1–2 the real token never enters a URL and is never shown to the client** —
  it lives server-side in the store, injected as `Authorization` by the module.
- The client only ever holds the **door-key** (ephemeral, low-priv, revocable). A leaked
  door-key = someone can *call* the bridge for ≤TTL until you rotate — never the token
  itself (they'd go through the bridge, which you kill).

## Module contract (decided) — one shape, three optional surfaces
```
export default {
  name, public,
  match(ctx), handle(ctx),      // DATA plane: react to a client GET
  rotate({ttl, core}),          // CONTROL plane: mint/refresh own secret -> store (operator-triggered)
  start(core),                  // BACKGROUND plane: run once at boot, forever (e.g. TG poll)
}
```
Kernel phases, all uniform (zero per-module special-casing):
- **boot** → `module.start?.(core)` for each.
- **request** → kernel auth (unless public) → first `match` → `handle`.
- **control** → `rotate(names, ttlMap)` → door-key + named modules' `rotate`. Per-key =
  per-name; both/all = every name; any TTL per key.

Telegram = the canonical **3rd type** (background): boots a whitelisted long-poll; on ⚡
calls generic `core.control.rotate([...], ttl)`. Bot knows nothing service-specific.

## Security lives in 3 generic primitives (design law — no per-service policy in modules)
1. **kernel auth** — HMAC-SHA256, canonical `v1\n path \n sorted-params`, ts ±window,
   single-use nonce, constant-time compare. Full-sign (no secret in URL) or degraded
   `key=` (for dumb fetch clients). Runs in kernel, before dispatch, unbypassable.
2. **`core.proxy`** — https-only + `ALLOW_HOSTS` (post-normalization) + block
   private/link-local/loopback/metadata IPs (incl. 169.254.169.254, DNS-rebind pin) +
   no cross-host redirect + response cap. One boundary for every http module.
3. **`core.exec`** — named vetted scripts only (client passes a *name*, never a command),
   `spawn` arg-array `shell:false`, path-locked under scripts dir (realpath, no `..`),
   name `^[a-z0-9_-]+$`, timeout + output cap, **off by default** (`EXEC_ENABLED=0`).

GitHub module carries **no** policy (dropped `GITHUB_MODE`/`GITHUB_REPOS` — crutch): it
only injects the store token and calls `core.proxy`. Want it restricted? Scope the token
at GitHub — real enforcement, not a shim.

## Build gate: module linter
`lint.mjs` **fails the build** on contract violations (direct `child_process`/`fs`/`net`
import, impure `match`, `process.env` bypass of `ctx.env`, bad/dup `name`, exec shell
string, dead module). The linter is itself corner-case tested (path-traversal names,
unicode homoglyphs, aliased/dynamic imports, re-export tricks).

## Invariants I1–I12
See SPEC §6. Each must have a **red-team test that tries to violate it and fails.**
"Zero vulnerabilities" = every invariant tested + no open finding.

## Constraints (hard)
- **LAN only** this phase. `BIND` private. No public exposure / Tailscale Funnel.
- **No real secret in git — ever.** Placeholders only; token lives only in host `.env`.
- **Zero runtime deps** (Node ≥18 built-ins).
- **Don't weaken proven guards** (bad_sig/replay/ts_expired/bad_nonce/host_not_allowed
  passed 3 blind iterations — must still pass after refactor).

## Worked examples to ship (all real, lint-clean, tested, documented)
`ping`(public) · `hash`(compute) · `temp`(exec, server temperature via vetted script) ·
`run`(exec, client picks vetted name) · `fetch`(http via proxy) · `github`(http + inject
+ rotate) · `telegram`(start daemon + control). These double as the "write your own
module" library.

## Rename
Repo `bridge-mta` → **`get-hub`**. The get-hub product now lives at the repo root
(`github.com/list91/get-hub`); the old Worker + flat-port code is archived under `legacy/`.
