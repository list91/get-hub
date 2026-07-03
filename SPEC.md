# get-hub — module system SPEC (frozen contract)

> **Status: frozen.** This is the single source of truth every build/audit/test agent
> works against. Do not deviate. If something here is wrong, change *this file* first,
> then rebuild — never let an agent silently reinterpret it.

get-hub is a **fetch-only gateway**: one GET-only signed HTTPS URL routes to pluggable
**modules**. The kernel authenticates the request, then dispatches to the first module
that claims it. Everything user-visible (`ping`, `info`, `do`, GitHub, demos) is a
module. The kernel itself is small, fixed, and security-bearing.

This SPEC generalizes the already-proven `legacy/server-node/server.mjs` (HMAC + `op=do` +
GitHub injection, blind-deployed 3× on the Pi). We **refactor** that working code into
kernel + modules — we do not rewrite from scratch, and we do not weaken any guard that
already passed.

---

## 1. Kernel (fixed — modules cannot alter this)

Request lifecycle, in order:

1. **parse** — method, path, query params, headers. GET/HEAD only; anything else → `405`.
2. **authenticate** — unless the matched op is `public`, verify auth (§3). Fail → reject
   *before* any module runs. **This step lives in the kernel and no module can bypass,
   disable, or run before it.** (Invariant I1.)
3. **dispatch** — walk the module registry in order; call `module.match(ctx)`; first
   truthy wins. No match → `404 no_such_op`.
4. **handle** — `await module.handle(ctx)` → the kernel serializes the result to JSON and
   responds. A thrown error → `500 module_error` with a safe message (no stack, no secret).

The kernel owns: parsing, auth, nonce store, the module registry/order, the response
writer, and the `core` capability object handed to modules. Nothing else.

### 1.1 Auth-before-dispatch is load-bearing

A module's `match()` may be called on an **unauthenticated** request only to decide
routing; `handle()` runs **only after** auth passed (for non-public ops). `match()` MUST
be pure and side-effect-free (no fetch, no spawn, no store write) — it only inspects
`ctx`. (Invariant I2.)

---

## 2. Module contract

A module is one `.mjs` file default-exporting this shape:

```js
export default {
  name: "github",             // unique, kebab/lower; used in logs + `ops`
  public: false,              // true → kernel skips auth for this op (like ping/info)
  match(ctx) {                // pure, sync, side-effect-free → boolean
    return ctx.op === "do" && ctx.host === "api.github.com";
  },
  async handle(ctx) {         // runs only after auth (unless public)
    // ... do work via ctx.core ...
    return { ok: true, /* ... */ };   // plain JSON-serializable object
  },
};
```

Rules:
- `match` is **pure** (I2). No I/O, no randomness that affects routing.
- `handle` returns a plain object (kernel serializes). On failure return
  `{ ok:false, error:"...", ... }` with a **safe** message — never echo a secret, a
  full upstream token, a stack trace, or an env var value.
- A module gets capabilities **only** through `ctx.core`. It must not import `node:child_process`,
  `node:fs`, or `node:net`/`http` directly for its work — those go through `core` so the
  kernel keeps the clamps. (Invariant I3. Enforced by audit + a lint check.)

### 2.1 `ctx` (built by kernel, passed to match/handle)

```
ctx = {
  op,        // string, the ?op= value
  params,    // parsed query params (sig/key stripped before handle)
  method,    // "GET" | "HEAD"
  url,       // parsed URL object
  host,      // for op=do: hostname of the target `t=` param, else null
  headers,   // outbound header bag the module may add to (for proxy)
  env,       // FROZEN read-only view of this module's own allowed config only (§4)
  core,      // capability object below
}
```

### 2.2 `ctx.core` capabilities (the only way modules touch the outside world)

```
core.proxy(targetUrl, opts)   // signed outbound HTTPS. Enforces host allowlist,
                              // https-only, no-redirect-to-new-host, response cap.
                              // Returns { ok, upstream_status, error, hint, body }.
core.exec(name, args)         // run a NAMED vetted script (§5). args = array only.
                              // Never a shell string. Off unless enabled in config.
core.store                    // { get(k), set(k,v,ttl) } — kernel KV (nonces live here too,
                              // but modules get a namespaced view; cannot read kernel keys).
core.log(safeMsg)             // structured log; kernel scrubs known secret patterns.
core.control.rotate(names[], ttlMap)  // operator-only: re-mint the named modules'
                              // secrets (+ door-key) into store, each with its own TTL.
                              // Only reachable from privileged callers (§2.4), never a client GET.
```

Modules **compute** freely in pure JS (no capability needed for that). Anything that
leaves the process (network, shell, fs) is a `core` call so the clamp is central.

### 2.3 Lifecycle hooks (optional — same contract, extra surfaces)

A module has up to three surfaces; it implements only the ones it needs. `match/handle`
is the data plane; the two below are optional:

```js
export default {
  name: "github",
  match(ctx) { ... }, async handle(ctx) { ... },   // data plane (react to a client GET)

  // CONTROL plane — mint/refresh THIS module's own secret into the store with a TTL.
  // Invoked by the operator via issue/CLI/telegram, NOT by a client request.
  async rotate({ ttl, core }) {
    const tok = await mintToken(core.env);          // e.g. GitHub App JWT -> install token
    await core.store.set("github:token", tok, ttl); // server-side only; never leaves the box
    return { minted: true, expires_in: ttl };
  },

  // BACKGROUND plane — long-running worker started ONCE at boot, runs forever.
  // No inbound GET; the bridge reaches out (e.g. a Telegram long-poll that, on an
  // operator ⚡, calls core.control.rotate). Optional; most modules omit it.
  async start(core) { ... },
};
```

Kernel phases, all uniform (no per-module special-casing):
- **boot** → for each module, `await module.start?.(core)`.
- **request** → kernel auth (unless `public`) → first `match` wins → `handle`.
- **control** → `rotate(names, ttlMap)` → rotate kernel door-key + `await module.rotate?.()`
  for each named module. Per-key = per-name; "both/all" = pass every name.

### 2.4 Control-plane authorization (privileged, NOT the door-key)

`rotate` mints keys, so it must not be gated by the key it mints. Reachable only from:
- the **local CLI** (a process on the host is the operator), and
- a module that asserts operator identity (e.g. `telegram.mjs` gating on a **chat-id
  whitelist**).

The door-key authorizes *calling* the bridge (data plane) — never *rotating* it. This
separation is an invariant (I12).

---

## 3. Authentication (unchanged from proven server — kernel-owned)

```
canonical = "v1\n" + path + "\n" + <params sorted, urlencoded, joined '&', 'sig' excluded>
sig       = hex( HMAC_SHA256(secret, canonical) )
```

- Signed request carries `ts` (unix s, ±`TS_WINDOW_SEC`, default 120 — tight replay window),
  `nonce` (8–128 chars, **single-use**, stored until window expiry), `sig`.
- Two accepted forms: **(a) full HMAC** (`sig`), **(b) degraded `key=<secret>`-in-URL**
  for fetch-only clients that cannot sign. Both compared **constant-time**.
- No active secret (ASLEEP) → signed req `no_secret_server`, degraded req `no_sig`.
- `public:true` ops skip all of this. The set of public ops is **explicit** and small.

Invariant I4: constant-time compare for every secret/sig check. No early-return on
first-byte mismatch.

---

## 4. Config & isolation

- Config from env (`.env`, `chmod 600`, dir not a git repo on the host). Repo ships only
  `.env.example` with placeholders. **Zero real secrets in git — ever.** (Invariant I5.)
- Each module sees **only its own** config namespace in `ctx.env` (e.g. `github` module
  gets `GITHUB_*`), as a frozen object. A module cannot read another module's secrets or
  the kernel's. (Invariant I6.)
- Global config: `PORT`, `BIND` (default `127.0.0.1`), `STORE_PATH`, `ALLOW_HOSTS`
  (proxy allowlist), `KEY_TTL_SEC`, `TS_WINDOW_SEC`, `DO_MAX_RESP` (response cap).

---

## 5. The three demo module classes (define the universal span)

**Design law: security lives in the 3 generic primitives (kernel auth, `core.proxy`,
`core.exec`), applied uniformly. Modules carry ZERO per-service policy.** No module has
its own "check this method / this path / this repo" logic — that is a crutch. A module
only: `match` → inject its env secret → call a `core.*` primitive. The clamps in §5.1/§5.2
are not add-on checks layered over a module; they *are* the primitive, so every http/exec
module inherits the same one boundary. Want a service restricted? Restrict the credential
at the service (e.g. a read-only GitHub token) — the bridge stays dumb and generic.

One demo per class proves the standard covers "algorithm → shell → HTTP".

| class    | example op    | `handle` body                         | main risk         |
|----------|---------------|---------------------------------------|-------------------|
| compute  | `op=hash`     | pure JS (hash/calc), return result    | none (no I/O)     |
| exec     | `op=run`      | `core.exec("backup", [arg])` → stdout | **RCE**           |
| http     | `op=fetch`    | `core.proxy(t, {method})`             | **SSRF**          |

### 5.1 exec-module clamps (mandatory — this is the RCE surface)

- **Off by default.** Enabled only via explicit config (`EXEC_ENABLED=1` + a scripts dir).
- **Named vetted scripts only.** Config maps a name → an absolute script path the
  operator placed. The client passes the *name*, never a path, never a command.
- **No shell.** Use `spawn(scriptPath, argsArray, {shell:false})`. Never `sh -c`, never
  string interpolation of client input into a command.
- **Args are an array of strings**, length-capped, each length-capped; reject args
  containing NUL. No client value ever becomes an executable token — only a positional
  argv to a fixed script.
- **Path lock:** resolved script path must live under the configured scripts dir
  (realpath check, reject symlink escape / `..`). Name must match `^[a-z0-9_-]+$`.
- **timeout** (kill on overrun) + **stdout/stderr cap**. Non-zero exit → `{ok:false}`.
- exec module ships **disabled**; the demo script is a trivial safe `echo`-style stub.

### 5.2 http-module clamps (SSRF surface)

- **https only.** Reject `http:`, `file:`, `ftp:`, `data:`, etc.
- **Host allowlist** (`ALLOW_HOSTS`) enforced *after* normalization (lowercase, strip
  trailing dot, punycode/IDN → ASCII, reject embedded credentials/`@`, reject explicit
  port that changes host meaning).
- **Block private/link-local/loopback targets** even if DNS resolves there:
  `127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16` (incl. `169.254.169.254`
  metadata), `::1`, `fc00::/7`, `fe80::/10`, `0.0.0.0`. Resolve then check the IP; block
  DNS-rebind by pinning the resolved IP for the request.
- **No redirect to a new host.** Follow redirects only within the allowlist; otherwise
  return the 3xx as-is. Never auto-follow to a non-allowlisted host.
- **Response cap** `DO_MAX_RESP`. Truncate + flag.

---

## 5.9 Threat model (READ THIS before reading the invariants)

**Modules are TRUSTED.** They are operator-authored or operator-reviewed code, dropped into
`modules/` by the same person who runs the bridge — exactly like nginx modules, an Apache
`httpd.conf`, or a server's own route handlers. A module is *first-party code*, not attacker
input. get-hub does **not** attempt to sandbox a hostile `.mjs`.

**Why this is the line.** In-process JavaScript cannot be structurally confined by a static
text linter: a determined module can defeat any source scan via aliasing (`const p = process`),
computed member access (`process["getBuiltin"+"Module"]`), unicode-escaped import specifiers,
capturing a privileged capability in a `start()` closure and using it from `handle()`, or
prototype pollution (`Array.prototype.includes = () => true`). Real isolation of untrusted
module code would require a per-module realm / Worker with frozen intrinsics and a
capability-passing boundary — a different, much larger architecture. get-hub deliberately does
**not** pay that cost; it stays zero-dep and simple, and trusts its modules.

**The defended attacker is the EXTERNAL fetch-only client.** Someone who knows the URL shape
and may or may not hold the door-key, but who **cannot place code in `modules/`**. Against
that attacker the kernel is the security boundary, and these MUST hold with red-team tests:
SSRF confinement (`core.proxy`: https-only, allowlist post-normalization, private/metadata-IP
block incl. IPv6-embedded forms, DNS-rebind pin, no cross-host redirect, response cap), auth
(HMAC before dispatch, constant-time, replay/skew guards, no protected op served without a
valid signature), and no server-side secret (door-key, injected Bearer, PAT/App token, PEM)
ever reaching a response body or a log.

**Recon surface (not a secret leak).** The public discovery ops `info`/`ops` reveal the version,
`allow_hosts`, and the op catalog to **anonymous** callers — by design (I9 classifies these as
non-sensitive policy). This is a known **fingerprinting/recon** surface for a public deploy, not a
secret leak; a public-exposure deployment should be aware of it (see DEPLOY.md "Public exposure").

**Consequence for the linter (I11).** `lint.mjs` is a **quality / hygiene gate**, not a
security boundary. It catches *accidental* contract violations (a module that forgets to route
through `core`, an impure `match`, a stray `process.env` read) and keeps contributed modules
uniform and reviewable. It is not, and cannot be, a defense against a module that is *trying*
to break out — that is the operator's review responsibility, per the trust boundary above.

## 6. Security invariants (the "zero-vuln" gate checks all of these)

| # | Invariant |
|---|-----------|
| I1 | Auth runs in the kernel, before dispatch, for every non-public op. Unbypassable. |
| I2 | `match()` is pure/side-effect-free; `handle()` runs only post-auth. |
| I3 | Modules reach the outside world only via `ctx.core` (no direct fs/net/child_process for work). |
| I4 | All secret/sig comparisons are constant-time. |
| I5 | No real secret in git, ever. Placeholders only; host `.env` chmod 600. |
| I6 | Per-module config isolation; a module cannot read another's or the kernel's secrets. |
| I7 | exec = named vetted scripts, arg-array, no shell, path-locked, timeout+cap, off by default. |
| I8 | http/proxy = https-only, allowlist post-normalization, private-IP/metadata blocked, no cross-host redirect, response-capped. |
| I9 | No secret, token, stack trace, or env value ever appears in a response body or log. |
| I10 | GET/HEAD only; state-changing effects gated by auth + per-module clamps, never by method alone. |
| I11 | A build-time **module linter** (`lint.mjs`) is a **quality/hygiene gate** — it statically rejects *accidental* contract violations and keeps modules uniform. It is NOT a security boundary against a hostile module (see §5.9). |
| I12 | Control plane (`rotate`) is operator-only (local CLI / whitelisted channel); the door-key can call the bridge but never rotate it. Enforced by the kernel operator-identity gate for the external attacker; a trusted module is not an adversary here (§5.9). |

**Scope (per §5.9).** I1, I4, I5, I8, I9, I10 defend the **external fetch-only attacker** and
MUST each have a red-team test that tries to violate it and fails — this is the load-bearing
"zero-vuln" gate. I2, I3, I6, I11, I12 are **contract/hygiene** invariants: they keep
first-party modules correct and uniform (and the linter catches honest mistakes), but they are
NOT claimed to hold against a *malicious* in-process module, because in-process JS cannot be
structurally confined without per-module isolation the design intentionally omits. "Zero
vulnerabilities" = every external-facing invariant has a passing red-team test + no open
finding reachable **without placing code in `modules/`**.

### 6.1 Module linter (I11) — build gate, corner-case tested

`lint.mjs` runs at build/CI and **fails the build** on any of:
- a module importing `node:child_process` / `node:fs` / `node:net` / `node:http(s)`
  directly for its work (must go through `core`) — the I3 escape hatch.
- `match` doing I/O / referencing `core`/`await` (must be pure, sync) — I2.
- missing/duplicate `name`; `name` not `^[a-z0-9_-]+$`.
- a non-`public` module with no `handle` **and** no `rotate`/`start` (dead module).
- a module reading `process.env` directly instead of `ctx.env` (bypasses per-module
  isolation) — I6.
- exec use with a shell string / client-supplied path (not a vetted name) — I7.

The linter itself is **corner-case tested**: path-traversal names (`../x`), unicode
homoglyph hosts, aliased imports (`import cp from "node:child_process"`), re-export
tricks, dynamic `import()` — each must be caught, not slip through. This test suite is
part of the security gate.

---

## 7. Deliverables the build must produce

- `kernel.mjs` — lifecycle + registry + `core` + auth. Small, audited.
- `modules/` — `ping.mjs`, `info.mjs`, `ops.mjs`, `echo.mjs`, `secure_echo.mjs`,
  `do.mjs`(generic proxy/http), `github.mjs`, plus demos `hash.mjs`(compute),
  `run.mjs`(exec-clamped), `fetch.mjs`(http). **`github.mjs` = pure injection only**
  (`match host == api.github.com` → add `Bearer` from `GITHUB_TOKEN` → `core.proxy`).
  **Drop `GITHUB_MODE`/`GITHUB_REPOS` entirely** — service-specific policy is a crutch;
  scope the token at GitHub instead. Preserve every proven guard that belongs to the
  *primitives* (bad_sig/replay/ts_expired/bad_nonce/host_not_allowed), not the dropped
  github policy.
- `server.mjs` — thin entry: load config, load modules, start `node:http`, wire CLI
  (`issue`/`kill`/`show`).
- `lint.mjs` — the build-gate module linter (§6.1) + its own corner-case test suite.
- Tests — one red-team test per invariant I1–I12 + per-module functional tests.
- **Worked examples (all real, all passing our standards).** Every module shape shown in
  design ships as an actual working, lint-clean, tested file, and is documented in the
  docs with a runnable snippet + expected output:
  `ping`(public) · `hash`(compute) · `temp`(exec, reads server temperature via a vetted
  script) · `run`(exec, client picks a vetted script name) · `fetch`(http via `core.proxy`)
  · `github`(http + secret inject + `rotate`) · `telegram`(`start` daemon + control trigger).
  These double as the "Write your own module" library — no toy/pseudo code in docs.
- Docs — README stays rough but gains a **"Write your own module"** base: the contract,
  a copy-paste template, the `core` capability list, and links to the worked examples above.
- `LICENSE`, `.env.example` (placeholders), `.gitattributes eol=lf` (already present).

## 8. Non-goals / constraints (do not cross)

- **LAN only.** No public exposure, no Tailscale Funnel this phase. `BIND` stays private.
- **No real secrets committed.** Blind E2E on the Pi runs credential-free except the one
  GitHub-injection check, whose token lives only in the host `.env`.
- **Don't weaken proven guards.** Every *primitive* guard the 3 blind iterations passed
  (bad_sig/replay/ts_expired/bad_nonce/host_not_allowed) must still pass after the
  refactor. Regression = blocker. (`repo_not_allowed`/`github_readonly` are intentionally
  removed — see §7.)
- Zero runtime dependencies (Node ≥18 built-ins only).
