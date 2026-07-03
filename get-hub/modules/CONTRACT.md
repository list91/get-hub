# get-hub module contract (what the kernel guarantees you, what you must satisfy)

Every file in this dir named `*.mjs` is auto-loaded (deterministic **alphabetical** order —
that is the dispatch order for `match`). Each must default-export ONE object of this shape.
`CONTRACT.md` and `_template.mjs` (leading underscore) are ignored — the loader only imports
plain `*.mjs` and `_template.mjs` is a copy-paste starting point, delete the underscore to arm it.

## The shape

```js
export default {
  name: "yourmod",          // REQUIRED. unique. must match /^[a-z0-9_-]+$/  (dup => boot fails)
  public: false,            // true => kernel SKIPS auth for this op (health/discovery only)

  // DATA plane — react to a client GET.
  match(ctx) { ... },       // REQUIRED*. PURE + SYNC. no I/O, no core, no await, no randomness.
  async handle(ctx) { ... },// REQUIRED*. runs ONLY after auth (unless public). returns plain JSON obj.

  // CONTROL plane (optional) — mint/refresh THIS module's own secret into the store.
  async rotate({ ttl, core }) { ... },   // operator-triggered (CLI/whitelisted TG), NEVER a client GET.

  // BACKGROUND plane (optional) — started ONCE at boot, runs forever (e.g. TG long-poll).
  async start(core) { ... },
};
// *a module must have `handle`, OR at least one of `rotate`/`start` (no dead modules).
```

## Hard rules the linter (`lint.mjs`) enforces at build time — violating = build FAILS

- `match` is PURE and SYNC: no `await`, no reference to `core`/`ctx.core`, no I/O. It only
  inspects `ctx` to decide routing. (I2)
- Reach the outside world ONLY through `ctx.core`. Do NOT import `node:child_process`,
  `node:fs`, `node:net`, `node:http(s)`, `node:dns` for your work — those clamps live in the
  kernel. Pure compute (crypto hashing, JSON, string work) is fine to do inline. (I3)
- Read config ONLY from `ctx.env` (a frozen view of YOUR namespace). Never `process.env`. (I6)
- `exec`: pass a vetted NAME + arg ARRAY. Never a shell string, never a client-supplied path
  or command. (I7)
- Never put a secret, token, stack trace, or env value in a returned object or a log. On
  failure return `{ ok:false, error:"safe_code" }`. (I9)

## `ctx` the kernel builds and hands to `match`/`handle`

```
ctx = {
  op,       // string — the ?op= value
  params,   // parsed query params, with `sig` and `key` STRIPPED before handle
  method,   // "GET" | "HEAD"
  url,      // WHATWG URL object of the request
  host,     // for op=do style: hostname of the `t=` target (normalized), else null
  headers,  // outbound header bag you MAY mutate before calling core.proxy (starts with User-Agent)
  env,      // FROZEN object: only YOUR namespace's config. github => { TOKEN, APP_ID, INSTALL_ID, APP_PEM_PATH }
  core,     // capability object — the ONLY door to the outside world (see below)
}
```

Note during ROUTING (`match`) the kernel calls you on an unauthenticated ctx with `core:null`,
`env:{}` — so `match` must not touch either. `handle` always gets the real `core` + `env`.

## `ctx.core` — exact signatures (match these; this is the real API)

```
core.proxy(targetUrl, opts?) => Promise<{
  ok, upstream_status, error, hint, fetched_at, body, truncated,
  // + optional flags: host, redirect_not_followed, location_host, too_many_redirects
}>
   // opts = { method?="GET", headers?={}, body? }.  https-only, host must be in ALLOW_HOSTS
   // (post-normalization), private/loopback/link-local/metadata IPs blocked with DNS-pin,
   // no cross-host redirect, response capped to DO_MAX_RESP. You cannot weaken any of this.

core.exec(name, argsArray) => Promise<{
  ok, exit_code?, error, stdout?, truncated?
}>
   // OFF unless EXEC_ENABLED=1 + EXEC_DIR set (else { ok:false, error:"exec_disabled" }).
   // `name` must match /^[a-z0-9_-]+$/ and resolve (realpath) to a file under EXEC_DIR.
   // `argsArray` = array of strings, capped count/length, no NUL. spawn shell:false.

core.store = {
  get(k) => value | null,
  set(k, v, ttlSec) => void,     // ttlSec falsy = no expiry
}
   // Namespaced to YOUR module (kernel prefixes "yourmod:"). You cannot read the door-key,
   // kernel nonces, or another module's keys. Convention: store your minted secret at key
   // "token" (the CLI `kill`/`show` look for "<name>:token").

core.log(safeMsg) => void          // structured log; kernel scrubs known secret patterns anyway.

core.control.rotate(names[], ttlMap) => Promise<results>
   // OPERATOR-ONLY (I12). Only call from a start()-daemon that has asserted operator identity
   // (e.g. telegram gating on TELEGRAM_WHITELIST). NEVER from handle() on a client's behalf.

core.env                           // same frozen namespace view as ctx.env (for start/rotate).
```

## rotate contract

```js
async rotate({ ttl, core }) {
  const tok = await mint(core.env);          // e.g. GitHub App JWT -> installation token
  await core.store.set("token", tok, ttl);   // server-side only; never returned/logged
  return { minted: true, expires_in: ttl };  // safe summary only
}
```

## Worked examples to ship (all real, lint-clean, tested):
`ping`(public) · `hash`(compute) · `temp`(exec) · `run`(exec) · `fetch`(http via proxy) ·
`github`(http + inject + rotate) · `telegram`(start daemon + control). See `_template.mjs`.
