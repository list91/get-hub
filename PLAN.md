# get-hub — delegation plan to production-ready

> Goal: a clean, working, "alive"-looking, **reusable/contributable** repo with **zero
> vulnerabilities** and **every corner case covered**. README stays rough but gains a
> "write your own module" base. Built by delegated agents; security proven adversarially,
> not asserted. LAN-only, no real secrets committed.

Source of truth: `SPEC.md` (contract) + `DESIGN-NOTES.md` (decisions). Every agent works
against those; if either is wrong, fix the doc first, then rebuild.

Foundation: the proven `server.mjs` (HMAC + `op=do` + GitHub inject, blind-deployed 3× on
the Pi). We **refactor** it into kernel + modules — not a rewrite — and no proven guard
may regress.

---

## Phase 0 — Spec freeze ✅ (done)
`SPEC.md` + `DESIGN-NOTES.md` written and approved. Locked.

## Phase 1 — Kernel + refactor  (1 agent)
**kernel-agent** builds `kernel.mjs`: parse → auth (kernel-owned, before dispatch) →
registry/`match` → `handle`; the 3 phases (boot `start` / request / control `rotate`);
the `core` object (`proxy`/`exec`/`store`/`log`/`control.rotate`); config + per-module
`ctx.env` isolation; CLI `issue`/`kill`/`show`.
- Output: working kernel; proven auth/nonce/store logic preserved verbatim.
- Gate: existing E2E guards (bad_sig/replay/ts_expired/bad_nonce/host_not_allowed) pass.

## Phase 2 — Modules  (parallel agents, isolated worktrees)
One agent per module (or small groups); each ships lint-clean + unit tests:
`ping · info · ops · echo · secure_echo` (built-ins) · `hash`(compute) · `temp` + `run`
(exec, clamped) · `fetch`(http) · `github`(http + inject + `rotate`) · `telegram`
(`start` daemon + control trigger).
- Each is a **real worked example** (SPEC §7) — no toy code, doc snippet + expected output.
- Gate: each passes the linter and its functional tests.

## Phase 3 — Linter  (1 agent, can overlap Phase 2)
**lint-agent** builds `lint.mjs` (build gate, SPEC §6.1) + its corner-case suite
(path-traversal names, unicode homoglyph hosts, aliased/dynamic imports, re-export
tricks). CI wires it as a hard gate.
- Gate: linter catches every corner-case probe; false-negative = blocker.

## Phase 4 — Adversarial security  (fan-out lenses, the zero-vuln gate) 🔴
Independent agents, **each a distinct lens, task = BREAK it** (not "verify"):
- **SSRF** — private/loopback/metadata IPs, DNS-rebind, redirect to non-allowlisted host,
  `http:`/`file:`/`data:`, host-normalization bypass (case, trailing dot, IDN, `@`, port).
- **RCE** — exec arg-injection, shell metachar, path-traversal to non-vetted script,
  symlink escape, name regex bypass, oversized args, NUL.
- **Auth-bypass** — replay, nonce reuse, ts skew/window edges, canonical ambiguity,
  degraded `key=` vs sign, public-op leak, constant-time regression.
- **Secret-leak** — token/env/stack in any response body, error, or log; scrub coverage.
- **Module-isolation** — greedy `match` shadowing, one module reading another's `ctx.env`
  or the kernel store keys.
- **Control-plane priv** — reach `rotate` via data-plane / door-key; TG whitelist bypass.

Each finding → **independent re-verification (majority vote)** → fix → re-audit. Loop
until **N consecutive clean rounds**. Deliverable: for **each invariant I1–I12**, a
red-team test that attempts the violation and **fails**.
- Gate: blocks merge. No open finding, every invariant has a passing attack-test.

## Phase 5 — Blind E2E deploy on the Pi (LAN)  (1 independent agent)
Deploy from README **alone**, zero prior context, over ssh on the Pi. Exercise the full
matrix (below), zero manual fixups — the proven blind-agent harness (worked 3×).
- Includes: ASLEEP↔ACTIVE transitions, public ops while asleep, `issue`/`kill`/rotate,
  all three secret modes (mode 1 with a real token living **only** in host `.env`),
  every module + every clamp, store survives restart.
- Gate: clean PASS, no fixups; any friction → improve repo → re-run.

## Phase 6 — Production polish + reusability  (1–2 agents)
- **reviewer-agent**: clean/consistent code, no dead code/TODO/console noise, "alive"
  (real structure, tests, coherent history) — reads like a maintained project.
- **docs**: README rough-but-augmented + **"Write your own module"** base (contract +
  copy-paste template + `core` list + links to worked examples); `THREAT-MODEL.md`
  (invariants + the attack-tests that back them); `CONTRIBUTING.md` (how to add a module,
  lint/test gates); `CHANGELOG.md`; `LICENSE`; `.env.example` placeholders.
- **naming**: consistent `get-hub` across clone URLs / docs / package name.

## Phase 7 — Final security sign-off + report
Full invariant matrix green, linter green, blind E2E green, docs complete. Written report:
what was attacked, what held, residual risks (if any), and the "not yet" list (public
exposure deferred).

---

## Corner-case matrix (must each have a test)
Encoding/transport: CRLF checkout, URL-encoding of `t`, HEAD method, oversized body,
oversized response (cap), non-UTF8. Auth: replay, nonce reuse, ts past/future/edge,
clock skew, TTL=0 (never-expire) vs finite, degraded-vs-sign, ASLEEP no_sig vs
no_secret_server. Proxy/SSRF: allowlist miss, private/metadata IP, DNS-rebind, redirect
chain, non-https scheme, host homoglyph/case/trailing-dot/port/`@`. Exec/RCE: name regex,
path traversal, symlink, disabled-by-default, timeout, non-zero exit, arg NUL/oversize,
client-command rejection. Modules: name collision, greedy match order, dead module,
missing config, malformed params, per-module env isolation. Lifecycle: rotate concurrency,
rotate each/both, store corruption + restart survival, boot with a failing `start`.
Leakage: secret/env/stack in body/error/log scrub.

## Orchestration mechanics
Pipeline **kernel → modules** (modules depend on the core contract). **Fan-out** the
security lenses with adversarial majority-vote verification (loop until dry). **Blind
E2E** last, on the Pi over LAN. Parallel module/security agents run in **isolated
worktrees** to avoid file conflicts. Each agent gets `SPEC.md` + `DESIGN-NOTES.md` +
a narrow scope + structured output; the orchestrator merges and re-audits.

## Hard rules threaded into every agent brief
Kernel auth unbypassable · security only in the 3 primitives · exec off-by-default +
named-scripts-only · no real secret in git · LAN-only · zero deps · don't weaken proven
guards · every invariant needs a failing attack-test, not a claim.
