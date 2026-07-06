# Proposals — deferred behavioral changes

These change **runtime behavior** and were intentionally **not** applied in the
OSS-prep refactor, which froze behavior (both live servers are gone, so nothing can
be tested end-to-end yet). Implement and verify each in the credential-testing phase,
where an agent deploys with real creds and exercises the paths.

## P1 — Decouple GitHub from the proxy core

**Now:** `op=do` special-cases `host === "api.github.com"` and injects `kc:gh`; ⚡
assumes a GitHub App. Repurposing to another API means editing the proxy body,
contradicting the "GitHub is just the first plug / generic dispatcher" goal.

**Proposed:** a declarative per-host credential map, e.g.
`INJECT = { "api.github.com": {kv:"kc:gh", scheme:"Bearer", accept:"application/vnd.github+json"} }`,
sourced from config/env. Adding a backend = one map entry + an `ALLOW_HOSTS` entry,
no core edit. GitHub ships as one example entry, not hardwired.

## P2 — Honest upstream-status mapping in Worker `do`

**Now:** the Worker returns `ok:true` wrapping the upstream status in `body.status`,
so a client can misread a 401/404 as success. The PHP port already maps honestly.

**Proposed:** port the PHP mapping to the Worker: `ok` strictly = 2xx, with
`error`/`hint` (`token_expired`, `not_found`, `rate_limited`, `forbidden`,
`upstream_error`) and a `fetched_at`. Aligns both deployments; update `docs/API.md`.

## P3 — First-class non-Telegram bootstrap

**Now:** activating the signed path outside Telegram requires a manual
`wrangler kv key put hmac:current ...` (documented in README §10 but not tooled).

**Proposed:** a small `npm run issue` / CLI that mints an HMAC (and optionally a
GitHub token from the App PEM) and writes KV, so headless/agent deploys don't depend
on pressing a Telegram button.

## P4 — Least-privilege GitHub App by default

Ship guidance + a sample manifest for a **read-only, single-throwaway-repo** App, so
the default blast radius is minimal. (Docs already warn; make it the default path.)

## P5 — Raise / stream past the 100 KB response cap

**Now:** `DO_MAX_RESP = 100000` silently truncates; weak agents misread truncation as
empty. **Proposed:** configurable cap, an explicit `truncated:true` flag, and/or a
range/pagination helper.

## Out of scope (design only, never coded)

The async **SSH/promise dispatcher** (start/poll/wait/kill via an ssh-gateway) from
the dev log was hand-proven on a server but **never shipped in code**. Do not treat
it as existing; it is a separate future project, not part of this bridge.
