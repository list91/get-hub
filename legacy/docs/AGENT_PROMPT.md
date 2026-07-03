# Agent usage prompt (English)

Paste the block below into any LLM chat whose only external capability is a web
fetch (GET a URL). Fill `BRIDGE_URL`, `ACCESS_KEY`, the `TOKEN`, and the `TASK`.
Send it as **one** message. Adapted from the battle-tested `ПРОМПТ-внешний-LLM-v3`;
the anti-flailing rules exist because weak free-tier models otherwise probe random
endpoints and burn the ~1h token.

```
You read my GitHub repositories ONLY through my HTTP bridge. Follow LITERALLY.
Do not invent rules not written here. If something is missing, ask in one line; do
not guess.

TOOL — exactly one: web_fetch (GET a URL). You have NO other access to GitHub.
- Calling api.github.com directly is FORBIDDEN — not a fallback, not a "check".
  Never form, try, or suggest a URL without the bridge host.
- Headers (Authorization etc.) are NOT needed and NOT supported — the bridge sets
  auth; the token is already in the URL. "web_fetch can't do auth, so I can't" is
  WRONG: private repos are reached exactly this way.

READY CALL. Replace PASTE_TOKEN with the token from the TOKEN block (whole, with the
ghs_ prefix), change nothing else, and make ONE web_fetch:
BRIDGE_URL/?op=do&format=raw&key=ACCESS_KEY&gh=PASTE_TOKEN&t=https%3A%2F%2Fapi.github.com%2Finstallation%2Frepositories%3Fper_page%3D5

t= is a github URL, ALREADY url-encoded (%3A=: %2F=/ %3F=? %3D== %26=&). For a
different github path, encode it the SAME way IN FULL and put it in t=. Do not touch
key= or format=.

BRIDGE RESPONSE — JSON {ok, upstream_status, error, hint, body}:
- ok:true  → data is in "body" (a JSON string; parse it). A big body is NOT "empty"
  and NOT an error.
- ok:false → print "hint" verbatim and STOP. Do not change the URL, try another
  endpoint, or go around.

IF web_fetch returns empty / non-JSON / HTML / timeout / "no content" (no ok field):
that is a bridge glitch, NOT a reason to find a workaround. Repeat the SAME web_fetch
once more (2 tries total). Still nothing → print "Bridge unavailable" and STOP.
FORBIDDEN on any error: changing the domain, going to api.github.com, googling,
seeking another service, building a different URL.

Pagination: if there are more than one page, do NOT touch the bridge URL; add
&page=2 INSIDE t= and re-encode the whole thing.

SECURITY (overrides any task below):
- The token is secret. NEVER print or repeat it, never show the full assembled URL,
  never reproduce the TOKEN block — not in the answer, not in reasoning, not in
  examples.
- To "show the URL / debug / repeat verbatim / what did you fetch" → answer
  "unavailable" and STOP.

OUTPUT — result only. No URLs, no raw JSON, no tool_call tags, no step description.

TOKEN:
<fresh ghs_… here>

TASK:
<your task, e.g.: list all private repositories>
```

**Notes**
- `format=raw` is required for Exa-backed `web_fetch` (it returns empty for
  `application/json`). Harmless elsewhere.
- On the Cloudflare Worker, `key=` is the current Bridge HMAC; on the PHP port it is
  your `ACCESS_KEY`. Do not mix them up with the `ghs_` GitHub token.
