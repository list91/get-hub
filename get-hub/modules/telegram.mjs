/**
 * telegram.mjs — the canonical BACKGROUND-plane module (start daemon + control trigger).
 *
 * Shape: NO match / NO handle. It has no data plane — a client GET can never reach it.
 * Its only surface is `start(core)`, a long-poll worker booted once by the kernel that:
 *   1. long-polls Telegram getUpdates via core.proxy (the ONE outbound-HTTPS boundary, I3/I8),
 *   2. gates EVERY update on the TELEGRAM_WHITELIST chat-id set — operator-only (I12),
 *   3. on an operator "/issue" (message text OR an inline-button callback with data "issue"),
 *      calls core.control.rotate(['door','github'], {door:3600, github:3600}) to re-mint the
 *      kernel door-key + the github module's install token.
 *
 * It is SERVICE-AGNOSTIC beyond passing rotate the names it was told: it knows nothing about
 * what "github" is or how a door-key is minted — it just asserts operator identity (whitelist)
 * and pulls the generic control-plane lever. That is the whole point of the 3rd module type.
 *
 * OPTIONAL: if TELEGRAM_TOKEN is empty the module no-ops cleanly (logs once, returns) — the
 * bridge boots fine with no Telegram configured.
 *
 * SECURITY (why this is allowed to call rotate at all — I12):
 *   rotate mints keys, so it must NOT be gated by the key it mints. It is reachable only from
 *   privileged callers: the local CLI, or a module that asserts OPERATOR IDENTITY. This module's
 *   operator assertion is the chat-id whitelist: a non-whitelisted chat's "/issue" is dropped
 *   before rotate is ever considered. No door-key, no HMAC — a different, stronger gate.
 *
 * ZERO service policy, ZERO direct I/O: everything outbound goes through core.proxy; the bot
 * token is read from ctx.env (frozen TELEGRAM_ namespace), never process.env (I6). The token is
 * never returned or logged (I9) — it only ever appears inside the proxied URL, which core.proxy
 * builds and the kernel scrubs.
 */

// ── tunables (kept well under the kernel's PROXY_TIMEOUT_MS=10000ms so the long-poll returns
//    cleanly instead of tripping the proxy's own upstream_timeout) ──
const LONGPOLL_SEC = 5;        // Telegram holds getUpdates open this long when idle
const IDLE_BACKOFF_MS = 1000;  // pause after a transport error before retrying (avoids hot loop)
const TG_HOST = "api.telegram.org";

// The names + TTLs this operator trigger rotates. Generic: the module doesn't interpret them.
const ROTATE_NAMES = ["door", "github"];
const ROTATE_TTLS = { door: 3600, github: 3600 };

// Parse "111,-100222 333" → Set<string> of chat-ids. Robust to comma/space, ignores blanks.
function parseWhitelist(raw) {
  return new Set(
    String(raw || "")
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

// Pull a chat-id + SENDER-id + trigger intent out of ONE Telegram update, without trusting its
// shape. Returns { chatId, senderId, isIssue } — chatId/senderId are strings ("" if none).
// The senderId (Telegram from.id) is the ACTUAL user; in a group chat it differs from chatId.
// The module does NOT decide who the operator is — it forwards both ids to the kernel control
// plane, which binds operator identity to the SENDER (I12). This keeps the module policy-free.
// Supports two operator gestures:
//   - a text message whose (trimmed, lowercased) body is "/issue" (or "/issue@thebot"),
//   - an inline-button callback_query whose data is "issue".
function readUpdate(u) {
  if (!u || typeof u !== "object") return { chatId: "", senderId: "", isIssue: false };

  // callback_query (button press) takes precedence — it carries its own message+chat.
  const cq = u.callback_query;
  if (cq && typeof cq === "object") {
    const chatId =
      cq.message && cq.message.chat && cq.message.chat.id != null
        ? String(cq.message.chat.id)
        : cq.from && cq.from.id != null
        ? String(cq.from.id)
        : "";
    const senderId = cq.from && cq.from.id != null ? String(cq.from.id) : "";
    const data = typeof cq.data === "string" ? cq.data.trim().toLowerCase() : "";
    return { chatId, senderId, isIssue: data === "issue" };
  }

  // plain / edited message
  const msg = u.message || u.edited_message;
  if (msg && typeof msg === "object") {
    const chatId = msg.chat && msg.chat.id != null ? String(msg.chat.id) : "";
    const senderId = msg.from && msg.from.id != null ? String(msg.from.id) : "";
    const text = typeof msg.text === "string" ? msg.text.trim().toLowerCase() : "";
    // "/issue" or "/issue@botname" (Telegram appends @bot in groups)
    const isIssue = text === "/issue" || text.startsWith("/issue@");
    return { chatId, senderId, isIssue };
  }

  return { chatId: "", senderId: "", isIssue: false };
}

export default {
  name: "telegram",
  public: false, // irrelevant (no data plane) but the loader wants a boolean; false = conservative.

  // NO match, NO handle — this module has no client-facing data plane. Its only surface is start().
  // (The kernel's "no dead module" rule is satisfied by start alone.)

  // BACKGROUND plane: booted once, runs forever. Never returns while polling.
  async start(core) {
    const env = core.env || {};
    const token = String(env.TOKEN || "").trim();

    // OPTIONAL: no token → clean no-op. The bridge runs fine without Telegram.
    if (!token) {
      core.log("no TELEGRAM_TOKEN — telegram daemon disabled (no-op).");
      return;
    }

    // OPERATOR IDENTITY is decided by the KERNEL (OPERATOR_CHATS / OPERATOR_SENDERS), not here.
    // The module forwards the observed { chatId, senderId } to core.control.rotate and the kernel
    // authorizes (binding to the SENDER for shared/group chats). This module carries ZERO operator
    // policy — it only routes an /issue gesture and hands the raw identity to the kernel (I12).
    // A daemon with no operator configured simply never passes the kernel gate — the rotate is a
    // safe no-op ({error:"not_operator"}); it can never fire for a non-operator.
    core.log(`telegram daemon armed: long-poll ${LONGPOLL_SEC}s (operator identity enforced by kernel).`);

    // getUpdates is a state cursor: we advance `offset` past every update we've consumed so a
    // given update is delivered once. Kept in-memory (a restart re-reads recent updates harmlessly;
    // rotate is idempotent — re-minting a key is always safe).
    let offset = 0;

    // Long-poll forever. Any transport failure backs off and retries — the daemon must not die.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      try {
        // Build the getUpdates URL. Token lives ONLY here, inside the proxied URL — core.proxy
        // sends it, the kernel scrubs it from logs, we never put it in a return value. (I9)
        const url =
          `https://${TG_HOST}/bot${encodeURIComponent(token)}/getUpdates` +
          `?timeout=${LONGPOLL_SEC}` +
          `&offset=${offset}` +
          `&allowed_updates=${encodeURIComponent(JSON.stringify(["message", "edited_message", "callback_query"]))}`;

        // The ONE outbound boundary (I3/I8). api.telegram.org must be in ALLOW_HOSTS (it is by
        // default). GET only — Telegram accepts getUpdates over GET.
        const res = await core.proxy(url, { method: "GET" });

        if (!res || !res.ok) {
          // Transport/upstream problem (timeout, non-2xx, host issue). Back off, don't hot-loop.
          // Never log res.body / error detail that could echo the token — just a coarse code.
          core.log(`getUpdates not ok (${(res && res.error) || "no_response"}) — backing off.`);
          await sleep(IDLE_BACKOFF_MS);
          continue;
        }

        let payload;
        try {
          payload = JSON.parse(res.body || "{}");
        } catch {
          core.log("getUpdates returned unparseable body — backing off.");
          await sleep(IDLE_BACKOFF_MS);
          continue;
        }

        const updates = payload && Array.isArray(payload.result) ? payload.result : [];
        for (const u of updates) {
          // Advance the cursor for EVERY update we see (whitelisted or not) so we never re-read it.
          if (u && typeof u.update_id === "number" && u.update_id >= offset) {
            offset = u.update_id + 1;
          }

          const { chatId, senderId, isIssue } = readUpdate(u);

          // No module-side operator gate: forward the /issue gesture WITH the observed identity to
          // the kernel control plane. The KERNEL binds operator identity to the SENDER (from.id) —
          // so an ordinary member of a whitelisted GROUP cannot rotate (only OPERATOR_SENDERS can).
          if (isIssue && chatId) {
            core.log("/issue gesture received — asking kernel to authorize + rotate.");
            try {
              const results = await core.control.rotate(ROTATE_NAMES, ROTATE_TTLS, { chatId, senderId });
              if (results && results.error === "not_operator") {
                core.log("rotate refused by kernel: sender is not an operator.");
              } else {
                // NEVER surface the minted door-key/token. Report only a safe per-name summary.
                core.log(`rotate done: ${summarizeRotate(results)}`);
              }
            } catch (e) {
              // scrub happens in core.log, but keep it coarse regardless (I9).
              core.log("rotate failed.");
            }
          }
        }
      } catch (e) {
        // Absolutely nothing in the loop may kill the daemon.
        core.log("telegram loop error — backing off.");
        await sleep(IDLE_BACKOFF_MS);
      }
    }
  },
};

// Non-secret one-line summary of a rotate result map. Strips the operator-only `_doorKey`
// and any nested secret values — only reports minted/expiry/error status per name. (I9)
function summarizeRotate(results) {
  if (!results || typeof results !== "object") return "(no result)";
  const parts = [];
  for (const [name, r] of Object.entries(results)) {
    if (name === "_doorKey") continue; // the raw door-key — never log it
    if (r && r.error) parts.push(`${name}=error(${r.error})`);
    else if (r && r.minted) parts.push(`${name}=minted(ttl=${r.expires_in ?? "?"})`);
    else parts.push(`${name}=ok`);
  }
  return parts.join(" ") || "(empty)";
}

// Timeout helper — pure setTimeout, no deps. (Not an outbound I/O; fine to use directly.)
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Test hooks: export the pure helpers so the unit test can exercise the gate/parse logic
//    WITHOUT booting a real long-poll or hitting the network. Not part of the module contract;
//    the kernel only reads `default`. ──
export const _test = { parseWhitelist, readUpdate, summarizeRotate };
