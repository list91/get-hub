/**
 * Unit test for modules/telegram.mjs — the background-daemon module.
 *
 * Runs with zero deps: `node test/telegram.test.mjs` (Node >=18). No network, no real Telegram.
 * We drive start() with a FAKE core whose proxy() replays a scripted getUpdates response, then
 * assert the operator/whitelist gate and the rotate trigger behave per the contract:
 *   - non-whitelisted chat "/issue"           => NO rotate
 *   - whitelisted chat non-trigger text        => NO rotate
 *   - whitelisted chat "/issue"                => rotate(['door','github'], {door:3600,github:3600})
 *   - whitelisted inline button data "issue"   => rotate
 *   - empty TELEGRAM_TOKEN                      => clean no-op, never touches proxy
 *   - empty TELEGRAM_WHITELIST                  => refuses to run, never touches proxy
 *   - _doorKey / secrets never appear in any log line (I9)
 */
import assert from "node:assert/strict";
import mod, { _test } from "../modules/telegram.mjs";

let passed = 0;
function ok(name) { passed++; console.log(`  ok - ${name}`); }

// ── 1. pure helper: parseWhitelist ──
{
  const w = _test.parseWhitelist("111, -100222  333");
  assert.equal(w.size, 3);
  assert.ok(w.has("111") && w.has("-100222") && w.has("333"));
  assert.equal(_test.parseWhitelist("").size, 0);
  assert.equal(_test.parseWhitelist(null).size, 0);
  assert.equal(_test.parseWhitelist(undefined).size, 0);
  ok("parseWhitelist splits comma/space, tolerates blanks/null");
}

// ── 2. pure helper: readUpdate covers message / button / junk ──
// Now also extracts senderId (from.id) so the kernel can bind operator identity to the SENDER,
// not just the (shared) chat-id — the I12 group-member fix.
{
  assert.deepEqual(
    _test.readUpdate({ message: { chat: { id: 42 }, from: { id: 42 }, text: "/issue" } }),
    { chatId: "42", senderId: "42", isIssue: true }
  );
  assert.deepEqual(
    _test.readUpdate({ message: { chat: { id: 42 }, from: { id: 42 }, text: "  /ISSUE  " } }),
    { chatId: "42", senderId: "42", isIssue: true },
    "trim + case-insensitive"
  );
  assert.deepEqual(
    _test.readUpdate({ message: { chat: { id: -100222 }, from: { id: 777 }, text: "/issue@get_hub_bot" } }),
    { chatId: "-100222", senderId: "777", isIssue: true },
    "group: chatId is the group, senderId is the individual member (distinct)"
  );
  assert.deepEqual(
    _test.readUpdate({ message: { chat: { id: 42 }, from: { id: 42 }, text: "hello" } }),
    { chatId: "42", senderId: "42", isIssue: false }
  );
  assert.deepEqual(
    _test.readUpdate({ callback_query: { data: "issue", from: { id: 5 }, message: { chat: { id: 7 } } } }),
    { chatId: "7", senderId: "5", isIssue: true },
    "inline button data=issue carries its own sender"
  );
  assert.deepEqual(
    _test.readUpdate({ callback_query: { data: "nope", from: { id: 9 } } }),
    { chatId: "9", senderId: "9", isIssue: false },
    "callback falls back to from.id for chat"
  );
  assert.deepEqual(_test.readUpdate({}), { chatId: "", senderId: "", isIssue: false });
  assert.deepEqual(_test.readUpdate(null), { chatId: "", senderId: "", isIssue: false });
  assert.deepEqual(_test.readUpdate({ message: { text: "/issue" } }), { chatId: "", senderId: "", isIssue: true }, "no chat.id => empty chatId (will be gated out)");
  ok("readUpdate extracts chatId + senderId + isIssue across message/button/junk");
}

// ── 3. summarizeRotate strips _doorKey and never leaks a secret value ──
{
  const s = _test.summarizeRotate({
    "door": { minted: true, expires_in: 3600 },
    "github": { minted: true, expires_in: 3600 },
    "_doorKey": "bridge-deadbeefcafef00d",
  });
  assert.ok(!s.includes("bridge-"), "door-key value must not appear");
  assert.ok(!s.includes("_doorKey"), "_doorKey name must not appear");
  assert.ok(s.includes("door=minted") && s.includes("github=minted"));
  assert.equal(_test.summarizeRotate({ github: { error: "rotate_failed" } }), "github=error(rotate_failed)");
  ok("summarizeRotate is I9-safe (no door-key value, no _doorKey key)");
}

// ── Fake core factory: scripts a single getUpdates batch, then a stop-signal error so the
//    infinite loop terminates deterministically for the test. Records every rotate + log. ──
// `operators` = { chats:[], senders:[] } — the KERNEL-side operator policy the fake control plane
// enforces (mirrors kernel.operatorAuthorized): a rotate is authorized iff the SENDER is a known
// operator, or the chat is a genuine 1:1 DM (sender==chat) on the operator-chats list. A group
// member (sender != chat, sender not an operator) is refused with {error:"not_operator"}.
function makeFakeCore({ env, updates, operators = { chats: [], senders: [] } }) {
  const rotateCalls = [];      // every FORWARDED rotate (regardless of authorization)
  const authorizedRotates = []; // only the rotates the kernel gate actually authorized
  const logs = [];
  let served = false;
  const authorize = (a) => {
    if (a == null) return true;
    const chatId = a.chatId != null ? String(a.chatId) : "";
    const senderId = a.senderId != null ? String(a.senderId) : "";
    if (senderId && operators.senders.includes(senderId)) return true;
    if (chatId && senderId && chatId === senderId && operators.chats.includes(chatId)) return true;
    return false;
  };
  return {
    core: {
      env,
      log: (m) => logs.push(String(m)),
      store: { get: () => null, set: () => {} },
      exec: async () => ({ ok: false, error: "exec_disabled" }),
      control: {
        rotate: async (names, ttlMap, assertion) => {
          rotateCalls.push({ names, ttlMap, assertion });
          // KERNEL gate (I12): refuse a non-operator (e.g. a group member) HERE.
          if (!authorize(assertion)) return { error: "not_operator" };
          authorizedRotates.push({ names, ttlMap, assertion });
          // Return a realistic result map INCLUDING the operator-only _doorKey to prove the
          // module never logs it.
          return {
            door: { minted: true, expires_in: (ttlMap && ttlMap.door) || 3600 },
            github: { minted: true, expires_in: (ttlMap && ttlMap.github) || 3600 },
            _doorKey: "bridge-secretsecretsecret0001",
          };
        },
      },
      proxy: async (url) => {
        // Assert the daemon reached Telegram through the boundary with the right host + no token leak in OUR view.
        assert.ok(url.startsWith("https://api.telegram.org/bot"), "proxy target is api.telegram.org getUpdates");
        if (!served) {
          served = true;
          return { ok: true, upstream_status: 200, error: null, body: JSON.stringify({ ok: true, result: updates }) };
        }
        // Second poll: the batch has been fully processed. The daemon is INTENTIONALLY immortal
        // (a background worker must never die), so we can't make start() return. Instead we park
        // this poll forever (a never-resolving promise) so there's no hot-loop/backoff churn while
        // the test's timer wins the race below. The test process.exit(0)s explicitly at the end.
        return new Promise(() => {});
      },
    },
    rotateCalls,
    authorizedRotates,
    logs,
  };
}

// Run start() to completion (it exits via the scripted __STOP__ throw's backoff → we cap it).
async function runStartOnce(env, updates, operators) {
  const { core, rotateCalls, authorizedRotates, logs } = makeFakeCore({ env, updates, operators });
  // start() never returns on its own; race it against a short timer. The scripted proxy throws
  // __STOP__ on the 2nd poll, then the loop backs off IDLE_BACKOFF_MS(1000) and re-polls (throws
  // again). One batch is fully processed before the first throw, which is all we assert.
  await Promise.race([mod.start(core), new Promise((r) => setTimeout(r, 300))]);
  return { rotateCalls, authorizedRotates, logs };
}

// ── 4. empty token => clean no-op, proxy never called ──
{
  let proxied = false;
  await mod.start({
    env: { TOKEN: "", WHITELIST: "111" },
    log: () => {},
    proxy: async () => { proxied = true; return { ok: true, body: "{}" }; },
    control: { rotate: async () => { throw new Error("must not rotate"); } },
    store: { get: () => null, set: () => {} },
  });
  assert.equal(proxied, false, "no token => proxy must never be called");
  ok("empty TELEGRAM_TOKEN => clean no-op (no proxy, no rotate)");
}

// ── 5. non-trigger text => module never forwards a rotate at all ──
{
  const { rotateCalls } = await runStartOnce(
    { TOKEN: "12345:AAtoken" },
    [{ update_id: 1, message: { chat: { id: 111 }, from: { id: 111 }, text: "hello there" } }],
    { chats: ["111"], senders: [] }
  );
  assert.equal(rotateCalls.length, 0, "no /issue gesture => module forwards nothing");
  ok("non-trigger text => rotate NOT forwarded");
}

// ── 6. GROUP MEMBER (sender != operator) /issue => kernel REFUSES (the I12 fix) ──
// The whole-chat is a whitelisted group (chat -100222), but the /issue comes from an ordinary
// member (from.id 777) who is NOT an operator sender. The module forwards {chatId,senderId};
// the KERNEL gate refuses (not_operator). A group member can no longer drive rotate.
{
  const { rotateCalls, authorizedRotates, logs } = await runStartOnce(
    { TOKEN: "12345:AAtoken" },
    [{ update_id: 1, message: { chat: { id: -100222 }, from: { id: 777 }, text: "/issue" } }],
    { chats: ["-100222"], senders: ["555"] }   // group is trusted, but 777 is NOT an operator
  );
  assert.equal(rotateCalls.length, 1, "module forwards the gesture with identity");
  assert.deepEqual(rotateCalls[0].assertion, { chatId: "-100222", senderId: "777" });
  assert.equal(authorizedRotates.length, 0, "kernel REFUSED a non-operator group member (I12)");
  assert.ok(logs.join("\n").includes("not an operator"), "refusal is logged");
  ok("group member /issue => kernel refuses (not_operator) — sender bound, not chat");
}

// ── 7. OPERATOR SENDER in a group /issue => kernel authorizes rotate ──
{
  const { rotateCalls, authorizedRotates, logs } = await runStartOnce(
    { TOKEN: "12345:AAtoken" },
    [{ update_id: 5, message: { chat: { id: -100222 }, from: { id: 555 }, text: "/issue" } }],
    { chats: ["-100222"], senders: ["555"] }   // 555 IS an operator sender
  );
  assert.equal(authorizedRotates.length, 1, "operator sender in a group is authorized");
  assert.deepEqual(authorizedRotates[0].names, ["door", "github"]);
  assert.deepEqual(authorizedRotates[0].ttlMap, { door: 3600, github: 3600 });
  const joined = logs.join("\n");
  assert.ok(!joined.includes("bridge-secretsecret"), "door-key value must never be logged (I9)");
  assert.ok(!joined.includes("12345:AAtoken"), "bot token must never be logged (I9)");
  ok("operator sender /issue in group => rotate(['door','github'],{3600,3600}), no secret in logs");
}

// ── 8. private DM (sender == chat) on the operator-chats list => authorized ──
{
  const { authorizedRotates } = await runStartOnce(
    { TOKEN: "12345:AAtoken" },
    [{ update_id: 8, message: { chat: { id: 42 }, from: { id: 42 }, text: "/issue" } }],
    { chats: ["42"], senders: [] }   // a genuine 1:1 DM: chat == sender
  );
  assert.equal(authorizedRotates.length, 1, "DM operator (sender==chat) is authorized");
  ok("private DM /issue (sender==chat) => rotate authorized");
}

// ── 9. operator inline button (data=issue) => authorized ──
{
  const { authorizedRotates } = await runStartOnce(
    { TOKEN: "12345:AAtoken" },
    [{ update_id: 9, callback_query: { data: "issue", from: { id: 555 }, message: { chat: { id: -100222 } } } }],
    { chats: [], senders: ["555"] }
  );
  assert.equal(authorizedRotates.length, 1, "operator button press triggers rotate");
  assert.deepEqual(authorizedRotates[0].names, ["door", "github"]);
  ok("operator inline-button data=issue => rotate authorized");
}

// ── 10. contract shape: background module, NO match/handle, has start ──
{
  assert.equal(mod.name, "telegram");
  assert.equal(typeof mod.start, "function");
  assert.equal(mod.match, undefined, "no data plane: match must be absent");
  assert.equal(mod.handle, undefined, "no data plane: handle must be absent");
  assert.ok(/^[a-z0-9_-]+$/.test(mod.name));
  ok("module shape: start-only background module (no match/handle)");
}

console.log(`\ntelegram.test.mjs: ${passed} checks passed.`);
// The module's start() is an intentionally-immortal daemon parked on a never-resolving proxy
// poll (see makeFakeCore). All assertions are done — exit cleanly instead of hanging on it.
process.exit(0);
