/**
 * bridge-mta — Cloudflare Worker: HMAC мост + Telegram keychain-бот (webhook).
 *
 * Маршруты:
 *   POST /tg/<TG_WEBHOOK_SECRET>  → Telegram webhook (бот: ⚡ Выдать / 💀 Убить)
 *   GET  /?op=...                 → мост (ping/echo/info/ops/secure_echo; signed)
 *   GET  /                        → health
 *
 * Состояние (KV NONCES, переиспользуется как общий KV):
 *   nonce:<n>     — anti-replay, TTL 120s
 *   hmac:current  — активный Bridge HMAC (ротируется ботом), TTL 3600s
 *   kc:gh         — активный GitHub installation token JSON {token,expires_at}
 *
 * Секреты (wrangler secret put):
 *   TG_TOKEN, TG_WEBHOOK_SECRET, TG_OWNER_IDS,
 *   GITHUB_APP_ID, GITHUB_INSTALL_ID, GITHUB_APP_PEM (PKCS#8)
 */

const SIG_VERSION = "v1";
const TS_WINDOW_SEC = 3600;  // окно подписи 1ч (было 60с): ссылка живёт час, 💀 убивает досрочно
const NONCE_TTL_SEC = 3600;  // синхронно с окном — anti-replay в пределах всего окна
const KEY_TTL_SEC = 3600;

const BTN_ISSUE = "⚡ Выдать ключи";
const BTN_KILL = "💀 Убить ключи";
const BRIDGE_URL = "https://<your-worker>.workers.dev"; // informational only; not used at runtime
const GH_UA = "bridge-mta-bot/1.0";

// op=do — исходящий прокси. Allowlist хостов (SSRF-guard). env.ALLOW_HOSTS переопределяет.
const ALLOW_HOSTS = new Set(["api.github.com", "api.telegram.org"]);
const DO_MAX_RESP = 100000;

// ───────────── РЕЕСТР КОМАНД МОСТА ─────────────
const OPS = {
  async ping(p, env, req) {
    return ok({ pong: true, time: Date.now() });
  },
  async echo(p, env, req) {
    return ok({ msg: p.msg || "" });
  },
  async info(p, env, req) {
    const cf = req.cf || {};
    return ok({
      version: "0.3.0",
      time: Date.now(),
      colo: cf.colo, country: cf.country, asn: cf.asn, tlsVersion: cf.tlsVersion,
    });
  },
  async ops(p, env, req) {
    return ok({ commands: Object.keys(OPS).sort() });
  },
  async secure_echo(p, env, req) {
    const safe = { ...p };
    delete safe.sig;
    return ok({ secured: true, params: safe });
  },
  // Универсальный исходящий прокси. t=target(URI), m=method, p=payload(b64url),
  // c=1 → payload сжат deflate-raw, h=headers(b64url JSON). Тело подписано (p в canonical).
  async do(p, env, req) {
    let target;
    try { target = new URL(p.t || ""); } catch { return err(400, "bad_target"); }
    if (target.protocol !== "https:") return err(400, "only_https");
    const allow = env.ALLOW_HOSTS
      ? new Set(env.ALLOW_HOSTS.split(/[,\s]+/).filter(Boolean))
      : ALLOW_HOSTS;
    if (!allow.has(target.hostname)) return err(403, "host_not_allowed", { host: target.hostname });

    const method = (p.m || "GET").toUpperCase();

    let body;
    if (p.p) {
      try {
        let buf = b64urlToBuf(p.p);
        if (p.c === "1") buf = await inflateRaw(buf);
        body = buf;
      } catch (e) { return err(400, "bad_payload"); }
    }

    const headers = { "User-Agent": GH_UA };
    if (p.h) {
      try { Object.assign(headers, JSON.parse(new TextDecoder().decode(b64urlToBuf(p.h)))); }
      catch { return err(400, "bad_headers"); }
    }

    // GitHub: подставляем installation-token из KV (не покидает облако)
    if (target.hostname === "api.github.com" && !headers.Authorization && env.NONCES) {
      const gh = await env.NONCES.get("kc:gh", "json");
      if (gh && gh.token) {
        headers.Authorization = `Bearer ${gh.token}`;
        if (!headers.Accept) headers.Accept = "application/vnd.github+json";
      }
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    let r;
    try {
      r = await fetch(target.toString(), {
        method,
        headers,
        body: (method === "GET" || method === "HEAD") ? undefined : body,
        redirect: "manual",
        signal: ctrl.signal,
      });
    } catch (e) {
      clearTimeout(timer);
      return err(502, "upstream_failed", { detail: String(e).slice(0, 150) });
    }
    clearTimeout(timer);

    const text = await r.text();
    return ok({ status: r.status, body: text.slice(0, DO_MAX_RESP) });
  },
};
const PUBLIC_OPS = new Set(["ping", "info", "echo", "ops"]);

// ───────────── HMAC + canonical ─────────────
function canonical(path, params) {
  const enc = (s) => encodeURIComponent(String(s));
  const pairs = Object.entries(params)
    .filter(([k]) => k !== "sig")
    .map(([k, v]) => `${enc(k)}=${enc(v)}`)
    .sort();
  return `${SIG_VERSION}\n${path}\n${pairs.join("&")}`;
}

async function computeHmacHex(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// HMAC секрет: сначала KV (ротируется ботом), потом env (fallback)
async function getHmacSecret(env) {
  if (env.NONCES) {
    const k = await env.NONCES.get("hmac:current");
    if (k) return k;
  }
  return ""; // KV-only: до ⚡ и после 💀 подписи невалидны (no_secret_server)
}

async function verifyRequest(path, params, env) {
  const sig = params.sig || "";
  if (!sig) return { ok: false, err: "no_sig" };

  const tsStr = params.ts || "";
  if (!tsStr) return { ok: false, err: "no_ts" };
  const ts = Number.parseInt(tsStr, 10);
  if (!Number.isFinite(ts)) return { ok: false, err: "bad_ts" };
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > TS_WINDOW_SEC) return { ok: false, err: "ts_expired" };

  const nonce = params.nonce || "";
  if (!nonce || nonce.length < 8 || nonce.length > 128) return { ok: false, err: "bad_nonce" };

  const secret = await getHmacSecret(env);
  if (!secret) return { ok: false, err: "no_secret_server" };
  const expected = await computeHmacHex(secret, canonical(path, params));
  if (!ctEqual(sig, expected)) return { ok: false, err: "bad_sig" };

  if (env.NONCES) {
    const seen = await env.NONCES.get("nonce:" + nonce);
    if (seen) return { ok: false, err: "replay" };
    await env.NONCES.put("nonce:" + nonce, "1", { expirationTtl: NONCE_TTL_SEC });
  }
  return { ok: true };
}

// ───────────── Response helpers ─────────────
const SEC_HEADERS = {
  "Cache-Control": "no-store, private, no-cache",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow",
};
function ok(data) {
  return new Response(JSON.stringify({ ok: true, ...data }), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", ...SEC_HEADERS },
  });
}
function err(code, msg, extra = {}) {
  return new Response(JSON.stringify({ ok: false, error: msg, ...extra }), {
    status: code,
    headers: { "Content-Type": "application/json; charset=utf-8", ...SEC_HEADERS },
  });
}

// ───────────── base64 / b64url ─────────────
function b64urlFromBuf(buf) {
  let s = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlFromStr(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBuf(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
async function inflateRaw(buf) {
  const stream = new Response(buf).body.pipeThrough(new DecompressionStream("deflate-raw"));
  return await new Response(stream).arrayBuffer();
}
function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

// ───────────── GitHub App (WebCrypto RS256) ─────────────
// Берём время из GitHub (заголовок Date) — устойчиво к перекосу часов воркера.
async function githubNow() {
  try {
    const r = await fetch("https://api.github.com/zen", { headers: { "User-Agent": GH_UA } });
    const d = r.headers.get("date");
    if (d) {
      const t = Math.floor(new Date(d).getTime() / 1000);
      if (Number.isFinite(t) && t > 0) return t;
    }
  } catch (e) { /* fallback ниже */ }
  return Math.floor(Date.now() / 1000);
}

async function makeAppJwt(env) {
  const now = await githubNow();
  const header = b64urlFromStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64urlFromStr(JSON.stringify({
    iat: now - 60, exp: now + 540, iss: String(env.GITHUB_APP_ID),
  }));
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    "pkcs8", pemToArrayBuffer(env.GITHUB_APP_PEM),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(data));
  return `${data}.${b64urlFromBuf(sig)}`;
}

async function issueGithub(env) {
  const jwt = await makeAppJwt(env);
  const r = await fetch(
    `https://api.github.com/app/installations/${env.GITHUB_INSTALL_ID}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": GH_UA,
      },
    }
  );
  const text = await r.text();
  if (r.status !== 200 && r.status !== 201) {
    throw new Error(`GitHub ${r.status}: ${text.slice(0, 200)}`);
  }
  const d = JSON.parse(text);
  return { token: d.token, expires_at: d.expires_at };
}

async function revokeGithub(token) {
  try {
    await fetch("https://api.github.com/installation/token", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": GH_UA,
      },
    });
  } catch (e) { /* best-effort */ }
}

function randToken(prefix) {
  const b = new Uint8Array(24);
  crypto.getRandomValues(b);
  return prefix + [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ───────────── Telegram helpers ─────────────
async function tg(env, method, payload) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${env.TG_TOKEN}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return await r.json();
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

const KB = {
  keyboard: [[{ text: BTN_ISSUE }, { text: BTN_KILL }]],
  resize_keyboard: true,
  is_persistent: true,
  input_field_placeholder: "⚡ Выдать  /  💀 Убить",
};

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function fmtUtc(unixSec) {
  return new Date(unixSec * 1000).toISOString().slice(11, 16) + " UTC";
}
function isOwner(env, uid) {
  const ids = String(env.TG_OWNER_IDS || "").replace(/,/g, " ").split(/\s+/).filter(Boolean);
  return ids.length === 0 || ids.includes(String(uid));
}

// ⚡ Выдать оба ключа
async function botIssue(env, chatId) {
  const oldGh = await env.NONCES.get("kc:gh", "json");
  if (oldGh && oldGh.token) await revokeGithub(oldGh.token);

  let gh = null, ghErr = null;
  try { gh = await issueGithub(env); } catch (e) { ghErr = String(e).slice(0, 200); }

  const hmac = randToken("bridge-");
  await env.NONCES.put("hmac:current", hmac, { expirationTtl: KEY_TTL_SEC });

  const now = Math.floor(Date.now() / 1000);
  let ghExp = now + 3600;
  if (gh) {
    ghExp = Math.floor(new Date(gh.expires_at).getTime() / 1000);
    await env.NONCES.put("kc:gh", JSON.stringify(gh),
      { expirationTtl: Math.max(60, ghExp - now) });
  }

  // Копируемый блок: краткая подпись + секрет (всё в одном <pre>), пояснения — снаружи
  const inner = [];
  if (gh) inner.push("github", gh.token);
  inner.push("bridge", hmac);
  const lines = [
    "<pre>" + esc(inner.join("\n")) + "</pre>",
    "",
    `🔑 <b>Ключи выданы</b> · истекают ${fmtUtc(now + KEY_TTL_SEC)}`,
  ];
  if (!gh) lines.push(`⚠️ GitHub не выдан: ${esc(ghErr)}`);
  lines.push("⚡ пересоздать · 💀 убить досрочно");
  await tg(env, "sendMessage", {
    chat_id: chatId, text: lines.join("\n"), parse_mode: "HTML",
    reply_markup: KB, disable_web_page_preview: true,
  });
}

// 💀 Убить оба
async function botKill(env, chatId) {
  const killed = [];
  const oldGh = await env.NONCES.get("kc:gh", "json");
  if (oldGh && oldGh.token) {
    await revokeGithub(oldGh.token);
    await env.NONCES.delete("kc:gh");
    killed.push("🐙 GitHub");
  }
  const hm = await env.NONCES.get("hmac:current");
  if (hm) {
    await env.NONCES.delete("hmac:current");
    killed.push("🌉 Bridge HMAC");
  }
  const text = killed.length
    ? "💀 <b>Убиты:</b>\n" + killed.map((k) => "  ✓ " + k).join("\n")
    : "Активных ключей нет.";
  await tg(env, "sendMessage", { chat_id: chatId, text, parse_mode: "HTML", reply_markup: KB });
}

async function handleUpdate(env, update) {
  const msg = update.message || update.edited_message;
  if (!msg || !msg.chat) return;
  const uid = msg.from && msg.from.id;
  const chatId = msg.chat.id;
  if (!isOwner(env, uid)) return; // silent drop — не выдаём существование бота

  const text = (msg.text || "").trim();
  if (text === "/start") {
    await tg(env, "sendMessage", {
      chat_id: chatId, parse_mode: "HTML", reply_markup: KB,
      text: "<b>Keychain</b> на Cloudflare (рядом с мостом).\n\n" +
        "⚡ <b>Выдать</b> — GitHub installation token + новый Bridge HMAC (TTL 1ч)\n" +
        "💀 <b>Убить</b> — мгновенно отзывает оба\n\n" +
        "Повторное ⚡ — пересоздаёт (старые умирают).",
    });
    return;
  }
  if (text === BTN_ISSUE) {
    await tg(env, "sendMessage", { chat_id: chatId, text: "⏳ Выдаю ключи…", reply_markup: KB });
    await botIssue(env, chatId);
    return;
  }
  if (text === BTN_KILL) {
    await botKill(env, chatId);
    return;
  }
  // прочее игнорируем
}

// ───────────── MAIN HANDLER ─────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Telegram webhook
    if (request.method === "POST" && env.TG_WEBHOOK_SECRET &&
        url.pathname === `/tg/${env.TG_WEBHOOK_SECRET}`) {
      const hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
      if (hdr !== env.TG_WEBHOOK_SECRET) return new Response("forbidden", { status: 403 });
      let update;
      try { update = await request.json(); } catch { return new Response("bad", { status: 400 }); }
      try { await handleUpdate(env, update); } catch (e) { /* swallow → always 200 */ }
      return new Response("ok");
    }

    // Bridge ops (GET)
    if (request.method !== "GET") return err(405, "method_not_allowed");

    const params = Object.fromEntries(url.searchParams);
    const op = params.op || "";

    if (!op) {
      return ok({ pong: true, msg: "bridge alive", v: "0.3.0", time: Date.now() });
    }
    if (PUBLIC_OPS.has(op)) {
      return OPS[op](params, env, request);
    }

    // Авторизация: либо прямое предъявление ТЕКУЩЕГО bridge-ключа из KV (для клиентов,
    // умеющих только GET по URL — читалки ссылок/WebFetch, HMAC посчитать не могут),
    // либо полноценная HMAC-подпись. Прямой ключ светится в URL и без anti-replay,
    // но короткоживущий (ротируется ⚡/💀) — осознанный компромисс под простых клиентов.
    const liveKey = params.key ? await getHmacSecret(env) : "";
    if (liveKey && params.key === liveKey) {
      // предъявлен валидный текущий bridge-ключ — HMAC пропускаем
    } else {
      const v = await verifyRequest(url.pathname, params, env);
      if (!v.ok) return err(401, v.err);
    }

    const handler = OPS[op];
    if (!handler) return err(400, "unknown_op", { op, available: Object.keys(OPS).sort() });

    try {
      return await handler(params, env, request);
    } catch (e) {
      return err(500, "op_failed", { detail: String(e).slice(0, 200) });
    }
  },
};
