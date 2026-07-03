<?php
// bridge-mta — PHP port of the Cloudflare Worker for shared hosting.
// op=do — outgoing HTTP proxy with host allowlist + token-mode auth + GitHub
// injection + deflate. Auth: key=<ACCESS_KEY> (for clients that can only GET a URL).
//
// Config lives in config.php (gitignored). Copy config.example.php → config.php
// and set your own ACCESS_KEY / GH_TOKEN. Behaviour is identical to the inline
// version; only the two secrets were externalised.

$__cfg = __DIR__ . '/config.php';
if (!is_file($__cfg)) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'no_config',
        'hint' => 'Copy config.example.php to config.php and set ACCESS_KEY.']);
    exit;
}
require $__cfg; // defines ACCESS_KEY and GH_TOKEN

const ALLOW_HOSTS = ['api.github.com', 'api.telegram.org'];
const MAX_RESP = 100000;

$__raw = (($_GET['format'] ?? '') === 'raw');   // format=raw → text/plain (so Exa/web_fetch reads the body)
header('Content-Type: ' . ($__raw ? 'text/plain' : 'application/json') . '; charset=utf-8');
header('Cache-Control: no-store, private, no-cache');
header('X-Robots-Tag: noindex, nofollow');
header('Pragma: no-cache');

function out($code, $arr) { http_response_code($code); echo json_encode($arr, JSON_UNESCAPED_SLASHES); exit; }
function b64url_decode($s) { return base64_decode(strtr($s, '-_', '+/')); }

$op = $_GET['op'] ?? '';

if ($op === '') {
    out(200, ['ok' => true, 'pong' => true, 'msg' => 'bridge alive', 'v' => 'php-0.1', 'time' => (int)round(microtime(true) * 1000)]);
}
if ($op === 'info') {
    out(200, ['ok' => true, 'version' => 'php-0.1', 'host' => $_SERVER['HTTP_HOST'] ?? '', 'time' => (int)round(microtime(true) * 1000)]);
}

if ($op === 'do') {
    // static-key auth
    if (($_GET['key'] ?? '') !== ACCESS_KEY) out(401, ['ok' => false, 'error' => 'bad_key']);

    $target = $_GET['t'] ?? '';
    $u = parse_url($target);
    if (!$u || ($u['scheme'] ?? '') !== 'https' || empty($u['host'])) out(400, ['ok' => false, 'error' => 'bad_target']);
    if (!in_array($u['host'], ALLOW_HOSTS, true)) out(403, ['ok' => false, 'error' => 'host_not_allowed', 'host' => $u['host']]);

    $method = strtoupper($_GET['m'] ?? 'GET');

    // body (optional): base64url, deflate-raw when c=1
    $body = null;
    if (!empty($_GET['p'])) {
        $raw = b64url_decode($_GET['p']);
        if (($_GET['c'] ?? '') === '1') { $raw = @gzinflate($raw); if ($raw === false) out(400, ['ok' => false, 'error' => 'bad_payload']); }
        $body = $raw;
    }

    $headers = ['User-Agent: bridge-mta-php/0.1', 'Cache-Control: no-cache', 'Pragma: no-cache'];
    if (!empty($_GET['h'])) {
        $h = json_decode(b64url_decode($_GET['h']), true);
        if (is_array($h)) foreach ($h as $k => $v) $headers[] = "$k: $v";
    }

    // github: token from gh= param (fresh, client-supplied) or the GH_TOKEN fallback
    $ghtok = $_GET['gh'] ?? GH_TOKEN;
    if ($u['host'] === 'api.github.com' && $ghtok !== '' && $ghtok !== 'GH_TOKEN_PLACEHOLDER') {
        $headers[] = 'Authorization: Bearer ' . $ghtok;
        $headers[] = 'Accept: application/vnd.github+json';
        $headers[] = 'X-GitHub-Api-Version: 2022-11-28';
    }

    $ch = curl_init($target);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_FOLLOWLOCATION => false,
    ]);
    if ($body !== null && !in_array($method, ['GET', 'HEAD'], true)) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);

    $resp = curl_exec($ch);
    if ($resp === false) {
        $e = curl_error($ch); curl_close($ch);
        out(200, ['ok' => false, 'upstream_status' => null, 'error' => 'network_error',
            'hint' => 'Bridge could not reach upstream: ' . substr($e, 0, 120),
            'fetched_at' => gmdate('c'), 'body' => null]);
    }
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // honest upstream-status mapping (ok = 2xx, otherwise an explicit reason)
    $ok = ($status >= 200 && $status < 300);
    $error = null; $hint = null;
    if (!$ok) {
        if ($status === 401) {
            $error = 'token_expired';
            $hint = 'GitHub token invalid/expired/revoked — supply a fresh one (ghs_ lives ~1h).';
        } elseif ($status === 404) {
            $error = 'not_found';
            $hint = 'Repo not found or no access (private without permission).';
        } elseif ($status === 403 || $status === 429) {
            if (stripos($resp, 'rate limit') !== false) { $error = 'rate_limited'; $hint = 'GitHub rate limit reached — retry later.'; }
            else { $error = 'forbidden'; $hint = 'GitHub refused (403) — possible lockout after repeated auth errors.'; }
        } elseif ($status >= 500) {
            $error = 'upstream_error'; $hint = 'GitHub server error (' . $status . ') — retry later.';
        } else {
            $error = 'upstream_error'; $hint = 'Unexpected upstream status: ' . $status;
        }
    }

    out(200, ['ok' => $ok, 'upstream_status' => $status, 'error' => $error, 'hint' => $hint,
        'fetched_at' => gmdate('c'), 'body' => substr($resp, 0, MAX_RESP)]);
}

out(400, ['ok' => false, 'error' => 'unknown_op', 'op' => $op]);
