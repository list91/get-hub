<?php
// Copy this file to config.php (same directory) and set your own values.
// config.php is gitignored — never commit real secrets.

// Static access key clients pass as ?key=... (token-mode auth).
// Generate a random one, e.g.:  echo 'clawbridge-'.bin2hex(random_bytes(10));
const ACCESS_KEY = 'REPLACE_WITH_YOUR_ACCESS_KEY';

// Optional fallback GitHub installation token. Usually you pass a fresh token
// per request via the gh= query param instead (installation tokens live ~1h),
// so leaving the placeholder is fine.
const GH_TOKEN = 'GH_TOKEN_PLACEHOLDER';
