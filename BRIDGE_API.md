# BRIDGE_API.md — deprecated

This document was stale (it listed a ±60 s signing window and an `env HMAC_SECRET`
that no longer exist). The shipped code uses a **±3600 s** window and a **KV-only**
secret.

**See instead:**
- [README.md](README.md) — deploy, security, lifecycle, troubleshooting
- [docs/API.md](docs/API.md) — accurate API & signing reference
- [clients/](clients/) — working Python / JS / Bash signers
