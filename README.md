⚡ Kingception

A single-file, Burp Suite–style HTTP intercepting proxy and web security testing suite, built with PyQt6. Kingception runs a local MITM proxy, lets you intercept and rewrite traffic in flight, replay and fuzz requests, run active/passive vulnerability scans, and get an AI-assisted second opinion on anything you capture — all in one dark-themed desktop app.


Legal & ethical use: Kingception is built for testing systems you own or are explicitly authorized to test (e.g. your own apps, or in-scope targets like PortSwigger's Web Security Academy). Intercepting, fuzzing, or scanning traffic you don't have permission to test may be illegal in your jurisdiction. Use responsibly.




Contents


Features at a glance
Requirements
Installation
Running Kingception
First-time setup: trusting the CA certificate
Tab-by-tab guide
Data storage
Known limitations
Troubleshooting



Features at a glance

AreaHighlightsProxyLocal MITM proxy on 127.0.0.1:8080, auto-starts on launch, dynamic per-host TLS certs signed by a generated local CATrafficFull history table with method, status, size, timing, and content-type; right-click to send anywhereInterceptLive request queue with pause/forward/drop, Raw/Headers/Body/Pretty/Hex editor, plus a dedicated WebSocket frame inspector/injectorRepeaterMulti-tab, Burp-style layout — compact Target field (scheme+host) with the path living in the editor, so long URLs never break the UI; \r\n toggle, cURL/Python export, one-click CSRF PoC generatorIntruderSniper / Battering Ram / Pitchfork / Cluster Bomb attack types, §...§ position markers with Add/Clear/Auto-detect, built-in payload sets (SQLi, XSS, LFI, SSTI, command injection, NoSQLi, fuzzing lists, credential lists)ScannerActive engine (15+ checks: SQLi, XSS, SSTI, command injection, path traversal, XXE, SSRF, JWT weaknesses, sensitive file exposure, HTTP method abuse, and more) plus a passive mode that audits already-captured traffic without sending a single extra requestAnalysisAttack-surface mapper: technology fingerprinting, endpoint inventory, parameter extraction, secret scanning (API keys, JWTs, private keys, credit cards…), auth-mechanism detection, cookie audit, and a ready-made attack-surface checklistDecoderBase64 (standard/URL-safe), URL encode/decode, hex, HTML entities, JWT decode, MD5/SHA-256, ROT13LoggerSearchable, filterable log of every request/response with live stats (2xx/3xx/4xx/5xx breakdown), CSV/JSON/HAR exportAI AnalyzerSend any captured request/response to Claude for a structured security review (OWASP Top 10, auth analysis, injection review, threat modeling, and more), with follow-up Q&A in the same sessionSettingsCA certificate generation/export, Match & Replace rules, scope allowlist, dark/light theme, traffic export/import


Requirements


Python 3.10+
PyQt6 (required — the GUI won't start without it)
requests (required for Repeater, Intruder, and Scanner to actually send traffic)
cryptography (required for HTTPS interception — without it, HTTPS traffic is tunneled but not decrypted/inspected)
pyjwt (optional — enables the JWT Decode operation in the Decoder tab and JWT weakness checks in the Scanner)


Kingception detects missing optional packages at startup and prints an install hint instead of crashing.

Installation

