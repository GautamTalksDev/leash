# Security

LEASH holds other people's production keys. This page is the honest version of how it protects them.

## Reporting a vulnerability

Email **security@gautamkhosla.com** or open a private advisory on GitHub (Security tab, "Report a vulnerability").
Please do not open a public issue. You will get an answer within 72 hours. Good-faith research is welcome; do not access
other people's data or degrade the service.

## Controls, mapped to OWASP

| Area | Control | OWASP |
|---|---|---|
| Sign-in | Passkeys only (WebAuthn, user verification required, origin and RP ID checked, single-use 5-minute challenges, signature counters) | A07 Identification and Authentication Failures |
| Sessions | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`, 12 h; CLI sessions are bearer tokens stored only as SHA-256 hashes | A07 |
| CSRF | Web writes require same `Origin` and an `x-leash: 1` header; no CORS; `OPTIONS` refused | A01 Broken Access Control |
| Authorization | Every query is scoped by `account_id`; holds, tokens and credentials of another account return 404 (tested) | A01, API1 BOLA |
| Privilege separation | CLI sessions can mint tokens but cannot approve holds or pre-approve irreversible operations | A01, A04 Insecure Design |
| Secrets | Envelope encryption: AES-256-GCM per secret, data key wrapped by a master key (Workers secret); AAD binds each ciphertext to its account, row and provider; no API returns a secret; secrets never logged | A02 Cryptographic Failures |
| Injection | All SQL is parameterized; request bodies are size-capped and parsed as JSON only | A03 Injection |
| SSRF | Upstream hosts are a fixed allow list per provider; paths are checked for traversal and encoded separators; redirects are never followed | A10 SSRF, API7 |
| Rate limits | Per token (policy, default 120/min), per account (300/min), per IP (IPv6 grouped by /64, salted hash) | API4 Unrestricted Resource Consumption |
| Headers | Strict CSP with `require-trusted-types-for 'script'`, HSTS preload, COOP, CORP, `X-Frame-Options: DENY`, `Permissions-Policy` | A05 Security Misconfiguration |
| Supply chain | Zero runtime dependencies in the Worker and the CLI; GitHub Actions pinned by SHA | A06, A08 |
| Logging | Hash-chained, append-only audit; tamper detection endpoint; no request bodies, tokens or keys in logs; a hold's audit entry records the SHA-256 of its request preview, and the preview itself is deleted a day after the decision | A09 Logging and Monitoring Failures |
| Agents (LLM Top 10) | Excessive agency is the threat LEASH exists for: irreversible calls are held outside the model; tool descriptions tell the agent not to route around holds | LLM06 Excessive Agency |

## What LEASH does not protect against

- A human approving something they should not. The approve screen shows the exact method, host and path, the reason, and a preview of the request (query string, SQL or GraphQL, body; at most 2 KB).
- An upstream API key that is itself over-scoped being used outside LEASH. Rotate keys you hand to LEASH and keep them only
  in the vault.
- Calls the map does not know are irreversible. The map is versioned and conservative (every `DELETE` is held on every
  provider); add `hold` rules to your policy for anything else you care about.
- A compromised Cloudflare account. The master key lives in Workers secrets.

## Hardening, 7 Oct 2026

- SQL to Supabase and D1 is now an allow list: only a single SELECT, WITH ... SELECT, EXPLAIN (without ANALYZE) or SHOW
  passes, read by a real tokenizer (quotes, quoted identifiers, comments). Dollar quotes, DO, EXECUTE, CALL, COPY, a second
  statement or anything unreadable is held.
- D1 bodies: every `sql`, `query` and batch entry is checked; a body with both `sql` and `query` is held.
- Paths: empty segments are refused, one trailing slash is dropped, GitHub owner and repo are matched case-insensitively,
  and the exact path that was checked is the one sent upstream.
- GitHub force-push and visibility rules parse the JSON body instead of matching text; unreadable bodies are held.
- Railway: a GraphQL lexer (commas, comments, strings) reads root mutation fields; only redeploy and restart pass. Batched
  array bodies, persisted queries and mutations sent over GET are held.
- Stripe: payment intents created with `confirm=true`, charge and application fee refunds, invoice pay and void, credit
  notes, and scheduled subscription cancellation are held. Map version `2026-10-07.2`.
- Holds store and show a capped preview of the request (deleted a day after the decision; the audit log keeps only its hash).
- SQL is held unless it is one read-only statement calling only known pure functions.
- Deleting your account needs a fresh passkey ceremony; deleting a vaulted key needs a web session.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
