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
| Logging | Hash-chained, append-only audit; tamper detection endpoint; no request bodies, tokens or keys in logs | A09 Logging and Monitoring Failures |
| Agents (LLM Top 10) | Excessive agency is the threat LEASH exists for: irreversible calls are held outside the model; tool descriptions tell the agent not to route around holds | LLM06 Excessive Agency |

## What LEASH does not protect against

- A human approving something they should not. The approve screen shows the exact method, host and path, and the reason.
- An upstream API key that is itself over-scoped being used outside LEASH. Rotate keys you hand to LEASH and keep them only
  in the vault.
- Calls the map does not know are irreversible. The map is versioned and conservative (every `DELETE` is held on every
  provider); add `hold` rules to your policy for anything else you care about.
- A compromised Cloudflare account. The master key lives in Workers secrets.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
