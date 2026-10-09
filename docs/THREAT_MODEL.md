# Threat model

LEASH sits between an AI agent and production APIs. It assumes the agent is **capable, fast, and sometimes wrong**, and
that anything the agent can read on the machine it runs on, an attacker who prompt-injects that agent can read too.

## Assets

1. Real API keys in the vault.
2. The decision of whether an irreversible call happens.
3. The integrity of the audit log.

## Actors

| Actor | Can | Cannot |
|---|---|---|
| The agent (honest but wrong, or prompt-injected) | Use its `lsh_` token; read the CLI config on its machine | See a real key; approve a hold; mint a token with pre-approved irreversible calls |
| Someone holding a leaked `lsh_` token | Make the calls that token's policy allows, until it expires or is revoked | Exceed the policy; get past a hold; read the key |
| Someone holding a stolen CLI session | List holds, mint ordinary tokens | Approve holds; mint pre-approved tokens; read keys |
| A phishing site | Ask for a passkey | Get an assertion LEASH accepts (origin and RP ID are bound into it) |
| A malicious web page in the user's browser | Send requests | Write to the API (SameSite=Strict, Origin check, custom header, no CORS) |
| An attacker with a database dump | Read ciphertext and hashes | Decrypt keys without the master key; use token hashes |

## Scenarios and mitigations

**S1. Agent finds a token and runs a destructive call (the PocketOS case).** The only tokens on the machine are `lsh_`
tokens. The destructive call matches the irreversible map and is held. Test: *PocketOS replay* in
`server/test/leash.test.js`.

**S2. Agent tries to approve its own hold.** Approval requires a WebAuthn assertion from a web session. CLI sessions get
`403 passkey_required`. Test: *a CLI session can mint tokens but can never approve a hold*.

**S3. Agent tries to change its own policy to skip holds.** `unattendedIrreversible` rules can only be set in a passkey
ceremony. Same test.

**S4. Approval replay.** An approval is bound to the request hash (method, host, path, query, body) and is consumed
atomically on first use (`UPDATE ... RETURNING`). Test: *a passkey approval lets the exact same request through once*.

**S5. Approval stretching.** Approving `DELETE /repos/acme/app` does not cover `DELETE /repos/acme/billing`. Test: *an
approval only covers the request it was given for*.

**S6. Path tricks to escape a provider or an allow list.** Dot segments are collapsed by URL parsing before routing;
encoded slashes and dots, backslashes and whitespace are refused; the upstream host is fixed per provider. Test: *policy:
... traversal*.

**S6b. Parser differentials to slip a call past the map.** The agent sends a request LEASH reads one way and the
upstream another: a repeated parameter (`confirm=false&confirm=true`; Rack keeps the last copy), the same parameter in
the body and the query string, a `;` separator, a JSON escape or case variant of a key, a method override (`_method`),
a doubled trailing slash, a different case or a `.json` suffix in the path, a HEAD for a GET. LEASH reads every copy,
treats JSON with repeated or case-variant keys as unreadable, and holds whenever two readings could disagree. Tests:
`server/test/bypass.test.js`.

**S7. Cross-account access (IDOR).** Every query is scoped by account; foreign ids return 404. Test: *another account
cannot see or approve your holds*.

**S8. Database theft.** Keys are envelope-encrypted with AAD bound to account, row and provider; swapping ciphertexts
between rows fails to decrypt. Tokens and sessions are stored as SHA-256 hashes. Test: *vault rows cannot be swapped*.

**S9. Log tampering.** Each audit row hashes the previous one; `/v1/audit/verify` detects edits and deletions. Test:
*the audit log is hash-chained and detects tampering*.

**S10. Phishing for passkeys.** WebAuthn binds origin and RP ID; assertions from another origin are rejected. User
verification is required. Test: *phishing origin and missing user verification are rejected*.

## Residual risks

- Irreversible operations the map does not cover. Mitigation: conservative defaults (every `DELETE` held), versioned map,
  user `hold` rules, public map for review.
- The human approves the wrong thing. Mitigation: the approve screen shows method, host, path, rule and reason.
- Master key compromise via the Cloudflare account. Mitigation: hardware-key 2FA on the Cloudflare account, key rotation
  procedure in [DEPLOY.md](DEPLOY.md).
