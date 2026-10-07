# Policy reference

Each `lsh_` token carries a policy. A policy can only **narrow** what the underlying key can do.

```json
{
  "allow": [{ "method": "GET", "path": "/repos/acme/**" }],
  "deny":  [{ "path": "/orgs/**" }],
  "hold":  [{ "method": "POST", "path": "/repos/*/*/releases" }],
  "default": "allow",
  "readOnly": false,
  "perMinute": 120,
  "unattendedIrreversible": []
}
```

| Field | Type | Meaning |
|---|---|---|
| `allow` | rules | If present, only these calls pass (plus anything the default allows; see below). |
| `deny` | rules | Always refused with `403 leash_denied`. Checked first. |
| `hold` | rules | Held for approval even though the irreversible map does not require it. |
| `default` | `allow`, `hold`, `deny` | What happens to calls that match no rule. With an `allow` list, `allow` means "refuse the rest". |
| `readOnly` | boolean | Only `GET` and `HEAD`. |
| `perMinute` | 1 to 600 | Rate limit for this token. Default 120. |
| `unattendedIrreversible` | rules | Irreversible calls that may run **without** approval. Only settable in a passkey ceremony. |

A **rule** is `{ "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "*", "path": "<glob>" }`. Paths are relative to
the provider's base (for Cloudflare, after `/client/v4`). Globs: `*` matches one path segment, `**` any depth, `{a,b}`
alternatives.

## Order of evaluation

1. `deny`
2. `readOnly`
3. The irreversible map (held, unless the call matches `unattendedIrreversible`)
4. `hold`
5. `allow` list
6. `default`

## Recipes

Read-only access to one GitHub org:

```json
{ "readOnly": true, "allow": [{ "path": "/repos/acme/**" }, { "path": "/orgs/acme/**" }] }
```

Let a release agent delete preview branches unattended, nothing else irreversible:

```json
{ "unattendedIrreversible": [{ "method": "DELETE", "path": "/repos/acme/web/git/refs/heads/preview-*" }] }
```

Hold every write to Stripe, not just the money-moving ones:

```json
{ "hold": [{ "method": "*", "path": "/v1/**" }], "allow": [{ "method": "GET", "path": "/v1/**" }], "default": "hold" }
```
