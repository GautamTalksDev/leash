# Deploy

LEASH is one Cloudflare Worker with a D1 database and static assets. About ten minutes.

```bash
cd server
npx -y wrangler@4 login
npx -y wrangler@4 d1 create leash                      # paste the database_id into wrangler.jsonc
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" | npx -y wrangler@4 secret put LEASH_KEK
node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))" | npx -y wrangler@4 secret put IP_SALT
npx -y wrangler@4 d1 migrations apply leash --remote
```

In `wrangler.jsonc`, uncomment the `routes` line with your domain and set `RP_ID` and `ORIGIN` to it (the passkey RP ID
must be the domain users see). Then:

```bash
npx -y wrangler@4 deploy
```

## After deploy

- Turn on hardware-key 2FA for the Cloudflare account. The master key lives in its Workers secrets.
- Create your account at `https://<domain>/app` with a passkey.
- `npx leashcli login --server https://<domain>`.

## Rotating the master key

Rotation re-wraps data keys; secrets themselves are not re-encrypted. Procedure: deploy with both `LEASH_KEK` (new) and
`LEASH_KEK_OLD`, run the re-wrap job, remove `LEASH_KEK_OLD`. (The re-wrap job is on the roadmap; until then, rotate by
re-adding credentials.)

## Publishing the CLI

```bash
cd cli && npm publish --access public      # package name leashcli; check availability first
```
