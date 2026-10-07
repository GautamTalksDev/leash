import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World, Authenticator, ORIGIN, RP_ID } from './helpers.js';
import { sqlDestructive, irreversibleRule } from '../src/providers.js';

const GH = 'ghp_' + 'A'.repeat(36);

async function setup(w, provider = 'github', secret = GH, policy) {
  const u = await w.user();
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, label: 'prod' } });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id, label: 'claude-code', policy } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return { u, cred: c.body, token: t.body.token };
}

async function approve(w, u, holdId) {
  const b = await w.req('POST', `/v1/holds/${holdId}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const cred = await u.auth.get(b.body.options);
  return w.req('POST', `/v1/holds/${holdId}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: cred } });
}

test('passkey sign-up, sign-in, and the session cookie is __Host-, HttpOnly, Secure, SameSite=Strict', async () => {
  const w = new World();
  const auth = new Authenticator(ORIGIN, RP_ID);
  const b = await w.req('POST', '/v1/auth/register/begin', { body: { name: 'Gautam' } });
  const f = await w.req('POST', '/v1/auth/register/finish', { body: { challengeId: b.body.challengeId, credential: await auth.create(b.body.options) } });
  const sc = f.headers.get('set-cookie');
  assert.match(sc, /^__Host-leash=/); assert.match(sc, /HttpOnly/); assert.match(sc, /Secure/); assert.match(sc, /SameSite=Strict/);
  const lb = await w.req('POST', '/v1/auth/login/begin', { body: {} });
  const lf = await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: lb.body.challengeId, credential: await auth.get(lb.body.options) } });
  assert.equal(lf.status, 200);
  // the challenge is single use
  const again = await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: lb.body.challengeId, credential: await auth.get(lb.body.options) } });
  assert.equal(again.body.error, 'challenge_expired');
});

test('phishing origin and missing user verification are rejected', async () => {
  const w = new World();
  const u = await w.user();
  const lb = await w.req('POST', '/v1/auth/login/begin', { body: {} });
  const evil = await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: lb.body.challengeId, credential: await u.auth.get(lb.body.options, { origin: 'https://leash-login.evil' }) } });
  assert.equal(evil.body.error, 'bad_origin');
  const lb2 = await w.req('POST', '/v1/auth/login/begin', { body: {} });
  const noUv = await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: lb2.body.challengeId, credential: await u.auth.get(lb2.body.options, { flags: 0x01 }) } });
  assert.equal(noUv.body.error, 'user_verification_required');
});

test('the agent never sees the real key: the proxy injects it upstream; reads pass straight through', async () => {
  const w = new World();
  const { token } = await setup(w);
  const r = await w.req('GET', '/p/github/repos/acme/app/issues?state=open', { bearer: token, origin: null, xleash: false });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-leash-decision'), 'allowed');
  assert.equal(r.headers.get('set-cookie'), null, 'upstream cookies are stripped');
  assert.equal(w.upstream[0].url, 'https://api.github.com/repos/acme/app/issues?state=open');
  assert.equal(w.upstream[0].headers.authorization, 'Bearer ' + GH);
  const dump = JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM credentials').all()) + JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM audit').all()) + JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM tokens').all());
  assert.ok(!dump.includes(GH), 'the real key is never stored in plaintext');
  assert.ok(!dump.includes(token), 'proxy tokens are stored only as hashes');
});

test('deleting a repo is held; a passkey approval lets the exact same request through once', async () => {
  const w = new World();
  const { u, token } = await setup(w);
  const del = () => w.req('DELETE', '/p/github/repos/acme/app', { bearer: token, origin: null, xleash: false });
  const h = await del();
  assert.equal(h.status, 428);
  assert.equal(h.body.error, 'held_for_approval');
  assert.match(h.body.message, /cannot be undone/);
  assert.equal(w.upstream.length, 0, 'nothing reached GitHub');
  assert.equal((await del()).body.hold_id, h.body.hold_id, 'retrying before approval reuses the same hold');
  const a = await approve(w, u, h.body.hold_id);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  const ok = await del();
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('x-leash-decision'), 'approved');
  assert.equal(w.upstream.length, 1);
  const third = await del();
  assert.equal(third.status, 428, 'an approval is good for one request only');
  assert.notEqual(third.body.hold_id, h.body.hold_id);
  // a different request is not covered by the approval
});

test('an approval only covers the request it was given for', async () => {
  const w = new World();
  const { u, token } = await setup(w);
  const h = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: token, origin: null, xleash: false });
  await approve(w, u, h.body.hold_id);
  const other = await w.req('DELETE', '/p/github/repos/acme/billing', { bearer: token, origin: null, xleash: false });
  assert.equal(other.status, 428);
  assert.equal(w.upstream.length, 0);
});

test('PocketOS replay: a Railway volumeDelete mutation is held, ordinary mutations pass', async () => {
  const w = new World();
  const { token } = await setup(w, 'railway', 'rw_' + 'x'.repeat(30));
  const gql = (q) => w.req('POST', '/p/railway/', { bearer: token, origin: null, xleash: false, body: { query: q } });
  const wipe = await gql('mutation { volumeDelete(volumeId: "vol_prod") }');
  assert.equal(wipe.status, 428);
  assert.match(wipe.body.rule, /^rw\./);
  const ok = await gql('mutation { serviceInstanceRedeploy(serviceId: "s", environmentId: "e") }');
  assert.equal(ok.status, 200);
  const q = await gql('query { me { email } }');
  assert.equal(q.status, 200);
  assert.equal(w.upstream.length, 2);
});

test('destructive SQL to Supabase is held; normal SQL is not', async () => {
  const w = new World();
  const { token } = await setup(w, 'supabase', 'sbp_' + 'a'.repeat(40));
  const sql = (q) => w.req('POST', '/p/supabase/v1/projects/abc/database/query', { bearer: token, origin: null, xleash: false, body: { query: q } });
  for (const bad of ['DROP TABLE users', 'select 1; truncate orders', 'DELETE FROM users', 'update users set admin = true', 'alter table users drop column email', 'ALTER TABLE t DISABLE ROW LEVEL SECURITY'])
    assert.equal((await sql(bad)).status, 428, bad);
  for (const good of ['select * from users where id = 1', 'delete from sessions where expires_at < now()', 'update users set name = $1 where id = $2', 'insert into logs values (1)'])
    assert.equal((await sql(good)).status, 200, good);
});

test('the irreversible map: force push, Stripe refunds and payouts, Cloudflare purge_everything', () => {
  assert.ok(irreversibleRule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x","force":true}'));
  assert.equal(irreversibleRule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x"}'), null);
  assert.ok(irreversibleRule('stripe', 'POST', '/v1/refunds', ''));
  assert.ok(irreversibleRule('stripe', 'POST', '/v1/payouts', ''));
  assert.equal(irreversibleRule('stripe', 'POST', '/v1/customers', ''), null);
  assert.ok(irreversibleRule('cloudflare', 'POST', '/zones/z1/purge_cache', '{"purge_everything":true}'));
  assert.equal(irreversibleRule('cloudflare', 'POST', '/zones/z1/purge_cache', '{"files":["https://a/b"]}'), null);
  assert.ok(sqlDestructive('/* hi */ DROP schema public cascade'));
  assert.ok(!sqlDestructive('select drop_count from stats'));
});

test('a CLI session can mint tokens but can never approve a hold or pre-approve irreversible operations', async () => {
  const w = new World();
  const { u, cred, token } = await setup(w);
  // device sign-in
  const d = await w.req('POST', '/v1/device/start', { body: {}, origin: null, xleash: false });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  const af = await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  assert.equal(af.status, 200, JSON.stringify(af.body));
  const p = await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, origin: null, xleash: false });
  const cli = p.body.access_token;
  assert.match(cli, /^lsc_/);
  assert.equal((await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, origin: null, xleash: false })).body.error, 'expired_token', 'device codes are single use');
  // mint: ok
  const t = await w.req('POST', '/v1/tokens', { bearer: cli, body: { credentialId: cred.id }, origin: null, xleash: false });
  assert.equal(t.status, 200);
  // pre-approval: refused
  const pre = await w.req('POST', '/v1/tokens', { bearer: cli, body: { credentialId: cred.id, policy: { unattendedIrreversible: [{ method: 'DELETE', path: '/**' }] } }, origin: null, xleash: false });
  assert.equal(pre.body.error, 'passkey_required');
  // approve: refused
  const h = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: token, origin: null, xleash: false });
  const ap = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { bearer: cli, body: {}, origin: null, xleash: false });
  assert.equal(ap.body.error, 'passkey_required');
  // but it can see holds
  assert.equal((await w.req('GET', '/v1/holds', { bearer: cli, origin: null, xleash: false })).body.holds.length, 1);
});

test('web writes need the same Origin and the x-leash header (CSRF); CORS preflight is refused', async () => {
  const w = new World();
  const u = await w.user();
  assert.equal((await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH }, xleash: false })).body.error, 'csrf');
  assert.equal((await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH }, origin: 'https://evil.example' })).body.error, 'csrf');
  assert.equal((await w.req('OPTIONS', '/v1/credentials')).status, 403);
});

test('policy: deny list, read-only tokens, allow lists, revoked tokens, wrong provider, traversal', async () => {
  const w = new World();
  const { u, cred } = await setup(w);
  const mk = async (policy) => (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred.id, policy } })).body;
  const ro = await mk({ readOnly: true });
  assert.equal((await w.req('POST', '/p/github/repos/a/b/issues', { bearer: ro.token, origin: null, xleash: false, body: { title: 'x' } })).body.error, 'leash_denied');
  const al = await mk({ allow: [{ method: 'GET', path: '/repos/acme/*' }] });
  assert.equal((await w.req('GET', '/p/github/repos/acme/app', { bearer: al.token, origin: null, xleash: false })).status, 200);
  assert.equal((await w.req('GET', '/p/github/repos/other/app', { bearer: al.token, origin: null, xleash: false })).body.error, 'leash_denied');
  assert.equal((await w.req('GET', '/p/cloudflare/zones', { bearer: al.token, origin: null, xleash: false })).body.error, 'wrong_provider');
  // URL parsing collapses dot segments before routing, so traversal lands on a path the allow list refuses
  assert.equal((await w.req('GET', '/p/github/repos/acme/../../user', { bearer: al.token, origin: null, xleash: false })).body.error, 'leash_denied');
  assert.equal((await w.req('GET', '/p/github/../cloudflare/zones', { bearer: al.token, origin: null, xleash: false })).body.error, 'wrong_provider');
  assert.equal((await w.req('GET', '/p/github/repos/acme%2f..%2fuser', { bearer: al.token, origin: null, xleash: false })).body.error, 'bad_path');
  await w.req('DELETE', `/v1/tokens/${al.id}`, { cookie: u.cookie });
  assert.equal((await w.req('GET', '/p/github/repos/acme/app', { bearer: al.token, origin: null, xleash: false })).body.error, 'token_invalid');
  assert.equal((await w.req('GET', '/p/github/x', { bearer: 'lsh_nope', origin: null, xleash: false })).body.error, 'leash_token_required');
});

test('another account cannot see or approve your holds (no IDOR)', async () => {
  const w = new World();
  const { token } = await setup(w);
  const h = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: token, origin: null, xleash: false });
  const eve = await w.user('Eve');
  assert.equal((await w.req('GET', '/v1/holds', { cookie: eve.cookie })).body.holds.length, 0);
  assert.equal((await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { cookie: eve.cookie, body: {} })).status, 404);
  assert.equal((await w.req('POST', `/v1/holds/${h.body.hold_id}/deny`, { cookie: eve.cookie, body: {} })).status, 404);
});

test('the audit log is hash-chained and detects tampering', async () => {
  const w = new World();
  const { u, token } = await setup(w);
  await w.req('DELETE', '/p/github/repos/acme/app', { bearer: token, origin: null, xleash: false });
  const v = await w.req('GET', '/v1/audit/verify', { cookie: u.cookie });
  assert.equal(v.body.ok, true);
  assert.ok(v.body.entries >= 4);
  w.env.DB.raw.prepare("UPDATE audit SET detail = '{}' WHERE action = 'hold'").run();
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, false);
});

test('keys that do not look like the provider are refused; vault rows cannot be swapped between accounts', async () => {
  const w = new World();
  const u = await w.user();
  assert.equal((await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'hunter22hunter22' } })).body.error, 'bad_secret');
  const { token } = await setup(w);
  // move the ciphertext to another account's row: AAD binding makes it undecryptable
  const eve = await w.user('Eve');
  const c = await w.req('POST', '/v1/credentials', { cookie: eve.cookie, body: { provider: 'github', secret: 'ghp_' + 'E'.repeat(36) } });
  const t = await w.req('POST', '/v1/tokens', { cookie: eve.cookie, body: { credentialId: c.body.id } });
  w.env.DB.raw.prepare('UPDATE credentials SET ct = (SELECT ct FROM credentials WHERE id != ? LIMIT 1), iv = (SELECT iv FROM credentials WHERE id != ? LIMIT 1) WHERE id = ?').run(c.body.id, c.body.id, c.body.id);
  const r = await w.req('GET', '/p/github/user', { bearer: t.body.token, origin: null, xleash: false });
  assert.equal(r.status, 500);
  assert.equal(r.body.error, 'vault_error');
  assert.ok(token);
});
