// Regressions for the 7 Oct 2026 hardening pass. Each test failed on map 2026-10-07.1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { sqlDestructive, irreversibleRule } from '../src/providers.js';

const GH = 'ghp_' + 'A'.repeat(36);
const P = { origin: null, xleash: false };

async function setup(w, provider = 'github', secret = GH, policy) {
  const u = await w.user();
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, label: 'prod' } });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id, policy } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return { u, cred: c.body, token: t.body.token };
}

test('C1: SQL bypasses through strings, comments, dollar quotes and functions are held', () => {
  for (const bad of [
    "SELECT '--'; DROP TABLE users",
    "select '/*'; drop table users; -- */",
    'select 1 /* ; */ ; drop table users',
    "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$",
    'CREATE FUNCTION f() RETURNS void AS $f$ DROP TABLE users $f$ LANGUAGE sql',
    "select E'\\''; drop table users; --'",
    'with x as (delete from users returning *) select * from x',
    'explain analyze delete from users',
    'select * into backup from users',
    'select pg_terminate_backend(42)',
    'call wipe()',
    "copy users to program 'curl evil'",
    'vacuum',
    'select 1; select 2',
    "select 'unterminated",
    '/* unterminated',
    '',
  ]) assert.ok(sqlDestructive(bad), bad);
  for (const ok of ['select * from users where note = \'drop table\'', 'select "delete" from t', 'with a as (select 1) select * from a', 'EXPLAIN SELECT 1', 'show all', 'select $1::int'])
    assert.ok(!sqlDestructive(ok), ok);
});

test('C2: D1 bodies are checked on every SQL field; sql plus query is held', () => {
  const d1 = (b) => irreversibleRule('cloudflare', 'POST', '/accounts/a/d1/database/d/query', JSON.stringify(b));
  assert.ok(d1({ query: 'select 1', sql: 'drop table users' }), 'D1 runs sql, not query');
  assert.ok(d1({ sql: 'drop table users' }));
  assert.ok(d1([{ sql: 'select 1' }, { sql: 'drop table users' }]), 'batch arrays');
  assert.ok(d1({ batch: [{ sql: 'select 1' }, { sql: 'delete from users' }] }));
  assert.ok(d1({ sql: ['drop table users'] }), 'non-string sql');
  assert.ok(irreversibleRule('cloudflare', 'POST', '/accounts/a/d1/database/d/raw', 'not json'), 'unreadable');
  assert.equal(d1({ sql: 'select * from users', params: [] }), null);
});

test('C3: empty segments are refused, trailing slashes and case cannot dodge a rule, upstream gets the checked path', async () => {
  const w = new World();
  const { token } = await setup(w, 'github', GH, { deny: [{ path: '/repos/acme/secret/**' }, { path: '/repos/acme/secret' }], hold: [{ method: 'POST', path: '/repos/acme/app/releases/' }] });
  const go = (m, p, body) => w.req(m, '/p/github' + p, { bearer: token, ...P, body });
  assert.equal((await go('GET', '/repos//acme/secret')).body.error, 'bad_path');
  assert.equal((await go('GET', '/repos/acme/secret/')).body.error, 'leash_denied', 'trailing slash');
  assert.equal((await go('GET', '/repos/ACME/Secret')).body.error, 'leash_denied', 'GitHub owner and repo are case-insensitive');
  assert.equal((await go('POST', '/repos/acme/app/releases', { tag_name: 'v1' })).status, 428, 'rule written with a trailing slash still matches');
  const ok = await go('GET', '/repos/Acme/App/');
  assert.equal(ok.status, 200);
  assert.equal(w.upstream.at(-1).url, 'https://api.github.com/repos/Acme/App', 'upstream gets the canonical path, original case');
  assert.equal(irreversibleRule('github', 'PATCH', '/REPOS/a/b', '{"private":true}')?.id, 'gh.visibility');
});

test('C4: GitHub body rules read JSON values, so unicode escapes do not hide force or visibility', () => {
  const ref = (b) => irreversibleRule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', b);
  const repo = (b) => irreversibleRule('github', 'PATCH', '/repos/a/b', b);
  assert.ok(ref('{"sha":"x","\\u0066orce":true}'));
  assert.ok(ref('{"sha":"x","force" :\ntrue}'));
  assert.ok(ref('not json'), 'unreadable bodies are held');
  assert.equal(ref('{"sha":"x","force":false}'), null);
  assert.ok(repo('{"\\u0076isibility":"public"}'));
  assert.ok(repo('{"\\u0070rivate":false}'));
  assert.ok(repo('{"archived":true}'));
  assert.ok(repo('['), 'unreadable');
  assert.equal(repo('{"description":"x","archived":false}'), null);
});

test('C5: Railway mutations hidden by commas, comments, aliases, batches or GET are held; redeploy still passes', async () => {
  const w = new World();
  const { token } = await setup(w, 'railway', 'rw_' + 'x'.repeat(30));
  const post = (body) => w.req('POST', '/p/railway/', { bearer: token, ...P, raw: JSON.stringify(body), body: {} });
  for (const q of [
    'mutation { volumeDelete,(volumeId: "v") }',
    'mutation { volumeDelete # hi\n (volumeId: "v") }',
    'mutation { ok: serviceInstanceRedeploy(serviceId: "s", environmentId: "e") gone: volumeDelete(volumeId: "v") }',
    'mutation { variableUpsert(input: {}) }',
    'mutation { ...F } fragment F on Mutation { volumeDelete(volumeId: "v") }',
    'mutation { volumeDelete(volumeId: "v"',
  ]) assert.equal((await post({ query: q })).status, 428, q);
  assert.equal((await post([{ query: 'mutation { volumeDelete(volumeId: "v") }' }])).status, 428, 'batched array body');
  assert.equal((await post({ extensions: { persistedQuery: { sha256Hash: 'x' } } })).status, 428, 'persisted query');
  const get = await w.req('GET', '/p/railway/?query=' + encodeURIComponent('mutation { volumeDelete(volumeId: "v") }'), { bearer: token, ...P });
  assert.equal(get.status, 428, 'mutation over GET');
  assert.equal((await post({ query: 'mutation Redeploy($s: String!) { serviceInstanceRedeploy(serviceId: $s, environmentId: "e") }' })).status, 200);
  assert.equal((await post({ query: 'query { me { email } }' })).status, 200);
  assert.equal((await w.req('GET', '/p/railway/?query=' + encodeURIComponent('{ me { email } }'), { bearer: token, ...P })).status, 200);
});

test('C6: Stripe money movers that were missing from the map are held', () => {
  const st = (p, b = '', q = '') => irreversibleRule('stripe', 'POST', p, b, q)?.id;
  assert.equal(st('/v1/payment_intents', 'amount=100&currency=usd&confirm=true'), 'st.pi-confirm');
  assert.equal(st('/v1/payment_intents', 'amount=100', '?confirm=true'), 'st.pi-confirm', 'query string params count');
  assert.equal(st('/v1/payment_intents', 'amount=100&currency=usd'), undefined);
  assert.equal(st('/v1/payment_intents', 'confirm=false'), undefined);
  assert.equal(st('/v1/payment_intents/pi_1/confirm'), 'st.money2');
  assert.equal(st('/v1/charges/ch_1/refunds'), 'st.refund');
  assert.equal(st('/v1/charges/ch_1/refund'), 'st.refund');
  assert.equal(st('/v1/application_fees/fee_1/refunds'), 'st.refund');
  assert.equal(st('/v1/invoices/in_1/pay'), 'st.invoice');
  assert.equal(st('/v1/credit_notes', 'invoice=in_1'), 'st.credit-note');
  assert.equal(st('/v1/subscriptions/sub_1', 'cancel_at_period_end=true'), 'st.cancel-at');
  assert.equal(st('/v1/subscriptions/sub_1', 'cancel_at=1790000000'), 'st.cancel-at');
  assert.equal(st('/v1/subscriptions/sub_1', 'metadata[x]=1'), undefined);
});

test('C7: a hold carries a capped preview of what it would do; the audit log keeps only its hash', async () => {
  const w = new World();
  const { u, token } = await setup(w, 'supabase', 'sbp_' + 'a'.repeat(40));
  const h = await w.req('POST', '/p/supabase/v1/projects/abc/database/query?x=1', { bearer: token, ...P, body: { query: 'DROP TABLE users' } });
  assert.equal(h.status, 428);
  const [hold] = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds;
  assert.match(hold.preview, /^SQL: 1 statement: DROP/, 'parsed summary first');
  assert.match(hold.preview, /\?x=1/);
  assert.match(hold.preview, /DROP TABLE users/);
  const a = (await w.req('GET', '/v1/audit', { cookie: u.cookie })).body.entries.find((e) => e.action === 'hold');
  assert.equal(a.detail.preview, undefined, 'request content never enters the permanent log');
  assert.match(a.detail.preview_sha256, /^[0-9a-f]{64}$/);
  await w.req('POST', '/p/supabase/v1/projects/abc/database/query', { bearer: token, ...P, body: { query: 'DROP TABLE t; -- ' + 'x'.repeat(5000) } });
  const big = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.find((x) => x.id !== hold.id);
  assert.ok(big.preview.length <= 2048);
  assert.match(big.preview, /\[truncated\]$/);
});

test('P2: a CLI session cannot delete a vaulted key', async () => {
  const w = new World();
  const { u, cred } = await setup(w);
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...P });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  const cli = (await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...P })).body.access_token;
  assert.equal((await w.req('DELETE', `/v1/credentials/${cred.id}`, { bearer: cli, ...P })).body.error, 'passkey_required');
  assert.equal((await w.req('DELETE', `/v1/credentials/${cred.id}`, { cookie: u.cookie })).status, 200);
});

test('P4: account deletion needs a passkey ceremony bound to this account', async () => {
  const w = new World();
  const u = await w.user();
  const eve = await w.user('Eve');
  const b = (await w.req('POST', '/v1/me/delete/begin', { cookie: eve.cookie, body: {} })).body;
  // Eve's challenge cannot be finished from Gautam's session
  const x = await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: b.challengeId, credential: await u.auth.get(b.options) } });
  assert.equal(x.body.error, 'forbidden');
  // a mint challenge cannot be reused for deletion
  const m = (await w.req('POST', '/v1/tokens/passkey/begin', { cookie: u.cookie, body: {} })).body;
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: m.challengeId, credential: await u.auth.get(m.options) } })).body.error, 'challenge_expired');
  assert.equal(w.env.DB.raw.prepare('SELECT count(*) n FROM accounts').get().n, 2);
});

test('C1b: SELECT may only call known pure functions', async () => {
  const { sqlReadOnly } = await import('../src/providers.js');
  assert.equal(sqlReadOnly('select count(*), lower(name) from users where id in (1,2)'), true);
  assert.equal(sqlReadOnly('select my_cleanup()'), false);
  assert.equal(sqlReadOnly('select public.wipe_all(1)'), false);
  assert.equal(sqlReadOnly('select "pg_terminate_backend"(1)'), false);
  assert.equal(sqlReadOnly('select http_post(1)'), false);
});

// ---- second review (7 Oct 2026)
test('R2-1: GitHub GraphQL mutations are held; plain queries pass', () => {
  const g = (q) => irreversibleRule('github', 'POST', '/graphql', JSON.stringify({ query: q }))?.id;
  assert.equal(g('mutation { deleteRepository(input:{repositoryId:"R_x"}){clientMutationId} }'), 'gh.graphql');
  assert.equal(g('mutation { transferRepository(input:{}){clientMutationId} }'), 'gh.graphql');
  assert.equal(g('query { viewer { login } }'), undefined);
  assert.equal(g('{ viewer { login } }'), undefined);
  assert.equal(irreversibleRule('github', 'POST', '/graphql', '[{"query":"{viewer{login}}"}]')?.id, 'gh.graphql', 'batches are held');
  assert.equal(irreversibleRule('github', 'GET', '/graphql', '')?.id, 'gh.graphql-get');
});
test('R2-2: Cloudflare Worker uploads and DNS overwrites are held', () => {
  assert.equal(irreversibleRule('cloudflare', 'PUT', '/accounts/a/workers/scripts/prod', '')?.id, 'cf.worker-put');
  assert.equal(irreversibleRule('cloudflare', 'PUT', '/zones/z/dns_records/r', '{"content":"6.6.6.6"}')?.id, 'cf.dns-write');
  assert.equal(irreversibleRule('cloudflare', 'PATCH', '/zones/z/dns_records/r', '{"content":"6.6.6.6"}')?.id, 'cf.dns-write');
  assert.equal(irreversibleRule('cloudflare', 'GET', '/zones/z/dns_records', ''), null);
});
test('R2-3: Supabase password reset and config changes are held', () => {
  assert.equal(irreversibleRule('supabase', 'POST', '/v1/projects/p/database/password', '{}')?.id, 'sb.db-password');
  assert.equal(irreversibleRule('supabase', 'PATCH', '/v1/projects/p/config/database/postgres', '{}')?.id, 'sb.config');
});
test('R2-4: padding cannot hide the dangerous part of a held request from the approver', async () => {
  const { preview } = await import('../src/broker.js');
  const q = 'mutation {\n #' + 'x'.repeat(2100) + '\n serviceInstanceRedeploy(serviceId:"s")\n volumeDelete(volumeId:"v")\n }';
  const pv = preview('', JSON.stringify({ query: q }));
  assert.ok(pv.length <= 2048 + 200);
  assert.match(pv.split('\n')[0], /volumeDelete/, 'the parsed summary comes first');
  assert.match(pv, /only the first part is shown/);
  const sql = preview('', JSON.stringify({ query: 'select 1 /*' + 'x'.repeat(3000) + '*/; drop table users' }));
  assert.match(sql.split('\n')[0], /SQL: 2 statements: SELECT; DROP \[DROP\]/);
  const bidi = preview('', JSON.stringify({ query: 'select 1 ‮ drop' }));
  assert.match(bidi, /<U\+202E>/);
  assert.ok(!bidi.includes('‮'));
});
test('R2-5: percent-encoded letters are decoded before matching', async () => {
  const { canonPath } = await import('../src/broker.js');
  assert.equal(canonPath('/v1/%72efunds'), '/v1/refunds');
  assert.equal(irreversibleRule('stripe', 'POST', canonPath('/v1/%72efunds'), '')?.id, 'st.money');
  assert.equal(canonPath('/a/b%20c'), '/a/b%20c');
});
