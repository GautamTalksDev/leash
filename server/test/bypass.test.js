// Regressions for the 9 Oct 2026 launch audit (AUDIT.md, LEASH section) and the review that followed it.
// Each test failed on map 2026-10-07.3 and passes on 2026-10-09.1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import * as M from '../src/providers.js';
import { canonPath } from '../src/broker.js';

const { irreversibleRule, globToRe } = M;
const jsonView = (t) => M.jsonView(t); // namespace access, so this file still loads (and fails per test) on the old map

const P = { origin: null, xleash: false };
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const rule = (prov, m, p, b = '', q = '') => irreversibleRule(prov, m, p, b, q)?.id;

async function setup(w, provider, secret, policy) {
  const u = await w.user();
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider, secret, label: 'prod' } });
  assert.equal(c.status, 200, JSON.stringify(c.body));
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id, policy } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return { u, cred: c.body, token: t.body.token };
}

test('L-H1: Stripe holds a repeated confirm or cancel_at (body, query string or both) and reads every copy', async () => {
  const pi = (b, q) => rule('stripe', 'POST', '/v1/payment_intents', b, q);
  for (const [b, q] of [
    ['amount=100&currency=usd&confirm=false&confirm=true'], // the audit probe: Rack keeps the last copy
    ['amount=100&confirm=true&confirm=false'],
    ['amount=100&confirm=false&confirm=false'], // repeated at all is held: parsers disagree on which copy wins
    ['amount=100&confirm=false', '?confirm=false'], // in both the body and the query string
    ['amount=100', '?confirm=false&confirm=true'],
    ['amount=100;confirm=true'], // ";" splits for Rack 2
    ['amount=100', '?x=1;confirm=true'],
    ['amount=100&confirm=false;confirm=true'],
    ['amount=100&confirm[]=true'], // odd forms a server may still read as confirm
    ['amount=100&[confirm]=false'],
    ['amount=100& confirm=false'],
    ['amount=100&Confirm=false'],
    ['amount=100&conf%69rm=tr%75e'],
    ['{"confirm":false,"confirm":true}'],
    ['{"\\u0063onfirm":true}'],
    ['[{"confirm":true}]'],
    ['{"amount":100,'], // looks like JSON, is not
    ['--x\r\nContent-Disposition: form-data; name="confirm"\r\n\r\ntrue\r\n--x--'], // multipart
  ]) assert.equal(pi(b, q), 'st.pi-confirm', `${b} ${q || ''}`);
  for (const ok of ['amount=100&currency=usd', 'amount=100&confirm=false', 'amount=100&confirmation_method=manual', 'amount=100&metadata[confirm]=true', '{"amount":100,"confirm":false}'])
    assert.equal(pi(ok), undefined, ok);
  const sub = (b, q) => rule('stripe', 'POST', '/v1/subscriptions/sub_1', b, q);
  assert.equal(sub('cancel_at_period_end=false&cancel_at_period_end=true'), 'st.cancel-at');
  assert.equal(sub('metadata[x]=1', '?cancel_at=1790000000'), 'st.cancel-at');
  assert.equal(sub('cancel_at=&cancel_at=1790000000'), 'st.cancel-at');
  assert.equal(sub('cancel_at_period_end=false&metadata[cancel_at]=1'), undefined);
  // end to end: the duplicated form body is held and nothing reaches Stripe
  const w = new World();
  const { token } = await setup(w, 'stripe', 'sk_test_' + 'x'.repeat(24));
  const r = await w.req('POST', '/p/stripe/v1/payment_intents', { bearer: token, ...P, headers: FORM, raw: 'amount=100&currency=usd&confirm=false&confirm=true' });
  assert.equal(r.status, 428);
  assert.equal(r.body.rule, 'st.pi-confirm');
  assert.equal(w.upstream.length, 0);
});

test('L-M1: Cloudflare purge reads parsed JSON: escaped keys, spacing, hosts and prefixes are held; files and tags pass', () => {
  const purge = (b, q) => rule('cloudflare', 'POST', '/zones/z/purge_cache', b, q);
  for (const b of ['{"purge\\u005feverything":true}', '{"\\u0070urge_everything":true}', '{ "purge_everything" :\n true }', '{"PURGE_EVERYTHING":true}',
    '{"purge_everything":false}', '{"hosts":["www.example.com"]}', '{"prefixes":["www.example.com/"]}', '{"files":["https://a/b"],"files":[]}',
    '{"files":["https://a/b"],"other":1}', 'not json', '[]', ''])
    assert.equal(purge(b), 'cf.purge', b);
  assert.equal(purge('{"files":["https://a/b"]}', '?purge_everything=true'), 'cf.purge', 'query string');
  assert.equal(purge('{"files":["https://a/b"]}'), undefined);
  assert.equal(purge('{"tags":["blog"]}'), undefined);
  assert.equal(purge('{"files":[{"url":"https://a/b","headers":{"Origin":"https://a"}}]}'), undefined);
});

test('R4-1: repeated, escaped or case-variant JSON keys are unreadable, so SQL, GraphQL and GitHub rules hold them', () => {
  // first-copy-wins parsers would run the mutation; JSON.parse shows LEASH the harmless copy
  assert.equal(rule('github', 'POST', '/graphql', '{"\\u0071uery":"mutation{deleteRepository(input:{}){clientMutationId}}","query":"{viewer{login}}"}'), 'gh.graphql');
  assert.equal(rule('railway', 'POST', '/', '{"query":"{me{email}}","QUERY":"mutation{volumeDelete(volumeId:\\"v\\")}"}'), 'rw.mutation');
  assert.equal(rule('supabase', 'POST', '/v1/projects/p/database/query', '{"\\u0071uery":"drop table x","query":"select 1"}'), 'sb.sql');
  assert.equal(rule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x","Force":true}'), 'gh.force-push');
  // the strict view itself
  assert.equal(jsonView('{"a":1,"a":2}'), undefined);
  assert.equal(jsonView(String.fromCharCode(0xfeff) + '{"a":1}'), undefined, 'byte order mark');
  assert.deepEqual(jsonView('{"s":"a\\"b\\n","n":[-2.5e3,0]}'), { s: 'a"b\n', n: [-2500, 0] });
  assert.equal(jsonView('{"a":1,"\\u0061":2}'), undefined);
  assert.equal(jsonView('{"sql":1,"SQL":2}'), undefined);
  assert.equal(jsonView('{"sql":1,"\u017fql":2}'), undefined, 'long s folds to s (Go encoding/json)');
  assert.equal(jsonView('{"k":1,"\u212a":2}'), undefined, 'Kelvin sign folds to k');
  assert.equal(jsonView('['.repeat(70) + ']'.repeat(70)), undefined, 'too deep');
  assert.equal(jsonView('{"a":1} x'), undefined);
  assert.deepEqual(jsonView('{"Query":"x","n":[1,true,null]}'), { query: 'x', n: [1, true, null] });
  assert.ok(Object.hasOwn(jsonView('{"__proto__":{"force":true}}'), '__proto__'), '__proto__ stays a plain key');
  assert.equal(rule('cloudflare', 'POST', '/accounts/a/d1/database/d/query', '{"\u017fql":"drop table x","sql":"select 1"}'), 'cf.d1-sql');
  assert.equal(rule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x","force":false,"force":true}'), 'gh.force-push');
  assert.equal(rule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x","Force":true}'), 'gh.force-push');
  assert.equal(rule('github', 'PATCH', '/repos/a/b', '{"Private":false}'), 'gh.visibility');
  // ordinary bodies still pass
  assert.equal(rule('github', 'POST', '/graphql', '{"query":"{viewer{login}}","variables":{"a":1}}'), undefined);
  assert.equal(rule('cloudflare', 'POST', '/accounts/a/d1/database/d/query', '{"sql":"select * from t where id = ?","params":[1]}'), undefined);
  assert.equal(rule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x","force":false}'), undefined);
});

test('R4-2: parameters outside the JSON body are read: GraphQL in the query string, persisted queries, force and private in the URL', () => {
  const gh = (b, q) => rule('github', 'POST', '/graphql', b, q);
  const view = '{"query":"{viewer{login}}"}';
  assert.equal(gh(view, '?query=' + encodeURIComponent('mutation{deleteRepository(input:{repositoryId:"R"}){clientMutationId}}')), 'gh.graphql', 'Rails merges the query string over the body');
  assert.equal(gh(view, '?operationName=x'), 'gh.graphql');
  assert.equal(gh('{"query":"{viewer{login}}","documentId":"abc"}'), 'gh.graphql');
  assert.equal(gh('{"query":"{viewer{login}}","variables":{"a":"&query=mutation{deleteRepository}&"}}'), 'gh.graphql', 'a form reading of the body');
  assert.equal(rule('railway', 'POST', '/', '{"query":"{me{email}}","extensions":{"persistedQuery":{"version":1,"sha256Hash":"x"}}}'), 'rw.mutation');
  assert.equal(gh('{"query":"{viewer{login}}","extensions":{}}'), undefined);
  assert.equal(gh(view), undefined);
  // Railway over GET: an escape decodeURIComponent rejects no longer hides the mutation
  assert.equal(rule('railway', 'GET', '/', null, '?query=%6Dutation%7BvolumeDelete%7D&x=%E0%A4%A'), 'rw.get-mutation');
  assert.equal(rule('railway', 'GET', '/', null, '?query=' + encodeURIComponent('{ me { email } }')), undefined);
  // GitHub REST: the same names in the query string or in a form reading of the body
  assert.equal(rule('github', 'PATCH', '/repos/a/b/git/refs/heads/main', '{"sha":"x"}', '?force=true'), 'gh.force-push');
  assert.equal(rule('github', 'PATCH', '/repos/a/b', '{}', '?private=false'), 'gh.visibility');
  assert.equal(rule('github', 'PATCH', '/repos/a/b', '{"description":"&private=false&"}'), 'gh.visibility');
  assert.equal(rule('github', 'PATCH', '/repos/a/b', '{"description":"x"}'), undefined);
  assert.equal(rule('supabase', 'POST', '/v1/projects/p/database/query', '{"query":"select 1"}', '?query=drop%20table%20x'), 'sb.sql');
});

test('R4-3: method overrides are held on every provider and cannot be pre-approved; override headers never reach upstream', async () => {
  for (const [b, q] of [['_method=DELETE'], ['%5Fmethod=DELETE'], ['title=x', '?_method=DELETE'], ['{"_method":"DELETE"}'], ['{"_METHOD":"DELETE"}'],
    ['--x\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--x--'], ['a=1;_method=DELETE'], ['_method[]=DELETE']])
    for (const prov of ['github', 'cloudflare', 'railway', 'stripe', 'supabase']) assert.equal(rule(prov, 'POST', '/v1/x', b, q), 'any.method-override', `${prov} ${b} ${q || ''}`);
  assert.equal(rule('github', 'POST', '/repos/a/b/issues', '{"title":"_method","body":"name=_method"}'), undefined, 'values are not names');
  assert.equal(rule('github', 'GET', '/search/code', null, '?q=_method'), undefined);

  const w = new World();
  const u = await w.user();
  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'A'.repeat(36) } });
  const b = (await w.req('POST', '/v1/tokens/passkey/begin', { cookie: u.cookie, body: {} })).body;
  const t = await w.req('POST', '/v1/tokens/passkey/finish', { cookie: u.cookie, body: { challengeId: b.challengeId, credential: await u.auth.get(b.options), credentialId: c.body.id, policy: { unattendedIrreversible: [{ method: 'POST', path: '/repos/acme/**' }] } } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  const go = (path, raw, headers = FORM) => w.req('POST', '/p/github' + path, { bearer: t.body.token, ...P, headers, raw });
  assert.equal((await go('/repos/acme/app/transfer', '{"new_owner":"x"}', {})).status, 200, 'the pre-approval itself works');
  const h = await go('/repos/acme/app', '_method=DELETE');
  assert.equal(h.status, 428, 'a POST that says it is a DELETE is held despite the POST pre-approval');
  assert.equal(h.body.rule, 'any.method-override');
  await w.req('GET', '/p/github/repos/acme/app', { bearer: t.body.token, ...P, headers: { 'x-http-method-override': 'DELETE', 'x-http-method': 'DELETE', 'x-method-override': 'DELETE' } });
  const sent = w.upstream.at(-1);
  assert.equal(sent.method, 'GET');
  for (const k of Object.keys(sent.headers)) assert.ok(!/method/i.test(k), `${k} must not be forwarded`);
});

test('R4-4: path variants (doubled trailing slash, ";" parameters, case, a format suffix) cannot dodge the map; HEAD trips GET rules', async () => {
  assert.throws(() => canonPath('/v1/refunds//'), /bad_path/);
  assert.throws(() => canonPath('/v1/refunds;x=1'), /bad_path/);
  assert.throws(() => canonPath('/v1/refunds%00'), /bad_path/);
  assert.equal(canonPath('/v1/refunds/'), '/v1/refunds');
  assert.equal(rule('stripe', 'POST', '/v1/Refunds'), 'st.money');
  assert.equal(rule('stripe', 'POST', '/V1/PAYOUTS'), 'st.money');
  assert.equal(rule('stripe', 'POST', '/v1/refunds.json'), 'st.money');
  assert.equal(rule('github', 'PUT', '/repos/a/b/branches/main/protection.json'), 'gh.protection');
  assert.equal(rule('cloudflare', 'POST', '/zones/z/PURGE_CACHE', '{"purge_everything":true}'), 'cf.purge');
  assert.equal(rule('supabase', 'POST', '/v1/projects/p/database/Query', '{"query":"drop table x"}'), 'sb.sql');
  assert.equal(rule('github', 'HEAD', '/graphql'), 'gh.graphql-get');
  assert.equal(rule('railway', 'HEAD', '/', null, '?query=mutation%7BvolumeDelete%7D'), 'rw.get-mutation');
  for (const m of ['PUT', 'PATCH', 'DELETE']) assert.equal(rule('railway', m, '/', '{"query":"mutation{volumeDelete(volumeId:\\"v\\")}"}'), 'rw.method', m);
  assert.equal(rule('stripe', 'POST', '/v1/customers.json'), undefined);

  const w = new World();
  const { token } = await setup(w, 'github', 'ghp_' + 'A'.repeat(36), { deny: [{ method: 'GET', path: '/repos/acme/secret/**' }] });
  assert.equal((await w.req('HEAD', '/p/github/repos/acme/secret/contents/key.pem', { bearer: token, ...P })).status, 403, 'a GET deny rule covers HEAD');
  const st = await setup(w, 'stripe', 'sk_test_' + 'y'.repeat(24));
  assert.equal((await w.req('POST', '/p/stripe/v1/refunds//', { bearer: st.token, ...P, headers: FORM, raw: 'charge=ch_1' })).body.error, 'bad_path');
  assert.equal(w.upstream.length, 0);
});

test('R4-5: a body declared in a charset other than UTF-8 is refused', async () => {
  const w = new World();
  const { token } = await setup(w, 'stripe', 'sk_test_' + 'z'.repeat(24));
  const send = (ct) => w.req('POST', '/p/stripe/v1/customers', { bearer: token, ...P, headers: { 'content-type': ct }, raw: 'email=a%40b.c' });
  assert.equal((await send('application/x-www-form-urlencoded; charset=utf-16')).body.error, 'bad_body');
  assert.equal((await send('application/x-www-form-urlencoded; charset="ISO-8859-1"')).body.error, 'bad_body');
  assert.equal((await send('application/x-www-form-urlencoded; charset=UTF-8')).status, 200);
  assert.equal((await send('application/x-www-form-urlencoded')).status, 200);
  assert.equal(w.upstream.length, 2);
});

test('R4-6: globs with * inside braces compile (the R2 rule used to throw on every Cloudflare PUT); bad policy globs are refused', async () => {
  assert.equal(rule('cloudflare', 'PUT', '/accounts/a/r2/buckets/b/lifecycle'), 'cf.r2-config');
  assert.equal(rule('cloudflare', 'PUT', '/accounts/a/r2/buckets/b/domains/custom/x.example.com'), 'cf.r2-config');
  assert.equal(rule('cloudflare', 'PUT', '/accounts/a/storage/kv/namespaces/n/values/k', 'v'), undefined);
  assert.ok(globToRe('/a/{b/**,c}').test('/a/b/x/y'));
  assert.throws(() => globToRe('/a/{b'));
  assert.throws(() => globToRe('/a/{b,{c}}'));
  const w = new World();
  const { u, cred, token } = await setup(w, 'cloudflare', 'cf_' + 'k'.repeat(37));
  const kv = await w.req('PUT', '/p/cloudflare/accounts/a/storage/kv/namespaces/n/values/k', { bearer: token, ...P, raw: 'value' });
  assert.equal(kv.status, 200, 'a KV write goes through instead of failing with 500');
  for (const path of ['/{a', '/a/{b,{c}}', '/a}']) {
    const r = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred.id, policy: { deny: [{ path }] } } });
    assert.equal(r.body.error, 'bad_policy', path);
  }
});

test('R4-7: SQL that runs through other doors is held: Supabase migrations, D1 import ingest, D1 time travel restore', () => {
  assert.equal(rule('supabase', 'POST', '/v1/projects/p/database/migrations', '{"query":"drop table users","name":"x"}'), 'sb.migration');
  assert.equal(rule('supabase', 'PUT', '/v1/projects/p/database/migrations', '{"query":"drop table users"}'), 'sb.migration');
  assert.equal(rule('supabase', 'GET', '/v1/projects/p/database/migrations'), undefined);
  const imp = (b) => rule('cloudflare', 'POST', '/accounts/a/d1/database/d/import', b);
  assert.equal(imp('{"action":"ingest","etag":"e","filename":"f"}'), 'cf.d1-import');
  assert.equal(imp('{"action":"init","action":"ingest"}'), 'cf.d1-import');
  assert.equal(imp('not json'), 'cf.d1-import');
  assert.equal(imp('{"action":"init","etag":"e"}'), undefined);
  assert.equal(imp('{"action":"poll","current_bookmark":"b"}'), undefined);
  assert.equal(rule('cloudflare', 'POST', '/accounts/a/d1/database/d/time_travel/restore', '', '?bookmark=b'), 'cf.d1-restore');
});
