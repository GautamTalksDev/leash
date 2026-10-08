import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { checkEndpoint } from '../src/push.js';

const GH = 'ghp_' + 'A'.repeat(36);
const FCM = 'https://fcm.googleapis.com/fcm/send/abc123';
const b64d = (s) => Uint8Array.from(Buffer.from(s, 'base64url'));

async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.pushStatus = 201;
  w.env.__pushFetch = async (url, init) => { w.pushes.push({ url, init }); return new Response(null, { status: w.pushStatus }); };
  return kp.publicKey;
}

test('push endpoints must be real push services (no SSRF)', () => {
  assert.equal(checkEndpoint(FCM), FCM);
  assert.ok(checkEndpoint('https://web.push.apple.com/QGx'));
  for (const bad of ['http://fcm.googleapis.com/x', 'https://evil.com/x', 'https://fcm.googleapis.com.evil.com/x', 'https://169.254.169.254/latest', 'https://fcm.googleapis.com:8443/x', 'https://u:p@fcm.googleapis.com/x', 'notaurl', 42]) {
    assert.throws(() => checkEndpoint(bad), /bad_endpoint|Not a known/);
  }
});

test('a held request wakes the owner devices with an EMPTY, VAPID-signed push; dead devices are dropped', async () => {
  const w = new World();
  const pub = await withVapid(w);
  const u = await w.user();
  const key = await w.req('GET', '/v1/push/key', { cookie: u.cookie });
  assert.equal(key.body.enabled, true);
  assert.equal(b64d(key.body.key).length, 65);
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: FCM } })).status, 200);
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://evil.com/x' } })).body.error, 'bad_endpoint');

  const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } });
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id, label: 'bot' } });
  const r = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: t.body.token, origin: null, xleash: false });
  assert.equal(r.body.error, 'held_for_approval');
  assert.equal(w.pushes.length, 1);
  const p = w.pushes[0];
  assert.equal(p.url, FCM);
  assert.equal(p.init.body, '', 'the push carries no payload');
  // VAPID JWT verifies against the public key the browser was given, audience = push service origin
  const m = p.init.headers.authorization.match(/^vapid t=([^.]+)\.([^.]+)\.([^,]+), k=(.+)$/);
  assert.ok(m);
  assert.equal(m[4], key.body.key);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, b64d(m[3]), new TextEncoder().encode(`${m[1]}.${m[2]}`));
  assert.ok(ok, 'signature valid');
  const claims = JSON.parse(Buffer.from(m[2], 'base64url'));
  assert.equal(claims.aud, 'https://fcm.googleapis.com');
  assert.ok(claims.exp > Date.now() / 1000 && claims.exp <= Date.now() / 1000 + 24 * 3600);

  // the same held request retried does not re-notify; an expired subscription is removed
  await w.req('DELETE', '/p/github/repos/acme/app', { bearer: t.body.token, origin: null, xleash: false });
  assert.equal(w.pushes.length, 1);
  w.pushStatus = 410;
  const tst = await w.req('POST', '/v1/push/test', { cookie: u.cookie, body: {} });
  assert.equal(tst.body.sent, 0);
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) AS n FROM push_subs').get().n, 0);
});

test('push needs a web/CLI session with CSRF header, is per account, capped, and off without a key', async () => {
  const w = new World();
  const anon = await w.req('POST', '/v1/push/subscribe', { body: { endpoint: FCM } });
  assert.equal(anon.status, 401);
  assert.equal((await w.req('GET', '/v1/push/key', { cookie: (await w.user()).cookie })).body.enabled, false);
  await withVapid(w);
  const a = await w.user('A'), b = await w.user('B');
  const noCsrf = await w.req('POST', '/v1/push/subscribe', { cookie: a.cookie, body: { endpoint: FCM }, xleash: false });
  assert.equal(noCsrf.status, 403);
  for (let i = 0; i < 10; i++) assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: a.cookie, body: { endpoint: FCM + i } })).status, 200);
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: a.cookie, body: { endpoint: FCM + 'x' } })).body.error, 'too_many_devices');
  // B cannot remove A's device; test push from B reaches nobody
  await w.req('POST', '/v1/push/unsubscribe', { cookie: b.cookie, body: { endpoint: FCM + '0' } });
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) AS n FROM push_subs').get().n, 10);
  assert.equal((await w.req('POST', '/v1/push/test', { cookie: b.cookie, body: {} })).body.sent, 0);
  assert.equal(w.pushes.length, 0);
});
