// Test world: D1 on node:sqlite, a virtual passkey authenticator (real ECDSA P-256 + CBOR), a fake upstream.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { handle } from '../src/index.js';
import { b64u, sha256 } from '../src/util.js';

class Stmt {
  constructor(db, sql, args = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...a) { return new Stmt(this.db, this.sql, a); }
  async first() { return this.db.prepare(this.sql).get(...this.args) ?? null; }
  async all() { return { results: this.db.prepare(this.sql).all(...this.args) }; }
  async run() { const r = this.db.prepare(this.sql).run(...this.args); return { meta: { changes: Number(r.changes) } }; }
}
export function makeDb() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  const dir = new URL('../migrations/', import.meta.url);
  for (const f of readdirSync(dir).sort()) db.exec(readFileSync(new URL(f, dir), 'utf8'));
  return {
    raw: db,
    prepare: (sql) => new Stmt(db, sql),
    async batch(list) { db.exec('BEGIN'); try { for (const s of list) await s.run(); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; } },
  };
}

// ---- minimal CBOR encoder (test side only)
function head(mt, n) {
  if (n < 24) return [mt << 5 | n];
  if (n < 256) return [mt << 5 | 24, n];
  if (n < 65536) return [mt << 5 | 25, n >> 8, n & 255];
  return [mt << 5 | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function cbor(v) {
  if (typeof v === 'number') return Uint8Array.from(v >= 0 ? head(0, v) : head(1, -1 - v));
  if (typeof v === 'string') { const b = new TextEncoder().encode(v); return Uint8Array.from([...head(3, b.length), ...b]); }
  if (v instanceof Uint8Array) return Uint8Array.from([...head(2, v.length), ...v]);
  if (v instanceof Map) { const parts = [...v].flatMap(([k, x]) => [...cbor(k), ...cbor(x)]); return Uint8Array.from([...head(5, v.size), ...parts]); }
  throw new Error('cbor type');
}

const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; let v = b.slice(i); if (v[0] & 0x80) v = Uint8Array.of(0, ...v); return Uint8Array.of(2, v.length, ...v); };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

export class Authenticator {
  constructor(origin, rpId) { this.origin = origin; this.rpId = rpId; this.count = 0; }
  async create(options) {
    this.kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', this.kp.publicKey);
    const from = (s) => Uint8Array.from(Buffer.from(s, 'base64url'));
    this.credId = crypto.getRandomValues(new Uint8Array(16));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, from(jwk.x)], [-3, from(jwk.y)]]));
    const authData = cat(await sha256(this.rpId), Uint8Array.of(0x45), Uint8Array.of(0, 0, 0, 0), new Uint8Array(16), Uint8Array.of(0, 16), this.credId, cose);
    const cd = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: this.origin }));
    return { id: b64u(this.credId), attestationObject: b64u(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))), clientDataJSON: b64u(cd) };
  }
  async get(options, { origin = this.origin, flags = 0x05 } = {}) {
    this.count++;
    const ad = cat(await sha256(this.rpId), Uint8Array.of(flags), Uint8Array.of(0, 0, 0, this.count));
    const cd = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.kp.privateKey, cat(ad, await sha256(cd))));
    return { id: b64u(this.credId), authenticatorData: b64u(ad), clientDataJSON: b64u(cd), signature: b64u(rawToDer(raw)) };
  }
}

export const ORIGIN = 'https://leash.test', RP_ID = 'leash.test';

export class World {
  constructor() {
    this.env = { DB: makeDb(), LEASH_KEK: b64u(crypto.getRandomValues(new Uint8Array(32))), IP_SALT: 'salt', ORIGIN, RP_ID };
    this.upstream = [];
    this.reply = () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'x=1' } });
    this.fetcher = async (url, init) => {
      this.upstream.push({ url, method: init.method, headers: Object.fromEntries(init.headers), body: init.body ? new TextDecoder().decode(init.body) : null });
      return this.reply(url, init);
    };
  }
  async req(method, path, { body, cookie, bearer, origin = ORIGIN, xleash = true, raw, headers = {} } = {}) {
    const h = { 'cf-connecting-ip': '203.0.113.7', ...headers };
    if (body !== undefined) h['content-type'] = 'application/json';
    if (cookie) h.cookie = cookie;
    if (bearer) h.authorization = 'Bearer ' + bearer;
    if (origin) h.origin = origin;
    if (xleash) h['x-leash'] = '1';
    const r = await handle(new Request('https://leash.test' + path, { method, headers: h, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined) }), this.env, { fetcher: this.fetcher });
    const text = await r.text();
    let j; try { j = JSON.parse(text); } catch { j = text; }
    return { status: r.status, body: j, headers: r.headers };
  }
  /** passkey sign-up; returns {cookie, auth} */
  async user(name = 'Gautam') {
    const auth = new Authenticator(ORIGIN, RP_ID);
    const b = await this.req('POST', '/v1/auth/register/begin', { body: { name } });
    const cred = await auth.create(b.body.options);
    const f = await this.req('POST', '/v1/auth/register/finish', { body: { challengeId: b.body.challengeId, credential: cred } });
    if (f.status !== 200) throw new Error('signup failed ' + JSON.stringify(f.body));
    const cookie = f.headers.get('set-cookie').split(';')[0];
    return { cookie, auth };
  }
}
