// Local dev server: the real API on node:sqlite + the static site. Never deployed.  node dev/local.js [port]
import http from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { makeDb } from '../test/helpers.js';
import { handle } from '../src/index.js';

const port = Number(process.argv[2] || 8790);
const env = { DB: makeDb(), LEASH_KEK: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'), IP_SALT: 'dev', ORIGIN: `http://localhost:${port}`, RP_ID: 'localhost' };
const SITE = new URL('../../site/public/', import.meta.url);
const TYPES = { html: 'text/html; charset=utf-8', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml', woff2: 'font/woff2' };
const headers = {};
for (const line of readFileSync(new URL('_headers', SITE), 'utf8').split('\n').slice(1)) {
  const i = line.indexOf(':');
  if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(' upgrade-insecure-requests', '');
}
env.ASSETS = {
  fetch: async (req) => {
    let p = new URL(req.url).pathname;
    if (p.includes('..')) return new Response('no', { status: 403 });
    if (p.endsWith('/')) p += 'index.html';
    let f = new URL('.' + p, SITE);
    if (existsSync(f) && statSync(f).isDirectory()) f = new URL('.' + p + '/index.html', SITE);
    if (!existsSync(f)) return new Response(readFileSync(new URL('404.html', SITE)), { status: 404, headers: { 'content-type': TYPES.html, ...headers } });
    const ext = f.pathname.split('.').pop();
    return new Response(readFileSync(f), { headers: { 'content-type': TYPES[ext] || 'application/octet-stream', ...headers } });
  },
};
http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const h = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') h.set(k, v);
  h.set('cf-connecting-ip', '127.0.0.1');
  const r = await handle(new Request(`http://localhost:${port}${req.url}`, { method: req.method, headers: h, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) }), env);
  const out = {};
  r.headers.forEach((v, k) => { out[k] = v; });
  res.writeHead(r.status, out);
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, () => console.log(`LEASH dev on http://localhost:${port}`));
