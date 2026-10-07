// Upstream APIs LEASH can broker, and the map of operations that cannot be undone.
// The irreversible map is the product: each rule names a real way an agent can destroy something, with the incident
// or doc it comes from. Rules match on method + path (glob) and, where the danger is in the body, on the body.
// Body checks fail closed: a body LEASH cannot read on a route that has a body rule is held.
// Version it; every change must come with a test in test/hardening.test.js or test/leash.test.js.
export const MAP_VERSION = '2026-10-07.2';

// ---------------------------------------------------------------- SQL
// A real tokenizer: single-quoted strings, double-quoted and backtick identifiers, -- and nested /* */ comments.
// Returns null (unreadable, so held) for unterminated strings or comments, backslashes inside strings (E'' escapes
// would shift where a string ends) and any $ that is not a $1 style parameter (dollar quotes, $$ bodies).
export function sqlTokens(sql) {
  const s = String(sql ?? ''), out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '-' && s[i + 1] === '-') { const j = s.indexOf('\n', i); i = j < 0 ? s.length : j + 1; continue; }
    if (c === '/' && s[i + 1] === '*') {
      let d = 1, j = i + 2;
      while (j < s.length && d) { if (s.startsWith('/*', j)) { d++; j += 2; } else if (s.startsWith('*/', j)) { d--; j += 2; } else j++; }
      if (d) return null;
      i = j; continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1;
      for (;;) {
        if (j >= s.length || s[j] === '\\') return null;
        if (s[j] === c) { if (s[j + 1] === c) { j += 2; continue; } break; }
        j++;
      }
      out.push({ t: c === "'" ? 's' : 'id', v: '' }); i = j + 1; continue;
    }
    if (c === '$') { const m = s.slice(i).match(/^\$\d+/); if (!m) return null; out.push({ t: 'p', v: m[0] }); i += m[0].length; continue; }
    const w = s.slice(i).match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (w) { out.push({ t: 'w', v: w[0].toLowerCase() }); i += w[0].length; continue; }
    out.push({ t: c === ';' ? ';' : 'p', v: c }); i++;
  }
  return out;
}

// Words that make a statement more than a read, anywhere outside a string. Functions with side effects that a
// SELECT can call (pg_terminate_backend, set_config, nextval, lo_import, dblink_exec) are caught by prefix.
const SQL_WRITE = new Set(('insert update delete merge drop truncate alter create grant revoke do execute exec call copy into ' +
  'lock for set reset attach detach pragma vacuum reindex analyze notify listen load import refresh cluster comment security prepare ' +
  'deallocate savepoint begin commit rollback returning').split(' '));
const SQL_FN = /^(pg_|lo_|dblink|set_config|nextval|setval|txid_|query_to_)/;

/** true only for one statement that is plainly a read: SELECT, WITH ... SELECT, EXPLAIN (no ANALYZE), SHOW */
export function sqlReadOnly(sql) {
  const tk = sqlTokens(sql);
  if (!tk) return false;
  while (tk.length && tk[tk.length - 1].t === ';') tk.pop();
  if (!tk.length || tk.some((x) => x.t === ';')) return false;
  if (tk[0].t !== 'w' || !['select', 'with', 'explain', 'show'].includes(tk[0].v)) return false;
  return !tk.some((x) => x.t === 'w' && (SQL_WRITE.has(x.v) || SQL_FN.test(x.v)));
}

/** kept for callers and tests: anything that is not plainly read-only needs a human */
export const sqlDestructive = (sql) => !sqlReadOnly(sql);

/** every SQL string in a request body (sql, query, batch arrays), or null when the body is unreadable or ambiguous */
export function sqlBodies(body) {
  let j;
  try { j = JSON.parse(body || ''); } catch { return null; }
  const out = [];
  const walk = (o) => {
    if (Array.isArray(o)) return o.length && o.every(walk);
    if (!o || typeof o !== 'object') return false;
    // D1 executes `sql`; Supabase executes `query`. A body carrying both could show one and run the other.
    if ('sql' in o && 'query' in o) return false;
    let found = false;
    for (const k of ['sql', 'query']) if (k in o) { if (typeof o[k] !== 'string') return false; out.push(o[k]); found = true; }
    if ('batch' in o) { if (!walk(o.batch)) return false; found = true; }
    return found;
  };
  return walk(j) ? out : null;
}
const sqlHold = (b) => { const l = sqlBodies(b); return !l || !l.length || l.some((q) => !sqlReadOnly(q)); };

// ---------------------------------------------------------------- GraphQL
// Lexer per the GraphQL spec: commas are whitespace, # starts a comment, strings and block strings are skipped.
export function gqlTokens(src) {
  const s = String(src), out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/[\s,]/.test(c)) { i++; continue; }
    if (c === '#') { while (i < s.length && s[i] !== '\n' && s[i] !== '\r') i++; continue; }
    if (s.startsWith('"""', i)) { const j = s.indexOf('"""', i + 3); if (j < 0) return null; out.push({ t: 's' }); i = j + 3; continue; }
    if (c === '"') {
      let j = i + 1;
      for (;;) { if (j >= s.length || s[j] === '\n') return null; if (s[j] === '\\') { j += 2; continue; } if (s[j] === '"') break; j++; }
      out.push({ t: 's' }); i = j + 1; continue;
    }
    if (s.startsWith('...', i)) { out.push({ t: 'p', v: '...' }); i += 3; continue; }
    const w = s.slice(i).match(/^[_A-Za-z][_0-9A-Za-z]*/);
    if (w) { out.push({ t: 'n', v: w[0] }); i += w[0].length; continue; }
    out.push({ t: 'p', v: c }); i++;
  }
  return out;
}

/** root field names of every mutation in a document; null if the document cannot be read with certainty */
export function gqlMutationFields(src) {
  const tk = gqlTokens(src);
  if (!tk) return null;
  const fields = [];
  let i = 0;
  const skip = (open, close) => { let d = 0; do { if (i >= tk.length) return false; if (tk[i].v === open) d++; else if (tk[i].v === close) d--; i++; } while (d); return true; };
  while (i < tk.length) {
    const t = tk[i];
    if (t.v === '{') { if (!skip('{', '}')) return null; continue; } // shorthand query
    if (t.t !== 'n' || !['query', 'mutation', 'subscription', 'fragment'].includes(t.v)) return null;
    const isMut = t.v === 'mutation';
    i++;
    while (i < tk.length && tk[i].v !== '{') {
      if (tk[i].v === '(') { if (!skip('(', ')')) return null; } else i++;
    }
    if (i >= tk.length) return null;
    if (!isMut) { if (!skip('{', '}')) return null; continue; }
    i++; // into the root selection set
    while (i < tk.length && tk[i].v !== '}') {
      if (tk[i].v === '...') return null; // fragment spreads at a mutation root could hide any field
      if (tk[i].t !== 'n') return null;
      let name = tk[i++].v;
      if (tk[i]?.v === ':') { i++; if (tk[i]?.t !== 'n') return null; name = tk[i++].v; }
      fields.push(name);
      if (tk[i]?.v === '(') { if (!skip('(', ')')) return null; }
      while (tk[i]?.v === '@') { i += 2; if (tk[i]?.v === '(') { if (!skip('(', ')')) return null; } }
      if (tk[i]?.v === '{') { if (!skip('{', '}')) return null; }
    }
    if (i >= tk.length) return null;
    i++;
  }
  return fields;
}

// The only Railway mutations that pass without approval: restarting or redeploying what is already running.
// Everything else (deletes, resets, rollbacks, variable and volume changes, anything new) is held.
export const RAILWAY_SAFE = new Set(['serviceInstanceRedeploy', 'deploymentRestart', '__typename']);
function railwayHold(body) {
  let j;
  try { j = JSON.parse(body || ''); } catch { return true; }
  if (!j || typeof j !== 'object' || Array.isArray(j) || typeof j.query !== 'string') return true; // batches, persisted queries
  const f = gqlMutationFields(j.query);
  return !f || f.some((n) => !RAILWAY_SAFE.has(n));
}
// GET carries the document in ?query=; mutations over GET are refused by spec but held here in case they are not
const railwayGetHold = (b, q) => /mutation/i.test(safeDecode(q));
const safeDecode = (q) => { try { return decodeURIComponent(String(q || '').replace(/\+/g, ' ')); } catch { return String(q || ''); } };

// ---------------------------------------------------------------- bodies
function jsonObj(b) {
  try { const j = JSON.parse(b || ''); return j && typeof j === 'object' && !Array.isArray(j) ? j : null; } catch { return null; }
}
const set = (v) => v !== undefined && v !== false;
// GitHub: inspect parsed values, so "force" and friends cannot slip past. Unreadable bodies are held.
const ghForce = (b) => { const j = jsonObj(b); return !j || set(j.force); };
const ghVisibility = (b) => { const j = jsonObj(b); return !j || 'visibility' in j || 'private' in j || set(j.archived); };
// Stripe: form-encoded params from the body and the query string (Stripe reads both); JSON bodies too.
function stripeParam(b, q, k) {
  const j = jsonObj(b);
  if (j && k in j) return String(j[k]);
  for (const src of [b, q]) { const v = new URLSearchParams(String(src || '').replace(/^\?/, '')).get(k); if (v !== null) return v; }
  return null;
}
const truthy = (v) => v !== null && !['', 'false', '0'].includes(v.toLowerCase());

export const PROVIDERS = {
  github: {
    name: 'GitHub',
    host: 'api.github.com',
    base: '',
    // owner and repo names are case-insensitive on GitHub, so rules match a lowercased path (upstream keeps the case)
    ci: true,
    auth: (k) => ({ authorization: `Bearer ${k}`, 'x-github-api-version': '2022-11-28' }),
    keyHint: /^(ghp_|github_pat_|gho_|ghs_)/,
    irreversible: [
      { id: 'gh.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on GitHub removes something (repo, branch, release, key, member).' },
      { id: 'gh.force-push', m: 'PATCH', p: '/repos/*/*/git/refs/**', body: ghForce, why: 'Force-updating a ref rewrites history and can drop commits for everyone.' },
      { id: 'gh.transfer', m: 'POST', p: '/repos/*/*/transfer', why: 'Transferring a repository hands it to another owner.' },
      { id: 'gh.visibility', m: 'PATCH', p: '/repos/*/*', body: ghVisibility, why: 'Changing visibility can publish private code; archiving freezes a repo.' },
      { id: 'gh.protection', m: 'PUT', p: '/repos/*/*/branches/*/protection', why: 'Rewriting branch protection can remove the rules that guard main.' },
      { id: 'gh.actions-secret', m: 'PUT', p: '/repos/*/*/actions/secrets/*', why: 'Overwriting a CI secret silently changes what production deploys with.' },
    ],
  },
  cloudflare: {
    name: 'Cloudflare',
    host: 'api.cloudflare.com',
    base: '/client/v4',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    irreversible: [
      { id: 'cf.delete', m: 'DELETE', p: '/**', why: 'Deletes a zone, DNS record, Worker, bucket, database or token.' },
      { id: 'cf.purge', m: 'POST', p: '/zones/*/purge_cache', body: (b) => /purge_everything/.test(b || ''), why: 'Purging the whole cache can take a site down under load.' },
      { id: 'cf.d1-sql', m: 'POST', p: '/accounts/*/d1/database/*/{query,raw}', body: sqlHold, why: 'SQL against a production D1 database that is not a single plain read.' },
    ],
  },
  railway: {
    name: 'Railway',
    host: 'backboard.railway.app',
    base: '/graphql/v2',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    irreversible: [
      // PocketOS, 25 Apr 2026: one volumeDelete wiped the production database and its volume backups in 9 seconds.
      { id: 'rw.mutation', m: 'POST', p: '/**', body: railwayHold, why: 'A Railway mutation other than a redeploy or restart, or a request LEASH cannot read (PocketOS lost production to one volumeDelete).' },
      { id: 'rw.get-mutation', m: 'GET', p: '/**', body: railwayGetHold, why: 'A Railway mutation sent over GET.' },
    ],
  },
  stripe: {
    name: 'Stripe',
    host: 'api.stripe.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    keyHint: /^(sk_|rk_)/,
    irreversible: [
      { id: 'st.delete', m: 'DELETE', p: '/**', why: 'Deletes customers, products, webhooks or cancels subscriptions.' },
      { id: 'st.money', m: 'POST', p: '/v1/{refunds,payouts,transfers,charges,topups}', why: 'Moves money.' },
      { id: 'st.money2', m: 'POST', p: '/v1/payment_intents/*/{confirm,capture}', why: 'Moves money.' },
      { id: 'st.pi-confirm', m: 'POST', p: '/v1/payment_intents', body: (b, q) => truthy(stripeParam(b, q, 'confirm')), why: 'Creating a payment intent with confirm=true charges the customer.' },
      { id: 'st.refund', m: 'POST', p: '/v1/{charges,application_fees}/*/{refund,refunds}', why: 'Refunds money.' },
      { id: 'st.invoice', m: 'POST', p: '/v1/invoices/*/{pay,void}', why: 'Paying or voiding an invoice cannot be undone.' },
      { id: 'st.credit-note', m: 'POST', p: '/v1/credit_notes', why: 'Issuing a credit note credits or refunds the customer.' },
      { id: 'st.credit-note-void', m: 'POST', p: '/v1/credit_notes/*/void', why: 'Voiding a credit note cannot be undone.' },
      { id: 'st.cancel', m: 'POST', p: '/v1/subscriptions/*/cancel', why: 'Cancels a paying customer.' },
      { id: 'st.cancel-at', m: 'POST', p: '/v1/subscriptions/*', body: (b, q) => truthy(stripeParam(b, q, 'cancel_at_period_end')) || truthy(stripeParam(b, q, 'cancel_at')), why: 'Schedules a paying customer to be cancelled.' },
      { id: 'st.webhook', m: 'POST', p: '/v1/webhook_endpoints/**', why: 'Changing webhooks can silently stop order fulfilment.' },
    ],
  },
  supabase: {
    name: 'Supabase',
    host: 'api.supabase.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    keyHint: /^sbp_/,
    irreversible: [
      { id: 'sb.delete', m: 'DELETE', p: '/**', why: 'Deletes a project, function, branch or secret.' },
      { id: 'sb.sql', m: 'POST', p: '/v1/projects/*/database/query', body: sqlHold, why: 'SQL on the database that is not a single plain read (SELECT, WITH ... SELECT, EXPLAIN, SHOW).' },
      { id: 'sb.pause', m: 'POST', p: '/v1/projects/*/{pause,restore}', why: 'Pausing or restoring a project takes production offline.' },
      { id: 'sb.secrets', m: 'POST', p: '/v1/projects/*/secrets', why: 'Overwriting project secrets changes production configuration.' },
    ],
  },
};

/** tiny glob: * = one segment, ** = any depth, {a,b} = alternatives */
export function globToRe(g) {
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') { if (g[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*'; }
    else if (c === '{') { const j = g.indexOf('}', i); re += '(' + g.slice(i + 1, j).split(',').map(esc).join('|') + ')'; i = j; }
    else re += esc(c);
  }
  return new RegExp('^' + re + '$');
}
const esc = (s) => s.replace(/[.+?^$()|[\]\\]/g, '\\$&');
const reCache = new Map();
export function globMatch(g, path) {
  let r = reCache.get(g);
  if (!r) { r = globToRe(g); reCache.set(g, r); }
  return r.test(path);
}

/** the path rules are matched against: canonical, and lowercased on case-insensitive providers */
export const matchPath = (provider, path) => (PROVIDERS[provider]?.ci ? path.toLowerCase() : path);

/** first irreversible rule this request trips, or null. `path` is canonical; `search` is the raw query string. */
export function irreversibleRule(provider, method, path, body, search = '') {
  const P = PROVIDERS[provider];
  const mp = matchPath(provider, path);
  for (const r of P.irreversible) {
    if (r.m !== method) continue;
    if (!globMatch(r.p, mp)) continue;
    if (r.body && !r.body(body, search)) continue;
    return r;
  }
  return null;
}
