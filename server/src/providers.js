// Upstream APIs LEASH can broker, and the map of operations that cannot be undone.
// The irreversible map is the product: each rule names a real way an agent can destroy something, with the incident
// or doc it comes from. Rules match on method + path (glob) and, where the danger is in the body, on the body.
// Version it; every change must come with a test in test/irreversible.test.js.
export const MAP_VERSION = '2026-10-07.1';

// One statement at a time, comments stripped: DROP/TRUNCATE, ALTER ... DROP, DELETE or UPDATE without WHERE,
// GRANT ALL, turning row-level security off.
export function sqlDestructive(sql) {
  const clean = String(sql || '').replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  return clean.split(';').some((st) => {
    const t = st.trim().toLowerCase().replace(/\s+/g, ' ');
    if (!t) return false;
    if (/^(drop|truncate)\b/.test(t)) return true;
    if (/^alter table .* drop\b/.test(t)) return true;
    if (/^grant all\b/.test(t)) return true;
    if (/disable row level security/.test(t)) return true;
    if (/^(delete from|update)\b/.test(t) && !/\bwhere\b/.test(t)) return true;
    if (/^with\b/.test(t) && /\b(delete from|drop|truncate)\b/.test(t)) return true;
    return false;
  });
}

function sqlFrom(body) {
  if (!body) return '';
  try {
    const j = JSON.parse(body);
    return typeof j.query === 'string' ? j.query : typeof j.sql === 'string' ? j.sql : '';
  } catch {
    return '';
  }
}

function gqlMutations(body) {
  try {
    const j = JSON.parse(body || '{}');
    const q = typeof j.query === 'string' ? j.query : '';
    if (!/^\s*mutation\b/i.test(q) && !/\bmutation\b/i.test(q)) return [];
    // field names directly called inside the mutation: name( or name {
    return [...q.matchAll(/\b([a-zA-Z]+)\s*(?=\(|\{)/g)].map((m) => m[1]).filter((n) => n !== 'mutation');
  } catch {
    return [];
  }
}

export const PROVIDERS = {
  github: {
    name: 'GitHub',
    host: 'api.github.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}`, 'x-github-api-version': '2022-11-28' }),
    keyHint: /^(ghp_|github_pat_|gho_|ghs_)/,
    irreversible: [
      { id: 'gh.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on GitHub removes something (repo, branch, release, key, member).' },
      { id: 'gh.force-push', m: 'PATCH', p: '/repos/*/*/git/refs/**', body: (b) => /"force"\s*:\s*true/.test(b || ''), why: 'Force-updating a ref rewrites history and can drop commits for everyone.' },
      { id: 'gh.transfer', m: 'POST', p: '/repos/*/*/transfer', why: 'Transferring a repository hands it to another owner.' },
      { id: 'gh.visibility', m: 'PATCH', p: '/repos/*/*', body: (b) => /"(visibility|private)"\s*:/.test(b || '') || /"archived"\s*:\s*true/.test(b || ''), why: 'Changing visibility can publish private code; archiving freezes a repo.' },
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
      { id: 'cf.d1-sql', m: 'POST', p: '/accounts/*/d1/database/*/{query,raw}', body: (b) => sqlDestructive(sqlFrom(b)), why: 'Destructive SQL against a production D1 database.' },
    ],
  },
  railway: {
    name: 'Railway',
    host: 'backboard.railway.app',
    base: '/graphql/v2',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    irreversible: [
      // PocketOS, 25 Apr 2026: one volumeDelete wiped the production database and its volume backups in 9 seconds.
      { id: 'rw.delete-mutation', m: 'POST', p: '/**', body: (b) => gqlMutations(b).some((n) => /(Delete|Remove|Reset|Restore|Rollback|Detach)$/i.test(n) || /^(volume|service|project|environment|plugin|database)(Delete|Remove)/i.test(n)), why: 'A Railway mutation that deletes, resets or rolls back a volume, service, project or environment (PocketOS lost production this way).' },
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
      { id: 'st.cancel', m: 'POST', p: '/v1/subscriptions/*/cancel', why: 'Cancels a paying customer.' },
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
      { id: 'sb.sql', m: 'POST', p: '/v1/projects/*/database/query', body: (b) => sqlDestructive(sqlFrom(b)), why: 'Destructive SQL (DROP, TRUNCATE, DELETE or UPDATE without WHERE, RLS off) on the database.' },
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

/** first irreversible rule this request trips, or null */
export function irreversibleRule(provider, method, path, body) {
  const P = PROVIDERS[provider];
  for (const r of P.irreversible) {
    if (r.m !== method) continue;
    if (!globMatch(r.p, path)) continue;
    if (r.body && !r.body(body)) continue;
    return r;
  }
  return null;
}
