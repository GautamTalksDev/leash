// Append-only audit log, hash-chained per account: each entry commits to the one before it, so a deleted or
// edited row breaks the chain (verifyChain). Secrets, tokens and request bodies are never written here.
import { sha256hex, now } from './util.js';

export async function audit(env, accountId, actor, action, detail) {
  const prev = await env.DB.prepare('SELECT hash FROM audit WHERE account_id = ? ORDER BY seq DESC LIMIT 1').bind(accountId).first();
  const prevHash = prev ? prev.hash : '0'.repeat(64);
  const at = now();
  const d = JSON.stringify(detail || {});
  const hash = await sha256hex(`${prevHash}|${accountId}|${at}|${actor}|${action}|${d}`);
  await env.DB.prepare('INSERT INTO audit (account_id, at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(accountId, at, actor, action, d, prevHash, hash).run();
  return hash;
}

export async function list(env, accountId, before, limit = 100) {
  const rows = await env.DB.prepare('SELECT seq, at, actor, action, detail, prev_hash, hash FROM audit WHERE account_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?')
    .bind(accountId, before || Number.MAX_SAFE_INTEGER, Math.min(200, limit)).all();
  return rows.results.map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
}

export async function verifyChain(env, accountId) {
  const rows = (await env.DB.prepare('SELECT * FROM audit WHERE account_id = ? ORDER BY seq').bind(accountId).all()).results;
  let prev = '0'.repeat(64);
  for (const r of rows) {
    if (r.prev_hash !== prev) return { ok: false, brokenAt: r.seq };
    const h = await sha256hex(`${r.prev_hash}|${r.account_id}|${r.at}|${r.actor}|${r.action}|${r.detail}`);
    if (h !== r.hash) return { ok: false, brokenAt: r.seq };
    prev = r.hash;
  }
  return { ok: true, entries: rows.length, head: prev };
}
