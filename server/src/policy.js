// Token policy. A token can only narrow what its credential can do; it never widens it.
// Order: deny > irreversible map (held unless pre-approved by a passkey holder) > hold > allow > default.
import { HttpError } from './util.js';
import { globMatch, irreversibleRule } from './providers.js';

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

function rules(list, name) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > 50) throw new HttpError(400, 'bad_policy', `${name} must be a list (max 50)`);
  return list.map((r) => {
    if (!r || typeof r !== 'object') throw new HttpError(400, 'bad_policy');
    const m = r.method === undefined ? '*' : String(r.method).toUpperCase();
    if (m !== '*' && !METHODS.includes(m)) throw new HttpError(400, 'bad_policy', `unknown method ${m}`);
    if (typeof r.path !== 'string' || !r.path.startsWith('/') || r.path.length > 300 || /[\s\\]/.test(r.path)) throw new HttpError(400, 'bad_policy', 'path must be a glob starting with /');
    return { method: m, path: r.path };
  });
}

/** validate + normalise a user policy. `byPasskey` decides whether irreversible pre-approval may be granted. */
export function normalisePolicy(p, byPasskey) {
  if (p === undefined || p === null) p = {};
  if (typeof p !== 'object' || Array.isArray(p)) throw new HttpError(400, 'bad_policy');
  const out = {
    allow: rules(p.allow, 'allow'),
    deny: rules(p.deny, 'deny'),
    hold: rules(p.hold, 'hold'),
    default: p.default === 'deny' ? 'deny' : p.default === 'hold' ? 'hold' : 'allow',
    readOnly: p.readOnly === true,
    perMinute: Number.isInteger(p.perMinute) && p.perMinute > 0 && p.perMinute <= 600 ? p.perMinute : 120,
    // Letting an agent run irreversible operations unattended is the one dangerous switch. Only a fresh passkey
    // ceremony can set it; a CLI session (which an agent on the same machine can read) cannot.
    unattendedIrreversible: rules(p.unattendedIrreversible, 'unattendedIrreversible'),
  };
  if (out.unattendedIrreversible.length && !byPasskey) throw new HttpError(403, 'passkey_required', 'Only a passkey holder can let irreversible operations through without approval.');
  return out;
}

const hit = (list, method, path) => list.some((r) => (r.method === '*' || r.method === method) && globMatch(r.path, path));

/** -> {decision: 'allow'|'deny'|'hold', rule, why} */
export function decide(policy, provider, method, path, body) {
  if (hit(policy.deny, method, path)) return { decision: 'deny', rule: 'policy.deny', why: 'This token is not allowed to call this endpoint.' };
  if (policy.readOnly && !['GET', 'HEAD'].includes(method)) return { decision: 'deny', rule: 'policy.readOnly', why: 'This token is read-only.' };
  const irr = irreversibleRule(provider, method, path, body);
  if (irr) {
    if (hit(policy.unattendedIrreversible, method, path)) return { decision: 'allow', rule: irr.id + ':preapproved', why: irr.why };
    return { decision: 'hold', rule: irr.id, why: irr.why };
  }
  if (hit(policy.hold, method, path)) return { decision: 'hold', rule: 'policy.hold', why: 'Your policy asks for approval on this endpoint.' };
  if (policy.allow.length) {
    if (hit(policy.allow, method, path)) return { decision: 'allow', rule: 'policy.allow', why: '' };
    return policy.default === 'allow'
      ? { decision: 'deny', rule: 'policy.allowlist', why: 'Not on this token\'s allow list.' }
      : { decision: policy.default, rule: 'policy.default', why: 'Not on this token\'s allow list.' };
  }
  if (policy.default === 'allow') return { decision: 'allow', rule: 'default', why: '' };
  return { decision: policy.default, rule: 'policy.default', why: 'Default for this token.' };
}
