// LEASH landing: the live blast-radius field, the 9-second replay, the playable demo, the irreversible map.
// DOM building only (Trusted Types: no innerHTML). Respects prefers-reduced-motion.
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const n = document.createElement(tag); Object.assign(n, props); for (const k of kids) if (k != null) n.append(k); return n; };
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;

// ------------------------------------------------------------ 1. the field
const cv = $('field'), cx = cv.getContext('2d');
let W, H, DPR, tiles = [], shots = [], rings = [], allowed = 0, held = 0;
const NAMES = ['prod-db', 'main', 'vol_prod', 'stripe', 'r2-bucket', 'dns', 'users', 'billing', 'backups', 'auth', 'webhooks', 'edge', 'orders', 'repo', 'payouts', 'secrets'];
function resize() {
  DPR = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight;
  cv.width = W * DPR; cv.height = H * DPR; cx.setTransform(DPR, 0, 0, DPR, 0, 0);
  tiles = []; const cols = Math.max(5, Math.round(W / 150)), rows = Math.max(4, Math.round(H / 130));
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    if (Math.random() < 0.35) continue;
    tiles.push({ x: (c + 0.5 + (r % 2) * 0.35) * (W / cols), y: (r + 0.5) * (H / rows), n: NAMES[(r * cols + c) % NAMES.length], glow: 0, hold: 0 });
  }
}
addEventListener('resize', resize); resize();
function fire() {
  if (!tiles.length) return;
  const t = tiles[(Math.random() * tiles.length) | 0];
  const bad = Math.random() < 0.18;
  const sx = Math.random() < 0.5 ? -20 : W + 20, sy = Math.random() * H;
  shots.push({ sx, sy, t, p: 0, bad, v: 0.012 + Math.random() * 0.01 });
}
function frame() {
  cx.clearRect(0, 0, W, H);
  // tiles
  for (const t of tiles) {
    t.glow *= 0.96; t.hold *= 0.985;
    const g = t.glow, h = t.hold;
    cx.strokeStyle = h > 0.05 ? `rgba(255,176,32,${0.25 + h * 0.6})` : `rgba(61,220,151,${0.08 + g * 0.6})`;
    cx.fillStyle = h > 0.05 ? `rgba(255,176,32,${h * 0.10})` : `rgba(61,220,151,${0.015 + g * 0.12})`;
    cx.lineWidth = 1;
    cx.beginPath(); cx.roundRect(t.x - 38, t.y - 16, 76, 32, 8); cx.fill(); cx.stroke();
    cx.fillStyle = h > 0.05 ? `rgba(255,190,80,${0.4 + h * 0.6})` : `rgba(160,175,200,${0.18 + g * 0.6})`;
    cx.font = '10px "Geist Mono", monospace'; cx.textAlign = 'center'; cx.fillText(t.n, t.x, t.y + 3.5);
  }
  // shots
  for (const s of shots) {
    s.p += s.v;
    const stop = s.bad ? 0.82 : 1;
    const p = Math.min(s.p, stop);
    const x = s.sx + (s.t.x - s.sx) * p, y = s.sy + (s.t.y - s.sy) * p;
    const tx = s.sx + (s.t.x - s.sx) * Math.max(0, p - 0.12), ty = s.sy + (s.t.y - s.sy) * Math.max(0, p - 0.12);
    const grd = cx.createLinearGradient(tx, ty, x, y);
    const col = s.bad ? '255,77,100' : '198,255,61';
    grd.addColorStop(0, `rgba(${col},0)`); grd.addColorStop(1, `rgba(${col},.9)`);
    cx.strokeStyle = grd; cx.lineWidth = 1.6; cx.beginPath(); cx.moveTo(tx, ty); cx.lineTo(x, y); cx.stroke();
    if (s.p >= stop && !s.done) {
      s.done = true;
      if (s.bad) { s.t.hold = 1; held++; rings.push({ x, y, r: 60, a: 1, tx: s.t.x, ty: s.t.y }); }
      else { s.t.glow = 1; allowed++; }
    }
  }
  shots = shots.filter((s) => !(s.done && s.p > (s.bad ? 1.1 : 1.15)));
  // leash rings: a dashed ring that snaps shut around the held call, then a HELD stamp
  for (const r of rings) {
    r.r += (14 - r.r) * 0.12; r.a *= 0.985;
    cx.save(); cx.translate(r.x, r.y); cx.rotate(performance.now() / 600);
    cx.setLineDash([5, 4]); cx.strokeStyle = `rgba(255,176,32,${r.a})`; cx.lineWidth = 2;
    cx.beginPath(); cx.arc(0, 0, r.r, 0, Math.PI * 2); cx.stroke(); cx.restore();
    if (r.a > 0.3) { cx.fillStyle = `rgba(255,176,32,${r.a})`; cx.font = '700 10px "Geist Mono", monospace'; cx.fillText('HELD', r.x, r.y - r.r - 8); }
  }
  rings = rings.filter((r) => r.a > 0.05);
  $('cAllowed').textContent = (allowed * 37 + 1204).toLocaleString();
  $('cHeld').textContent = held.toLocaleString();
  if (!RM) requestAnimationFrame(frame);
}
if (!RM) { setInterval(fire, 260); requestAnimationFrame(frame); } else frame();

// ------------------------------------------------------------ 2. the nine seconds (scroll-driven)
const vols = $('vols');
for (let i = 0; i < 24; i++) vols.append(el('div', { textContent: i === 0 ? 'vol_prod' : i < 6 ? `backup_${String(i).padStart(2, '0')}` : `vol_${(i * 7919 % 9000).toString(16)}` }));
const nine = $('nine'), items = [...document.querySelectorAll('#story li')];
function onScroll() {
  const r = nine.getBoundingClientRect();
  const p = Math.min(1, Math.max(0, -r.top / (r.height - innerHeight)));
  const t = Math.min(9, p * 11);
  $('clock').textContent = t.toFixed(2);
  items.forEach((li) => li.classList.toggle('on', t >= Number(li.dataset.t)));
  const gone = t >= 6.8 ? Math.min(24, Math.round((t - 6.8) / 2.2 * 24)) : 0;
  [...vols.children].forEach((d, i) => d.classList.toggle('gone', i < gone));
  $('rewind').classList.toggle('on', p > 0.86);
  // reveal on scroll
  for (const n of document.querySelectorAll('.reveal:not(.in)')) if (n.getBoundingClientRect().top < innerHeight * 0.88) n.classList.add('in');
}
addEventListener('scroll', onScroll, { passive: true });
for (const s of document.querySelectorAll('.three, .flow, .map, .install, .pricing, .sec, .demo')) s.classList.add('reveal');
onScroll();

// ------------------------------------------------------------ 3. the playable demo
const SC = [
  { label: 'List open pull requests', sub: 'GitHub, read', kind: 'allow', call: 'GET api.github.com/repos/acme/app/pulls?state=open', reply: '200  12 open pull requests' },
  { label: 'Delete the staging volume', sub: 'Railway, the PocketOS call', kind: 'hold', call: 'POST backboard.railway.app  mutation { volumeDelete(volumeId: "vol_prod") }', why: 'Deletes a volume. This cannot be undone.', rule: 'rw.delete-mutation' },
  { label: 'Force push a rewritten main', sub: 'GitHub, history rewrite', kind: 'hold', call: 'PATCH api.github.com/repos/acme/app/git/refs/heads/main  {"force":true}', why: 'Rewrites history for everyone.', rule: 'gh.force-push' },
  { label: 'Clean up old users', sub: 'Supabase SQL', kind: 'hold', call: 'POST api.supabase.com/v1/projects/abc/database/query  DELETE FROM users', why: 'DELETE without WHERE removes every row.', rule: 'sb.sql' },
  { label: 'Refund the last 40 orders', sub: 'Stripe, moves money', kind: 'hold', call: 'POST api.stripe.com/v1/refunds x40', why: 'Moves money.', rule: 'st.money' },
];
const term = $('term'), picks = $('picks');
let busy = false, decide = null;
function line(cls, text) { term.append(el('span', { className: cls, textContent: text }), '\n'); term.scrollTop = term.scrollHeight; }
const wait = (ms) => new Promise((r) => setTimeout(r, RM ? 0 : ms));
async function typeLine(text) { const s = el('span'); term.append(s, '\n'); for (const ch of text) { s.textContent += ch; await wait(9); } }
function phoneHold(sc) {
  $('phIdle').hidden = true; $('phHold').hidden = false;
  $('phWhat').textContent = sc.call.split('  ')[0]; $('phWhy').textContent = sc.why;
  const ph = $('phone'); ph.classList.remove('buzz'); void ph.offsetWidth; ph.classList.add('buzz');
  return new Promise((res) => { decide = res; });
}
$('phOk').onclick = () => decide && decide(true);
$('phNo').onclick = () => decide && decide(false);
async function run(sc, btn) {
  if (busy) return; busy = true;
  [...picks.children].forEach((b) => b.classList.toggle('on', b === btn));
  term.replaceChildren();
  line('d', `> ${sc.label.toLowerCase()}`);
  await wait(250); await typeLine(`agent  calling ${sc.call}`);
  await wait(300);
  if (sc.kind === 'allow') { line('g', `leash  allowed   (key injected server-side; the agent never saw it)`); line('d', `api    ${sc.reply}`); busy = false; return; }
  line('w', `leash  HELD  ${sc.rule}: ${sc.why}`); line('w', `       approve: leash.gautamkhosla.com/app#hold=4f2a...`);
  line('d', `agent  That can't be undone, so I've paused and asked you to approve it.`);
  const ok = await phoneHold(sc);
  $('phHold').hidden = true; $('phIdle').hidden = false; decide = null;
  if (ok) { line('g', `phone  approved with Face ID (this exact request, once, 10 min)`); await wait(300); line('d', `agent  retrying ... done.`); }
  else { line('r', `phone  denied`); await wait(300); line('d', `agent  Understood, I won't do that. Want me to snapshot the volume first instead?`); }
  busy = false;
}
for (const sc of SC) { const b = el('button', {}, sc.label, el('small', { textContent: sc.sub })); b.onclick = () => run(sc, b); picks.append(b); }
line('d', 'Pick something for the agent to try.');

// ------------------------------------------------------------ 4. the irreversible map, as a periodic table
fetch('/v1/meta').then((r) => r.json()).then((m) => {
  $('mapVer').textContent = `version ${m.mapVersion}`;
  const T = $('table');
  for (const p of m.providers) for (const r of p.irreversible) {
    const sym = r.id.split('.')[1].split('-').map((w) => w[0].toUpperCase() + (w[1] || '')).join('').slice(0, 3);
    T.append(el('div', { className: 'cell', tabIndex: 0 }, el('div', { className: 'p', textContent: `${p.name}  ${r.id}` }), el('div', { className: 'sym', textContent: sym }), el('div', { className: 'rt', textContent: `${r.method} ${r.path}` }), el('div', { className: 'why', textContent: r.why })));
  }
}).catch(() => {});
