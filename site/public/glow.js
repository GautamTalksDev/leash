// The background glow follows the pointer, eased, and drifts on its own when the pointer is still.
// Sets CSS custom properties only (CSSOM), so it works under the strict CSP.
export function liveGlow() {
  const g = document.querySelector('.glow');
  if (!g || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  let tx = 50, ty = 8, x = 50, y = 8, last = 0, raf = 0;
  addEventListener('pointermove', (e) => {
    const r = g.getBoundingClientRect();
    tx = (e.clientX / r.width) * 100;
    ty = Math.min(100, Math.max(0, ((e.clientY - r.top) / r.height) * 100));
    last = performance.now();
    if (!raf) raf = requestAnimationFrame(tick);
  }, { passive: true });
  function tick(t) {
    if (t - last > 2500) { tx = 50 + Math.sin(t / 3200) * 18; ty = 10 + Math.cos(t / 4100) * 6; }
    x += (tx - x) * 0.06; y += (ty - y) * 0.06;
    g.style.setProperty('--mx', x.toFixed(2) + '%');
    g.style.setProperty('--my', y.toFixed(2) + '%');
    raf = document.hidden ? 0 : requestAnimationFrame(tick);
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden && !raf) raf = requestAnimationFrame(tick); });
  raf = requestAnimationFrame(tick);
}
