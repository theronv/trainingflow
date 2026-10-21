// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Course result ceremony
//  The screen a learner sees after finishing a course: a short reveal of the
//  score, what they earned, and what to do next. Failing gets the same care.
// ══════════════════════════════════════════════════════════

const Celebrate = {
  SOUND_KEY: 'trainflow_cert_sound',
  RING_LEN: 327, // circumference of the r=52 score ring
  _el: null,
  _opener: null,
  _timers: [],
  _raf: 0,
  _audio: null,

  // ─── Pure helpers (unit-tested) ───
  formatDuration(ms) {
    const mins = Math.round(ms / 60000);
    if (!(mins >= 1)) return 'Under a minute';
    if (mins < 60) return `${mins} min`;
    const h = Math.floor(mins / 60), r = mins % 60;
    return r ? `${h} h ${r} min` : `${h} h`;
  },

  // Modules where at least one question was missed, worst first.
  missedModules(breakdown) {
    return (breakdown || [])
      .filter(m => m.correct < m.total)
      .sort((a, z) => a.correct / a.total - z.correct / z.total);
  },

  // The assigned course to suggest next: not yet passed, soonest due date first.
  nextUp(assignments, completions, currentId) {
    const done = new Set((completions || []).filter(c => c.passed).map(c => c.course_id));
    const dueOf = a => {
      if (!a.due_at) return Infinity;
      const t = isNaN(a.due_at) ? new Date(a.due_at).getTime() : a.due_at * 1000;
      return t || Infinity;
    };
    return (assignments || [])
      .filter(a => a.course_id !== currentId && !done.has(a.course_id))
      .sort((a, z) => dueOf(a) - dueOf(z))[0] || null;
  },

  // Facts for the stats strip under the score.
  stats(res, elapsedMs) {
    const total = (res.breakdown || []).reduce((n, m) => n + m.total, 0);
    const right = (res.breakdown || []).reduce((n, m) => n + m.correct, 0);
    const out = [];
    if (total) out.push({ label: 'Correct answers', value: `${right} of ${total}` });
    out.push({ label: 'Attempt', value: res.attempt > 1 ? `Attempt ${res.attempt}` : 'First try' });
    if (elapsedMs > 0) out.push({ label: 'Time this session', value: Celebrate.formatDuration(elapsedMs) });
    return out;
  },

  // ─── Preferences, motion, feedback ───
  reducedMotion() { return !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches); },
  soundOn() { try { return localStorage.getItem(Celebrate.SOUND_KEY) === '1'; } catch { return false; } },
  setSound(on) { try { localStorage.setItem(Celebrate.SOUND_KEY, on ? '1' : '0'); } catch {} },

  _cssColor(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); },

  _chime() {
    if (!Celebrate.soundOn()) return;
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      const ctx = Celebrate._audio || (Celebrate._audio = new Ctx());
      if (ctx.state === 'suspended') ctx.resume();
      [523.25, 659.25, 783.99].forEach((freq, i) => {
        const osc = ctx.createOscillator(), gain = ctx.createGain();
        const t = ctx.currentTime + i * 0.14;
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.0001, t);
        gain.gain.exponentialRampToValueAtTime(0.12, t + 0.03);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.5);
        osc.connect(gain).connect(ctx.destination);
        osc.start(t); osc.stop(t + 0.55);
      });
    } catch {}
  },

  _confetti() {
    if (typeof confetti !== 'function') return;
    const colors = ['--brand', '--brand-secondary', '--brand-accent'].map(Celebrate._cssColor).filter(Boolean);
    const base = { colors, disableForReducedMotion: true, zIndex: 400 };
    confetti({ ...base, particleCount: 90, spread: 70, origin: { x: 0.2, y: 0.7 }, angle: 60 });
    confetti({ ...base, particleCount: 90, spread: 70, origin: { x: 0.8, y: 0.7 }, angle: 120 });
    Celebrate._later(() => confetti({ ...base, particleCount: 120, spread: 100, startVelocity: 35, origin: { y: 0.55 } }), 350);
  },

  _later(fn, ms) { Celebrate._timers.push(setTimeout(fn, ms)); },

  // Count the number up while the ring fills; the ring itself is a CSS transition.
  _countUp(node, target, ms) {
    if (Celebrate.reducedMotion() || target <= 0) { node.textContent = target + '%'; return; }
    const start = performance.now();
    const tick = now => {
      const p = Math.min(1, (now - start) / ms);
      node.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))) + '%';
      if (p < 1) Celebrate._raf = requestAnimationFrame(tick);
    };
    Celebrate._raf = requestAnimationFrame(tick);
  },

  // ─── Overlay lifecycle ───
  _open(html) {
    Celebrate.close(true);
    Celebrate._opener = document.activeElement;
    const el = document.createElement('div');
    el.id = 'celebrate';
    el.className = 'celebrate';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    el.setAttribute('aria-labelledby', 'cel-title');
    el.innerHTML = `<div class="cel-card">${html}</div>`;
    el.addEventListener('keydown', Celebrate._onKey);
    document.body.appendChild(el);
    Celebrate._el = el;
    return el;
  },

  _onKey(e) {
    if (e.key === 'Escape') { e.stopPropagation(); Celebrate.done(); return; }
    if (e.key !== 'Tab') return;
    const items = [...Celebrate._el.querySelectorAll('button:not([disabled])')];
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  },

  close(quiet) {
    Celebrate._timers.forEach(clearTimeout); Celebrate._timers = [];
    cancelAnimationFrame(Celebrate._raf);
    if (Celebrate._el) { Celebrate._el.remove(); Celebrate._el = null; }
    if (!quiet && Celebrate._opener && Celebrate._opener.isConnected) Celebrate._opener.focus();
  },

  // Leave the ceremony and go back to the course list.
  done() { Celebrate.close(); App.exitCourse(); },

  _calcHtml(text) {
    return `<div class="cel-calc" role="status"><div class="cel-spinner" aria-hidden="true"></div><div id="cel-title" class="cel-calc-text">${esc(text)}</div></div>`;
  },

  _ringHtml(cls) {
    return `<div class="cel-ring ${cls}" aria-hidden="true">
      <svg viewBox="0 0 120 120"><circle class="cel-ring-track" cx="60" cy="60" r="52"/><circle class="cel-ring-fill" cx="60" cy="60" r="52" style="stroke-dasharray:${Celebrate.RING_LEN};stroke-dashoffset:${Celebrate.RING_LEN};"/></svg>
      <div class="cel-ring-num">0%</div>
    </div>`;
  },

  _fillRing(root, score) {
    const fill = root.querySelector('.cel-ring-fill');
    const num = root.querySelector('.cel-ring-num');
    const reduced = Celebrate.reducedMotion();
    if (reduced) fill.style.transition = 'none';
    // Next frame so the browser registers the starting offset before the transition.
    requestAnimationFrame(() => { fill.style.strokeDashoffset = String(Celebrate.RING_LEN * (1 - score / 100)); });
    Celebrate._countUp(num, score, 900);
  },

  // What the result screen needs beyond the score: the next assigned course and any new badges.
  async _context(courseId, certId) {
    if (window._adminPreview || Learner._preview) return { next: null, badges: [] };
    try {
      const [assigned, comps, courses] = await Promise.all([
        learnerApi('/api/assignments/me'),
        learnerApi('/api/completions/me').catch(() => []),
        learnerApi('/api/courses').catch(() => [])
      ]);
      return {
        next: Celebrate.nextUp(assigned, comps, courseId),
        badges: Milestones.fresh(comps.filter(c => c.cert_id !== certId), comps, courses)
      };
    } catch { return { next: null, badges: [] }; }
  },

  _soundToggleHtml() {
    const on = Celebrate.soundOn();
    return `<button type="button" class="btn btn-ghost btn-sm cel-sound" aria-pressed="${on}" onclick="Celebrate.toggleSound(this)">Sound ${on ? 'on' : 'off'}</button>`;
  },

  toggleSound(btn) {
    const on = !Celebrate.soundOn();
    Celebrate.setSound(on);
    btn.setAttribute('aria-pressed', String(on));
    btn.textContent = `Sound ${on ? 'on' : 'off'}`;
    if (on) Celebrate._chime();
  },

  // ─── Pass ───
  async showPass({ res, course, learner, elapsedMs, onCertificate }) {
    const reduced = Celebrate.reducedMotion();
    const el = Celebrate._open(Celebrate._calcHtml('Checking your answers…'));
    const { next, badges } = await Celebrate._context(course.id, res.cert_id);
    if (!reduced) await new Promise(r => Celebrate._later(r, 900));
    if (Celebrate._el !== el) return; // dismissed while waiting

    const stats = Celebrate.stats(res, elapsedMs).map((s, i) =>
      `<div class="cel-stat cel-rise" style="--i:${i + 3}"><div class="cel-stat-val">${esc(s.value)}</div><div class="cel-stat-label">${esc(s.label)}</div></div>`).join('');
    const perfect = res.score === 100;
    el.querySelector('.cel-card').innerHTML = `
      ${Celebrate._ringHtml('cel-pass')}
      <div class="cel-eyebrow cel-rise" style="--i:1">${perfect ? 'Perfect score' : 'Course complete'}</div>
      <h2 id="cel-title" class="cel-title cel-rise" style="--i:2">Well done, ${esc(learner.name)}.</h2>
      <p class="cel-sub cel-rise" style="--i:2">You earned a certificate for <strong>${esc(course.title)}</strong>.</p>
      <div class="cel-stats">${stats}</div>
      ${badges.length ? `<div class="cel-badges cel-rise" style="--i:5"><div class="cel-badges-title">New badge${badges.length > 1 ? 's' : ''} unlocked</div>${Milestones.chipsHtml(badges)}</div>` : ''}
      <div class="cel-actions cel-rise" style="--i:6">
        <button type="button" class="btn btn-primary btn-lg" id="cel-cert">View your certificate</button>
        ${next ? `<button type="button" class="btn btn-outline" id="cel-next">Next up: ${esc(next.course_title || 'your next course')}</button>` : ''}
        <button type="button" class="btn btn-ghost" id="cel-back">${next ? 'Back to courses' : 'Back to courses — you’re all caught up'}</button>
      </div>
      <div class="cel-foot">${Celebrate._soundToggleHtml()}<span class="cel-id">Certificate ID ${esc(res.cert_id)}</span></div>`;
    el.querySelector('#cel-cert').onclick = onCertificate;
    el.querySelector('#cel-back').onclick = Celebrate.done;
    const nextBtn = el.querySelector('#cel-next');
    if (nextBtn) nextBtn.onclick = () => { Celebrate.close(true); Learner.startCourse(next.course_id); };
    Celebrate._fillRing(el, res.score);
    el.querySelector('#cel-cert').focus();
    Celebrate._later(Celebrate._confetti, reduced ? 0 : 500);
    Celebrate._later(Celebrate._chime, reduced ? 0 : 500);
    if (!reduced && navigator.vibrate) navigator.vibrate([30, 40, 60]);
  },

  // ─── Fail ───
  showFail({ res, course, passMark, onRetry }) {
    const missed = Celebrate.missedModules(res.breakdown);
    const gap = passMark - res.score;
    const list = missed.length
      ? `<div class="cel-missed"><div class="cel-missed-title">Worth another look</div>${missed.map(m =>
          `<div class="cel-missed-row"><span>${esc(m.title)}</span><span>${m.correct} of ${m.total} correct</span></div>`).join('')}</div>`
      : '';
    const el = Celebrate._open(`
      ${Celebrate._ringHtml('cel-fail')}
      <div class="cel-eyebrow cel-rise" style="--i:1">Not quite yet</div>
      <h2 id="cel-title" class="cel-title cel-rise" style="--i:2">${gap <= 10 ? 'So close.' : 'Keep going.'}</h2>
      <p class="cel-sub cel-rise" style="--i:2">You scored ${res.score}% on <strong>${esc(course.title)}</strong>. The pass mark is ${passMark}%, so you need ${gap} more point${gap === 1 ? '' : 's'}. You can retake it whenever you’re ready.</p>
      ${list}
      <div class="cel-actions cel-rise" style="--i:4">
        <button type="button" class="btn btn-primary btn-lg" id="cel-retry">Retake the course</button>
        <button type="button" class="btn btn-ghost" id="cel-back">Back to courses</button>
      </div>`);
    el.querySelector('#cel-retry').onclick = onRetry;
    el.querySelector('#cel-back').onclick = Celebrate.done;
    Celebrate._fillRing(el, res.score);
    el.querySelector('#cel-retry').focus();
  }
};
