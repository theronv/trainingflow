// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Learner Experience & Quiz Engine
// ══════════════════════════════════════════════════════════

const Learner = {
  _prog: null, // { course_id, module_idx, modules: [{mi, passed, score}] }
  _navSeq: 0,
  _preview: null, // { api, back } while an admin/manager is viewing the learner experience

  // Admins and managers have no learner session, so "Learner view" is a read-only preview
  // of the catalogue and course player using their own token. Nothing is saved.
  enterPreview() {
    const isAdmin = !!getToken();
    Learner._preview = { api: isAdmin ? adminApi : managerApi, back: isAdmin ? 'screen-admin' : 'screen-manager' };
    curLearner = { id: 'preview', name: isAdmin ? 'Admin preview' : 'Manager preview' };
    const btn = $$('l-signout-btn'); if (btn) btn.textContent = 'Exit preview';
    const acct = $$('ln-account'); if (acct) acct.classList.add('hidden');
    Learner.init();
  },
  exitPreview() {
    const back = Learner._preview ? Learner._preview.back : 'screen-landing';
    Learner._preview = null; curLearner = null; curCourse = null; curModIdx = 0; quizSt = {};
    window._adminPreview = false;
    const btn = $$('l-signout-btn'); if (btn) btn.textContent = 'Sign Out';
    const acct = $$('ln-account'); if (acct) acct.classList.remove('hidden');
    App.show(back);
  },

  init() {
    App.show('screen-learner');
    // Hide the sign-in panel and reveal the user pill
    const loginPanel = $$('lp-name');
    if(loginPanel) { loginPanel.classList.add('hidden'); loginPanel.classList.remove('active'); }
    const pill = $$('l-user-pill');
    if(pill) pill.style.display = '';
    $$('l-name-display').textContent = curLearner.name;
    $$('l-avatar').textContent = curLearner.name[0];
    // Clear any leftover login error / fields
    const err = $$('l-login-error'); if(err) { err.style.display = 'none'; err.textContent = ''; }
    const ni = $$('learner-name-input'); if(ni) ni.value = '';
    const pi = $$('learner-pw-input'); if(pi) pi.value = '';
    Learner.nav('courses');
  },

  nav(p) {
    Learner._navSeq++;
    ['courses','progress','certs','account'].forEach(k => {
      if($$(`ln-${k}`)) $$(`ln-${k}`).classList.toggle('active', k===p);
      const lp = $$(`lp-${k}`);
      if(lp) { lp.classList.toggle('hidden', k!==p); lp.classList.toggle('active', k===p); }
    });
    if(p==='courses') Learner.renderCourses();
    if(p==='progress') Learner.renderProgress();
    if(p==='certs') Learner.renderCerts();
    if(p==='account' && curLearner) { const n = $$('lcp-name'); if(n) n.value = curLearner.name || ''; }
  },

  // ─── COURSES ───
  async renderCourses() {
    const seq = Learner._navSeq;
    const grid = $$('l-courses-grid'); if(!grid) return;
    grid.innerHTML = Skeleton.cards(4);
    try {
      const pv = Learner._preview;
      const [apiCourses, apiRecs, apiAssigns, apiProgress, apiSections] = pv
        ? await Promise.all([pv.api('/api/courses'), [], [], [], pv.api('/api/sections').catch(() => [])])
        : await Promise.all([
            learnerApi('/api/courses'),
            learnerApi('/api/completions/me').catch(() => []),
            learnerApi('/api/assignments/me').catch(() => []),
            learnerApi('/api/progress/me').catch(() => []),
            learnerApi('/api/sections').catch(() => [])
          ]);
      if (Learner._navSeq !== seq) return;
      const recs = apiRecs.map(normRecord);
      const sections = orderSections(apiSections || []);

      if (!apiCourses.length) {
        grid.innerHTML = '<div class="empty" style="grid-column:1/-1;"><div class="empty-icon">' + ICON.book + '</div><div class="empty-title">No training assigned yet</div><div class="empty-hint">Your manager will add courses to your plan. Check back soon — or let them know you\'re ready to start.</div></div>';
        return;
      }

      const isPassed = id => recs.some(r => r.cid === id && r.passed);
      const progOf = id => !isPassed(id) && apiProgress.find(p => p.course_id === id);
      // Started but not passed, most recently touched first: these go in their own section at the top.
      const resumeCourses = apiCourses
        .filter(c => progOf(normCourse(c).id))
        .sort((a, z) => (progOf(normCourse(z).id).updated_at || 0) - (progOf(normCourse(a).id).updated_at || 0));
      const resumeIds = new Set(resumeCourses.map(c => normCourse(c).id));

      const renderCard = (c, resume = false) => {
        const nc = normCourse(c);
        const assignment = apiAssigns.find(a => a.course_id === nc.id);
        const assigned = !!assignment;
        const best = recs.filter(r => r.cid === nc.id).sort((a,z) => z.score - a.score)[0];
        const passed = best && best.passed;
        const prog = !passed && apiProgress.find(p => p.course_id === nc.id);
        const modsDone = prog ? prog.modules.length : 0;
        const totalMods = nc.mods ? nc.mods.length : null;
        const dueTs = assignment && assignment.due_at
          ? (isNaN(assignment.due_at) ? new Date(assignment.due_at).getTime() : assignment.due_at * 1000)
          : null;
        const overdue = !passed && dueTs && dueTs < Date.now();
        const dueStr = !passed && dueTs && !overdue
          ? `Due ${new Date(dueTs).toLocaleDateString()}`
          : '';
        let chip = '';
        if (passed) chip = '<span class="chip chip-green">Passed</span>';
        else if (overdue) chip = `<span class="chip chip-red">Overdue</span>`;
        else if (prog) chip = `<span class="chip chip-blue">In progress${totalMods ? ` · ${modsDone}/${totalMods}` : ''}</span>`;
        else if (assigned) chip = `<span class="chip chip-brand-secondary">Mandatory</span>`;
        const modCount = totalMods ? `${totalMods} module${totalMods!==1?'s':''}` : '';
        const desc = nc.desc ? `<div class="lc-desc">${esc(nc.desc)}</div>` : '';
        const pct = prog && totalMods ? Math.min(100, Math.round(modsDone / totalMods * 100)) : 0;
        const bar = prog && totalMods ? `<div class="lc-progress" aria-hidden="true"><span style="width:${pct}%"></span></div>` : '';
        const cta = passed ? 'Review' : (prog ? 'Continue' : 'Start');
        return `<div class="course-card lc${resume ? ' lc-resume' : ''}" role="button" tabindex="0" onclick="Learner.startCourse('${nc.id}')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();Learner.startCourse('${nc.id}')}">
          <div class="lc-top">
            <div class="lc-icon" aria-hidden="true">${courseIcon(nc.icon)}</div>
            <div class="lc-body">
              <div class="lc-title">${esc(nc.title)}</div>
              <div class="lc-meta">${resume && totalMods ? `Module ${Math.min((prog.module_idx || 0) + 1, totalMods)} of ${totalMods}` : modCount}${dueStr ? ` · ${dueStr}` : ''}</div>
            </div>
          </div>
          ${desc}
          ${bar}
          <div class="lc-foot">
            <span>${chip}</span>
            <span class="lc-cta">${resume ? 'Continue where you left off' : cta} <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg></span>
          </div>
        </div>`;
      };

      let html = '';
      if (resumeCourses.length) {
        html += `<div class="section-header" style="grid-column:1/-1;">Continue where you left off</div>`;
        html += resumeCourses.map(c => renderCard(c, true)).join('');
      }
      const restCourses = apiCourses.filter(c => !resumeIds.has(normCourse(c).id));
      if(sections.length) {
        const bySec = {};
        const unsec = [];
        sections.forEach(s => { bySec[s.id] = []; });
        restCourses.forEach(c => {
          if(c.section_id && bySec[c.section_id]) bySec[c.section_id].push(c);
          else unsec.push(c);
        });
        sections.forEach(s => {
          if(!bySec[s.id].length) return;
          html += `<div class="section-header" style="grid-column:1/-1;">${esc(s.label)}</div>`;
          html += bySec[s.id].map(c => renderCard(c)).join('');
        });
        if(unsec.length) {
          html += `<div class="section-header" style="grid-column:1/-1;">Other</div>`;
          html += unsec.map(c => renderCard(c)).join('');
        }
      } else {
        html += restCourses.map(c => renderCard(c)).join('');
      }
      grid.innerHTML = html || '<div class="empty" style="grid-column:1/-1;"><div class="empty-icon">' + ICON.book + '</div><div class="empty-title">No training assigned yet</div><div class="empty-hint">Your manager will add courses to your plan. Check back soon — or let them know you\'re ready to start.</div></div>';
    } catch(e) {
      grid.innerHTML = `<div class="card" style="grid-column:1/-1;color:var(--fail);">${esc(e.message)}</div>`;
    }
  },

  // ─── PROGRESS ───
  async renderProgress() {
    const seq = Learner._navSeq;
    const el = $$('l-progress-content'); if(!el) return;
    if (Learner._preview) {
      el.innerHTML = '<div class="empty"><div class="empty-icon">' + ICON.clip + '</div><div class="empty-title">Nothing to show in preview</div><div class="empty-hint">Assignments and progress are tracked per learner. Sign in as a learner to see them.</div></div>';
      return;
    }
    el.innerHTML = Skeleton.list(3);
    try {
      const [assigned, completions, progress, courses] = await Promise.all([
        learnerApi('/api/assignments/me'),
        learnerApi('/api/completions/me').catch(() => []),
        learnerApi('/api/progress/me').catch(() => []),
        learnerApi('/api/courses').catch(() => [])
      ]);
      if (Learner._navSeq !== seq) return;
      // Courses the learner has started count even if nobody assigned them.
      const assignments = [...(assigned || [])];
      (progress || []).forEach(p => {
        if (assignments.some(a => a.course_id === p.course_id)) return;
        const c = (courses || []).find(x => x.id === p.course_id);
        if (c) assignments.push({ course_id: p.course_id, course_title: c.title, due_at: null });
      });
      if (!assignments.length) {
        el.innerHTML = '<div class="empty"><div class="empty-icon">' + ICON.clip + '</div><div class="empty-title">No training assigned yet</div><div class="empty-hint">Check back later, or contact your manager to get started.</div></div>';
        return;
      }
      const passedCourseIds = new Set((completions || []).filter(c => c.passed).map(c => c.course_id));
      const progOf = id => (progress || []).find(p => p.course_id === id);
      const pending = assignments.filter(a => !passedCourseIds.has(a.course_id))
        .sort((a, z) => ((progOf(z.course_id) || {}).updated_at || 0) - ((progOf(a.course_id) || {}).updated_at || 0));
      const done = assignments.filter(a => passedCourseIds.has(a.course_id));
      let html = '';
      if (pending.length) {
        html += `<div style="font-weight:700;margin-bottom:var(--space-3);">To Do (${pending.length})</div>`;
        html += pending.map(a => {
          const overdue = a.due_at && (new Date(a.due_at).getTime() || a.due_at * 1000) < Date.now();
          const dueTs = a.due_at ? (isNaN(a.due_at) ? new Date(a.due_at).getTime() : a.due_at * 1000) : null;
          const dueStr = dueTs ? `<span style="font-size:var(--text-xs);color:${overdue ? 'var(--fail)' : 'var(--ink-4)'};">Due ${new Date(dueTs).toLocaleDateString()}</span>` : '';
          return `<div class="card" style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-3);margin-bottom:var(--space-3);">
            <div>
              <div style="font-weight:600;">${esc(a.course_title)}</div>
              ${progOf(a.course_id) ? '<span class="chip chip-blue">In progress</span> ' : ''}${dueStr}
            </div>
            <button class="btn btn-primary btn-sm" onclick="Learner.startCourse('${a.course_id}')">${progOf(a.course_id) ? 'Continue' : 'Start'} →</button>
          </div>`;
        }).join('');
      }
      if (done.length) {
        html += `<div style="font-weight:700;margin-bottom:var(--space-3);margin-top:var(--space-6);">Completed (${done.length})</div>`;
        html += done.map(a => `<div class="card" style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-3);margin-bottom:var(--space-3);opacity:0.75;">
          <div style="font-weight:600;">${esc(a.course_title)}</div>
          <span class="chip chip-green">✓ Done</span>
        </div>`).join('');
      }
      el.innerHTML = html;
    } catch(e) { el.innerHTML = `<div class="card" style="color:var(--fail);">${esc(e.message)}</div>`; }
  },

  // ─── CERTS ───
  _certsCache: [],
  async renderCerts() {
    const seq = Learner._navSeq;
    if (Learner._preview) {
      $$('l-certs-content').innerHTML = '<div class="empty"><div class="empty-icon">' + ICON.award + '</div><div class="empty-title">Nothing to show in preview</div><div class="empty-hint">Certificates are issued to learners who pass a course.</div></div>';
      return;
    }
    try {
      const res = await learnerApi('/api/completions/me');
      if (Learner._navSeq !== seq) return;
      Learner._certsCache = (res || []).filter(r => r.passed);
      $$('l-certs-content').innerHTML = Learner._certsCache.length
        ? Learner._certsCache.map(r => `<div class="card" style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-3);margin-bottom:var(--space-3);">
            <div>
              <div style="font-weight:600;">${esc(r.course_title)}</div>
              <div style="font-size:var(--text-xs);color:var(--ink-4);margin-top:4px;">Passed ${r.score}% · ${new Date(r.completed_at*1000).toLocaleDateString()} · ID: <span style="font-family:monospace;">${r.cert_id || '—'}</span></div>
            </div>
            <button class="btn btn-outline btn-sm" onclick="Learner.viewCert('${r.cert_id}')">↓ Download PDF</button>
          </div>`).join('')
        : '<div class="empty"><div class="empty-icon">' + ICON.award + '</div><div class="empty-title">No certificates yet</div><div class="empty-hint">Complete a course and pass its quiz to earn your first certificate.</div></div>';
    } catch(e) { $$('l-certs-content').innerHTML = `<div class="card" style="color:var(--fail);">${esc(e.message)}</div>`; }
  },

  // ─── QUIZ ENGINE ───
  async startCourse(cid) {
    try {
      const pv = Learner._preview;
      if (pv) window._adminPreview = true; // local grading, nothing saved, exit returns to the preview list
      const [res, progList] = pv
        ? [await pv.api(`/api/courses/${cid}`), []]
        : await Promise.all([
            learnerApi(`/api/courses/${cid}`),
            learnerApi('/api/progress/me').catch(() => [])
          ]);
      curCourse = normCourse(res);
      quizSt = {};
      Learner._prog = progList.find(p => p.course_id === cid) || { course_id: cid, module_idx: 0, modules: [] };

      App.show('screen-course');
      // Populate module sidebar
      $$('mod-nav-list').innerHTML = curCourse.mods.map((m, i) => `
        <div class="mod-item" id="mod-nav-${i}" onclick="Learner.loadMod(${i})">
          <span class="mod-bullet" id="mod-bullet-${i}">${i + 1}</span>
          <div class="mod-item-body">
            <div class="mod-item-title">${esc(m.title)}</div>
            ${m.summary ? `<div class="mod-item-summary">${esc(m.summary.length > 65 ? m.summary.slice(0, 65) + '…' : m.summary)}</div>` : ''}
          </div>
        </div>`).join('');
      $$('ch-meta').textContent = esc(curCourse.title);

      // Restore completed module state in sidebar
      Learner._prog.modules.forEach(({ mi, passed }) => {
        const item = $$(`mod-nav-${mi}`);
        const bullet = $$(`mod-bullet-${mi}`);
        if(item)   item.classList.add(passed ? 'done-pass' : 'done-fail');
        if(bullet) bullet.textContent = passed ? '✓' : '✗';
      });

      // Resume from last saved module
      Learner.loadMod(Learner._prog.module_idx);
    } catch(e) { Toast.err(e.message); }
  },

  loadMod(mi) {
    curModIdx = mi;
    const mod = curCourse.mods[mi];
    // Update sidebar active state
    curCourse.mods.forEach((_, i) => {
      const item = $$(`mod-nav-${i}`);
      if(item) item.classList.toggle('active', i === mi);
    });
    // On phones the module list is a horizontal strip: keep the current module in view.
    const cur = $$(`mod-nav-${mi}`);
    if (cur && cur.parentElement) cur.parentElement.scrollTo({ left: Math.max(0, cur.offsetLeft - 16), behavior: 'smooth' });
    // Update progress bar
    const pct = Math.round((mi / curCourse.mods.length) * 100);
    if($$('ch-prog')) $$('ch-prog').style.width = pct + '%';
    if($$('ch-label')) $$('ch-label').textContent = `Module ${mi + 1} of ${curCourse.mods.length}`;

    const hasQuiz = mod.questions && mod.questions.length > 0;
    const refUrl = mod.refUrl || curCourse.refUrl || '';

    // "Read This First" source banner
    const sourceBanner = refUrl ? `
      <div class="source-banner">
        <div class="source-banner-icon">${ICON.book}</div>
        <div class="source-banner-body">
          <div class="source-banner-label">Before You Begin</div>
          <div class="source-banner-text">This module is based on official source material. Reading it before the competency check will help you answer questions accurately.</div>
        </div>
        <a href="${esc(refUrl)}" target="_blank" rel="noopener noreferrer" class="source-banner-link">Open Source Material →</a>
      </div>` : '';

    // Overview card: summary + objectives + meta
    const wordCount = (mod.content || '').trim().split(/\s+/).filter(Boolean).length;
    const readMin = Math.max(1, Math.ceil(wordCount / 200));
    const objectivesHtml = mod.objectives && mod.objectives.length ? `
      <div class="mod-objectives">
        <div class="mod-objectives-label">What You'll Learn</div>
        <ul>${mod.objectives.map(o => `<li>${esc(o)}</li>`).join('')}</ul>
      </div>` : '';
    const overviewCard = (mod.summary || (mod.objectives && mod.objectives.length) || hasQuiz) ? `
      <div class="mod-overview-card">
        ${mod.summary ? `<p class="mod-summary-text">${esc(mod.summary)}</p>` : ''}
        ${objectivesHtml}
        <div class="mod-meta-row">
          <span class="mod-meta-chip">~${readMin} min read</span>
          ${hasQuiz ? `<span class="mod-meta-chip">${mod.questions.length} question${mod.questions.length !== 1 ? 's' : ''}</span>` : ''}
        </div>
      </div>` : '';

    // Render content with markdown parser
    const contentHtml = typeof marked !== 'undefined' ? marked.parse(mod.content || '') : (mod.content || '');

    $$('mod-main').innerHTML = `<div class="module-prose">
      ${sourceBanner}
      <h2>${esc(mod.title)}</h2>
      ${overviewCard}
      <div class="prose-content">${contentHtml}</div>
      ${hasQuiz
        ? `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-6);" onclick="Learner.startQuiz(${mi})">Start Competency Check →</button>`
        : `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-8);" onclick="Learner.finishMod(${mi})">Continue →</button>`}
    </div>`;
  },

  startQuiz(mi) {
    quizSt[mi] = { ans: [] };
    const nav = $$('mod-nav-list');
    if (nav) { nav.style.pointerEvents = 'none'; nav.style.opacity = '0.5'; nav.title = 'Complete the quiz to navigate modules'; }
    Learner.renderQ(mi, 0);
  },

  renderQ(mi, qi) {
    const q = curCourse.mods[mi].questions[qi];
    const total = curCourse.mods[mi].questions.length;
    const letters = ['A','B','C','D'];
    $$('mod-main').innerHTML = `<div class="quiz-wrap">
      <div class="quiz-header">
        <div class="quiz-step">Question ${qi + 1} of ${total}</div>
        <div class="quiz-q">${esc(q.question)}</div>
      </div>
      <div class="quiz-options">
        ${q.options.filter(o => o).map((o, i) => `
          <button class="quiz-opt" onclick="Learner.answer(${mi},${qi},${i})">
            <span class="opt-letter">${letters[i]}</span>
            ${esc(o)}
          </button>`).join('')}
      </div>
    </div>`;
  },

  async answer(mi, qi, sel) {
    const q = curCourse.mods[mi].questions[qi];
    const total = curCourse.mods[mi].questions.length;
    const buttons = $$('mod-main').querySelectorAll('.quiz-opt');
    buttons.forEach(btn => { btn.disabled = true; });

    // Grading is server-side — the answer key is never sent to learners. Admin preview has no
    // learner session and already holds the key locally. (Demo grades through its in-memory API.)
    let ok, correctIndex, explanation;
    if (window._adminPreview) {
      if (typeof q.correct_index !== 'number') {
        buttons.forEach(btn => { btn.disabled = false; });
        return Toast.info('Quizzes can only be graded in an admin preview or a learner account.');
      }
      correctIndex = q.correct_index;
      ok = sel === correctIndex;
      explanation = q.explanation;
    } else {
      try {
        const r = await learnerApi('/api/quiz/answer', { method: 'POST', body: JSON.stringify({ question_id: q.id, selected_index: sel }) });
        ok = r.correct; correctIndex = r.correct_index; explanation = r.explanation;
      } catch (e) {
        buttons.forEach(btn => { btn.disabled = false; });
        return Toast.err(e.message || 'Could not submit your answer. Please try again.');
      }
    }
    quizSt[mi].ans.push({ question_id: q.id, ok, correct_index: correctIndex, explanation });

    // Mark all option buttons
    buttons.forEach((btn, i) => {
      const letter = btn.querySelector('.opt-letter');
      if(i === sel) {
        btn.classList.add(ok ? 'correct' : 'wrong');
        if(letter) letter.classList.add(ok ? 'correct' : 'wrong');
      }
      if(i === correctIndex && !ok) {
        btn.classList.add('correct');
        if(letter) letter.classList.add('correct');
      }
    });

    // Inject feedback panel + next button
    const wrap = $$('mod-main').querySelector('.quiz-wrap');
    if(wrap) {
      const isLast = qi + 1 >= total;
      const nextLabel = isLast ? 'See Results' : `Next Question →`;
      const nextFn = isLast
        ? `Learner.showModResults(${mi})`
        : `Learner.renderQ(${mi},${qi+1})`;
      const fb = document.createElement('div');
      fb.className = `quiz-feedback ${ok ? 'fb-pass' : 'fb-fail'}`;
      fb.innerHTML = `
        <div class="fb-icon">${ok ? '✓' : '✗'}</div>
        <div class="fb-body">
          <div class="fb-verdict">${ok ? 'Correct!' : 'Incorrect'}</div>
          ${explanation ? `<div class="fb-exp">${esc(explanation)}</div>` : ''}
        </div>
        <button class="btn btn-primary fb-next" onclick="${nextFn}">${nextLabel}</button>`;
      wrap.appendChild(fb);
    }
  },

  async showModResults(mi) {
    const nav = $$('mod-nav-list');
    if (nav) { nav.style.pointerEvents = ''; nav.style.opacity = ''; nav.title = ''; }
    const answers = quizSt[mi].ans;
    const correct = answers.filter(a => a.ok).length;
    const total = answers.length;
    const pct = total > 0 ? Math.round((correct / total) * 100) : 100;
    const passed = pct >= (brandCache.pass || 80);

    // Update sidebar bullet
    const item = $$(`mod-nav-${mi}`);
    const bullet = $$(`mod-bullet-${mi}`);
    if(item)   item.classList.add(passed ? 'done-pass' : 'done-fail');
    if(bullet) bullet.textContent = passed ? '✓' : '✗';

    const nextMod = mi + 1 < curCourse.mods.length;
    const questions = curCourse.mods[mi].questions;
    const reviewHtml = `
      <div class="qr-review">
        <div class="qr-review-title">Question Review</div>
        ${answers.map((a, idx) => {
          const q = questions[idx];
          if (!q) return '';
          return `<div class="qr-review-item ${a.ok ? 'qr-item-pass' : 'qr-item-fail'}">
            <div class="qr-review-status">${a.ok ? '✓' : '✗'}</div>
            <div class="qr-review-body">
              <div class="qr-review-q">${esc(q.question)}</div>
              ${!a.ok ? `<div class="qr-review-correct">Correct answer: <strong>${esc(q.options[a.correct_index] || '')}</strong></div>` : ''}
              ${a.explanation ? `<div class="qr-review-exp">${esc(a.explanation)}</div>` : ''}
            </div>
          </div>`;
        }).join('')}
      </div>`;

    $$('mod-main').innerHTML = `<div class="quiz-results">
      <div class="qr-score ${passed ? 'qr-pass' : 'qr-fail'}">${pct}%</div>
      <div class="qr-label">${correct} of ${total} correct</div>
      <div class="qr-verdict">${passed ? 'Module passed' : 'Not quite — review the material and try again.'}</div>
      ${nextMod
        ? `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-6);" onclick="Learner.loadMod(${mi+1})">Next Module →</button>`
        : `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-6);" onclick="Learner.completeCourse()">Finish Course 🎓</button>`}
      ${!passed ? `<button class="btn btn-outline btn-lg" style="margin-top:var(--space-3);" onclick="Learner.retryMod(${mi})">Retry Module</button>` : ''}
      ${reviewHtml}
    </div>`;

    // Save progress after every quiz module (pass or fail)
    await Learner._saveProgress(mi, passed, pct);
  },

  retryMod(mi) {
    quizSt[mi] = { ans: [] };
    const nav = $$('mod-nav-list');
    if (nav) { nav.style.pointerEvents = 'none'; nav.style.opacity = '0.5'; nav.title = 'Complete the quiz to navigate modules'; }
    Learner.renderQ(mi, 0);
  },

  async finishMod(mi) {
    // Mark non-quiz modules done in sidebar
    const item = $$(`mod-nav-${mi}`);
    const bullet = $$(`mod-bullet-${mi}`);
    if(item)   item.classList.add('done-pass');
    if(bullet) bullet.textContent = '✓';

    await Learner._saveProgress(mi, true, 100);

    if(mi + 1 < curCourse.mods.length) Learner.loadMod(mi + 1);
    else Learner.completeCourse();
  },

  async _saveProgress(mi, passed, score) {
    if(!curLearner || !curCourse || window._adminPreview) return;
    const prog = Learner._prog;
    // Update or insert this module's record
    const existing = prog.modules.findIndex(m => m.mi === mi);
    if(existing >= 0) prog.modules[existing] = { mi, passed, score };
    else prog.modules.push({ mi, passed, score });
    // Advance the resume pointer to the next unfinished module
    prog.module_idx = Math.max(prog.module_idx, mi + 1);
    try {
      await learnerApi('/api/progress', {
        method: 'POST',
        body: JSON.stringify({ course_id: curCourse.id, module_idx: prog.module_idx, modules: prog.modules })
      });
    } catch(e) { console.warn('Progress save failed:', e.message); }
  },

  async completeCourse() {
    if (window._adminPreview) { App.exitCourse(); return; }
    // The score and pass/fail are computed server-side from the answers submitted during the quizzes.
    let res;
    try {
      res = await learnerApi('/api/completions', { method:'POST', body: JSON.stringify({ course_id: curCourse.id }) });
    } catch (e) { return Toast.err(e.message || 'Could not complete the course.'); }
    const score = res.score;
    if (!res.passed) {
      Toast.err(`You scored ${score}% — the pass mark is ${brandCache.pass || 80}%. Review the modules and try again.`);
      learnerApi(`/api/progress/${curCourse.id}`, { method: 'DELETE' }).catch(() => {});
      Learner._prog = null;
      App.exitCourse();
      return;
    }

    // Clear progress record now that the course is done
    learnerApi(`/api/progress/${curCourse.id}`, { method: 'DELETE' }).catch(() => {});
    Learner._prog = null;

    confetti({ particleCount: 150, spread: 70, origin: { y: 0.6 } });
    
    // Fully populate certificate
    const b = typeof brandCache !== 'undefined' ? brandCache : { name: CONFIG.DEFAULT_BRAND_NAME };
    const l = typeof curLearner !== 'undefined' && curLearner ? curLearner : { name: 'Learner' };
    const c = typeof curCourse !== 'undefined' && curCourse ? curCourse : { title: 'Course' };

    $$('c-org').textContent    = b.name || CONFIG.DEFAULT_BRAND_NAME;
    $$('c-name').textContent   = l.name;
    $$('c-course').textContent = c.title;
    $$('c-date').textContent   = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    $$('c-score').textContent  = score + '%';
    $$('c-id').textContent     = res.cert_id;
    
    // Logo and Signature Labels
    const sigLabel = $$('c-sig-dept');
    if (sigLabel) sigLabel.textContent = (b.name || CONFIG.DEFAULT_BRAND_NAME) + ' Training Department';
    const logoImg = $$('c-logo');
    if (logoImg) {
      if (b.logo) { logoImg.src = b.logo; $$('c-logo-wrap').classList.remove('hidden'); }
      else { logoImg.src = ''; $$('c-logo-wrap').classList.add('hidden'); }
    }
    
    setTimeout(() => {
      $$('cert-overlay').classList.remove('hidden');
    }, 100);
  },

  viewCert(certId) {
    const r = Learner._certsCache.find(c => c.cert_id === certId);
    if (!r) return Toast.err('Certificate data not found locally.');
    
    // Fully populate certificate template
    const b = typeof brandCache !== 'undefined' ? brandCache : { name: CONFIG.DEFAULT_BRAND_NAME };
    const l = typeof curLearner !== 'undefined' && curLearner ? curLearner : { name: r.learner_name || 'Learner' };

    $$('c-org').textContent    = b.name || CONFIG.DEFAULT_BRAND_NAME;
    $$('c-name').textContent   = l.name;
    $$('c-course').textContent = r.course_title || 'Course';
    $$('c-date').textContent   = new Date(r.completed_at * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    $$('c-score').textContent  = (r.score || 0) + '%';
    $$('c-id').textContent     = r.cert_id;

    // Logo and Signature Labels
    const sigLabel = $$('c-sig-dept');
    if (sigLabel) sigLabel.textContent = (b.name || CONFIG.DEFAULT_BRAND_NAME) + ' Training Department';
    const logoImg = $$('c-logo');
    if (logoImg) {
      if (b.logo) { logoImg.src = b.logo; $$('c-logo-wrap').classList.remove('hidden'); }
      else { logoImg.src = ''; $$('c-logo-wrap').classList.add('hidden'); }
    }

    // Trigger download (without showing overlay necessarily, but we need the elements to be in DOM)
    // The downloadCertPDF uses html2canvas on #cert-sheet.
    // If it's hidden, html2canvas might struggle depending on implementation.
    // Let's ensure it's at least not display:none during the capture.
    const wasHidden = $$('cert-overlay').classList.contains('hidden');
    if (wasHidden) {
       $$('cert-overlay').style.visibility = 'hidden';
       $$('cert-overlay').classList.remove('hidden');
    }

    setTimeout(() => {
      App.downloadCertPDF();
      if (wasHidden) {
        $$('cert-overlay').classList.add('hidden');
        $$('cert-overlay').style.visibility = '';
      }
    }, 150);
  }
};

// Tap a lesson screenshot to open it full size (scrollable / pinch-zoomable); tap again or Esc to close.
(function () {
  const close = () => { const z = document.querySelector('.img-zoom'); if (z) z.remove(); };
  document.addEventListener('click', e => {
    if (e.target.closest('.img-zoom')) { close(); return; }
    const img = e.target.closest('.prose-content img');
    if (!img) return;
    const z = document.createElement('div');
    z.className = 'img-zoom'; z.setAttribute('role', 'dialog'); z.setAttribute('aria-label', 'Screenshot, full size');
    z.innerHTML = `<button class="img-zoom-close" aria-label="Close">×</button><img src="${img.currentSrc || img.src}" alt="${esc(img.alt || '')}">`;
    document.body.appendChild(z);
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
})();


// Phone: scale the fixed-width certificate preview to the screen instead of panning (PDF export resets the zoom).
(function () {
  const ov = document.getElementById('cert-overlay'), sheet = document.getElementById('cert-sheet');
  if (!ov || !sheet) return;
  const fit = () => {
    const avail = ov.clientWidth - 32;
    sheet.style.zoom = innerWidth <= 860 && avail < 760 && avail > 0 ? String(avail / 760) : '';
  };
  new MutationObserver(fit).observe(ov, { attributes: true, attributeFilter: ['class'] });
  addEventListener('resize', fit);
})();
