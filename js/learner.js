// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Learner Experience & Quiz Engine
// ══════════════════════════════════════════════════════════

const Learner = {
  _prog: null, // { course_id, module_idx, modules: [{mi, passed, score}] }

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
    ['courses','progress','certs','account'].forEach(k => {
      if($$(`ln-${k}`)) $$(`ln-${k}`).classList.toggle('active', k===p);
      const lp = $$(`lp-${k}`);
      if(lp) { lp.classList.toggle('hidden', k!==p); lp.classList.toggle('active', k===p); }
    });
    if(p==='courses') Learner.renderCourses();
    if(p==='progress') Learner.renderProgress();
    if(p==='certs') Learner.renderCerts();
  },

  // ─── COURSES ───
  async renderCourses() {
    const grid = $$('l-courses-grid'); if(!grid) return;
    grid.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;"><div class="spinner"></div></div>';
    try {
      const [apiCourses, apiRecs, apiAssigns, apiProgress, apiSections] = await Promise.all([
        api('/api/courses'),
        learnerApi('/api/completions/me').catch(() => []),
        learnerApi('/api/assignments/me').catch(() => []),
        learnerApi('/api/progress/me').catch(() => []),
        api('/api/sections').catch(() => [])
      ]);
      const recs = apiRecs.map(normRecord);
      const sections = apiSections || [];

      if (!apiCourses.length) {
        grid.innerHTML = '<div class="card" style="grid-column:1/-1;text-align:center;padding:40px;color:var(--ink-4);">No courses available.</div>';
        return;
      }

      const renderCard = c => {
        const nc = normCourse(c);
        const assigned = apiAssigns.some(a => a.course_id === nc.id);
        const best = recs.filter(r => r.cid === nc.id).sort((a,z) => z.score - a.score)[0];
        const passed = best && best.passed;
        const prog = !passed && apiProgress.find(p => p.course_id === nc.id);
        const modsDone = prog ? prog.modules.length : 0;
        const totalMods = nc.mods ? nc.mods.length : null;
        let chip = '';
        if (passed) chip = '<span class="chip chip-green">✓ Passed</span>';
        else if (prog) chip = `<span class="chip chip-blue">▶ In Progress${totalMods ? ` (${modsDone}/${totalMods})` : ''}</span>`;
        else if (assigned) chip = '<span class="chip chip-amber">Mandatory</span>';
        return `<div class="course-card" onclick="Learner.startCourse('${nc.id}')">
          <div style="font-weight:700;">${esc(nc.title)}</div>
          <div style="margin-top:8px;">${chip}</div>
        </div>`;
      };

      let html = '';
      if(sections.length) {
        const bySec = {};
        const unsec = [];
        sections.forEach(s => { bySec[s.id] = []; });
        apiCourses.forEach(c => {
          if(c.section_id && bySec[c.section_id]) bySec[c.section_id].push(c);
          else unsec.push(c);
        });
        sections.forEach(s => {
          if(!bySec[s.id].length) return;
          html += `<div class="section-header" style="grid-column:1/-1;">${esc(s.name)}</div>`;
          html += bySec[s.id].map(renderCard).join('');
        });
        if(unsec.length) {
          html += `<div class="section-header" style="grid-column:1/-1;">Other</div>`;
          html += unsec.map(renderCard).join('');
        }
      } else {
        html = apiCourses.map(renderCard).join('');
      }
      grid.innerHTML = html || '<div class="card" style="grid-column:1/-1;text-align:center;padding:40px;color:var(--ink-4);">No courses available.</div>';
    } catch(e) {
      grid.innerHTML = `<div class="card" style="grid-column:1/-1;color:var(--fail);">${esc(e.message)}</div>`;
    }
  },

  // ─── PROGRESS ───
  async renderProgress() {
    const res = await learnerApi('/api/assignments/me');
    $$('l-progress-content').innerHTML = `<h3>Mandatory Training</h3>` + res.map(a => `<div class="card">${esc(a.course_title)} - ${a.completed ? 'Done' : 'Pending'}</div>`).join('');
  },

  // ─── CERTS ───
  _certsCache: [],
  async renderCerts() {
    try {
      const res = await learnerApi('/api/completions/me');
      Learner._certsCache = (res || []).filter(r => r.passed);
      $$('l-certs-content').innerHTML = Learner._certsCache.length 
        ? Learner._certsCache.map(r => `<div class="card">📜 ${esc(r.course_title)} <button class="btn btn-outline btn-sm" onclick="Learner.viewCert('${r.cert_id}')">Download</button></div>`).join('')
        : '<div class="card" style="color:var(--ink-4);text-align:center;">No certificates earned yet. Complete a course to earn one!</div>';
    } catch(e) { $$('l-certs-content').innerHTML = `<div class="card" style="color:var(--fail);">${esc(e.message)}</div>`; }
  },

  // ─── QUIZ ENGINE ───
  async startCourse(cid) {
    try {
      const [res, progList] = await Promise.all([
        api(`/api/courses/${cid}`),
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
          <span>${esc(m.title)}</span>
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
    // Update progress bar
    const pct = Math.round((mi / curCourse.mods.length) * 100);
    if($$('ch-prog')) $$('ch-prog').style.width = pct + '%';
    if($$('ch-label')) $$('ch-label').textContent = `Module ${mi + 1} of ${curCourse.mods.length}`;
    const hasQuiz = mod.questions && mod.questions.length > 0;
    const refUrl = curCourse.refUrl || '';
    const refNotice = (hasQuiz && refUrl) ? `
      <div class="ref-material-notice">
        <span class="ref-icon">📎</span>
        <span>Before starting the competency check, make sure you've reviewed the course material.</span>
        <a href="${esc(refUrl)}" target="_blank" rel="noopener noreferrer" class="ref-link">View Material →</a>
      </div>` : '';
    $$('mod-main').innerHTML = `<div class="module-prose">
      <h2>${esc(mod.title)}</h2>
      <div>${mod.content}</div>
      ${refNotice}
      ${hasQuiz ? `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-4);" onclick="Learner.startQuiz(${mi})">Start Competency Check →</button>` : `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-8);" onclick="Learner.finishMod(${mi})">Continue →</button>`}
    </div>`;
  },

  startQuiz(mi) { quizSt[mi] = { ans: [] }; Learner.renderQ(mi, 0); },

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

  answer(mi, qi, sel) {
    const q = curCourse.mods[mi].questions[qi];
    const ok = sel === q.correct_index;
    quizSt[mi].ans.push({ question_id: q.id, ok });
    const total = curCourse.mods[mi].questions.length;

    // Mark all option buttons
    $$('mod-main').querySelectorAll('.quiz-opt').forEach((btn, i) => {
      btn.disabled = true;
      const letter = btn.querySelector('.opt-letter');
      if(i === sel) {
        btn.classList.add(ok ? 'correct' : 'wrong');
        if(letter) letter.classList.add(ok ? 'correct' : 'wrong');
      }
      if(i === q.correct && !ok) {
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
          ${q.exp ? `<div class="fb-exp">${esc(q.exp)}</div>` : ''}
        </div>
        <button class="btn btn-primary fb-next" onclick="${nextFn}">${nextLabel}</button>`;
      wrap.appendChild(fb);
    }
  },

  async showModResults(mi) {
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
    $$('mod-main').innerHTML = `<div class="quiz-results">
      <div class="qr-score ${passed ? 'qr-pass' : 'qr-fail'}">${pct}%</div>
      <div class="qr-label">${correct} of ${total} correct</div>
      <div class="qr-verdict">${passed ? '🎉 Module Passed!' : '❌ Not quite — review the material and try again.'}</div>
      ${nextMod
        ? `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-8);" onclick="Learner.loadMod(${mi+1})">Next Module →</button>`
        : `<button class="btn btn-primary btn-lg" style="margin-top:var(--space-8);" onclick="Learner.completeCourse()">Finish Course 🎓</button>`}
      ${!passed ? `<button class="btn btn-outline btn-lg" style="margin-top:var(--space-4);" onclick="Learner.retryMod(${mi})">Retry Module</button>` : ''}
    </div>`;

    // Save progress after every quiz module (pass or fail)
    await Learner._saveProgress(mi, passed, pct);
  },

  retryMod(mi) {
    quizSt[mi] = { ans: [] };
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
    if(!curLearner || !curCourse) return;
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
    // Combine scores from progress (prior sessions) + current quizSt (this session)
    const prog = Learner._prog || { modules: [] };
    const allModScores = [...prog.modules];
    // Override with fresh answers from this session
    Object.entries(quizSt).forEach(([mi, st]) => {
      const ans = st.ans;
      const score = ans.length > 0 ? Math.round(ans.filter(a => a.ok).length / ans.length * 100) : 100;
      const idx = allModScores.findIndex(m => m.mi === Number(mi));
      if(idx >= 0) allModScores[idx].score = score;
      else allModScores.push({ mi: Number(mi), score });
    });
    
    // Calculate final score across all modules
    const quizScores = allModScores.filter(m => m.score !== undefined);
    const score = quizScores.length > 0
      ? Math.round(quizScores.reduce((s, m) => s + m.score, 0) / quizScores.length)
      : 100;
    const passed = score >= (brandCache.pass || 80);

    if (window._adminPreview) { App.exitCourse(); return; }
    const res = await learnerApi('/api/completions', { method:'POST', body: JSON.stringify({ course_id: curCourse.id, score, passed }) });
    
    // Clear progress record now that the course is done
    learnerApi(`/api/progress/${curCourse.id}`, { method: 'DELETE' }).catch(() => {});
    Learner._prog = null;

    confetti({ particleCount: 150, spread: 70, origin: { y: 0.6 } });
    
    // Fully populate certificate
    const b = typeof brandCache !== 'undefined' ? brandCache : { name: 'TrainFlow' };
    const l = typeof curLearner !== 'undefined' && curLearner ? curLearner : { name: 'Learner' };
    const c = typeof curCourse !== 'undefined' && curCourse ? curCourse : { title: 'Course' };

    $$('c-org').textContent    = b.name || 'TrainFlow';
    $$('c-name').textContent   = l.name;
    $$('c-course').textContent = c.title;
    $$('c-date').textContent   = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    $$('c-score').textContent  = score + '%';
    $$('c-id').textContent     = res.cert_id;
    
    // Logo and Signature Labels
    const sigLabel = $$('c-sig-dept');
    if (sigLabel) sigLabel.textContent = (b.name || 'TrainFlow') + ' Training Department';
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
    const b = typeof brandCache !== 'undefined' ? brandCache : { name: 'TrainFlow' };
    const l = typeof curLearner !== 'undefined' && curLearner ? curLearner : { name: r.learner_name || 'Learner' };

    $$('c-org').textContent    = b.name || 'TrainFlow';
    $$('c-name').textContent   = l.name;
    $$('c-course').textContent = r.course_title || 'Course';
    $$('c-date').textContent   = new Date(r.completed_at * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    $$('c-score').textContent  = (r.score || 0) + '%';
    $$('c-id').textContent     = r.cert_id;

    // Logo and Signature Labels
    const sigLabel = $$('c-sig-dept');
    if (sigLabel) sigLabel.textContent = (b.name || 'TrainFlow') + ' Training Department';
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
