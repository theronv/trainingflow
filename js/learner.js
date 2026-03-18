// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Learner Experience & Quiz Engine
// ══════════════════════════════════════════════════════════

const Learner = {
  init() {
    App.show('screen-learner');
    $$('l-name-display').textContent = curLearner.name;
    $$('l-avatar').textContent = curLearner.name[0];
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
      const [apiCourses, apiRecs, apiAssigns] = await Promise.all([
        api('/api/courses'),
        learnerApi('/api/completions/me').catch(() => []),
        learnerApi('/api/assignments/me').catch(() => [])
      ]);
      const courses = apiCourses.map(normCourse);
      const recs = apiRecs.map(normRecord);
      
      if (!courses.length) {
        grid.innerHTML = '<div class="card" style="grid-column:1/-1;text-align:center;padding:40px;color:var(--ink-4);">No courses available.</div>';
        return;
      }

      grid.innerHTML = courses.map(c => {
        const assigned = apiAssigns.some(a => a.course_id === c.id);
        const best = recs.filter(r => r.cid === c.id).sort((a,z) => z.score - a.score)[0];
        const passed = best && best.passed;
        
        return `<div class="course-card" onclick="Learner.startCourse('${c.id}')">
          <div style="font-weight:700;">${esc(c.title)}</div>
          <div style="margin-top:8px;">${passed ? '<span class="chip chip-green">✓ Passed</span>' : assigned ? '<span class="chip chip-amber">Mandatory</span>' : ''}</div>
        </div>`;
      }).join('');
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
  async renderCerts() {
    const res = await learnerApi('/api/completions/me');
    const passed = res.filter(r => r.passed);
    $$('l-certs-content').innerHTML = passed.map(r => `<div class="card">📜 ${esc(r.course_title)} <button class="btn btn-outline btn-sm" onclick="Learner.viewCert('${r.cert_id}')">Download</button></div>`).join('');
  },

  // ─── QUIZ ENGINE ───
  async startCourse(cid) {
    const res = await api(`/api/courses/${cid}`);
    curCourse = normCourse(res);
    App.show('screen-course');
    Learner.loadMod(0);
  },
  loadMod(mi) {
    curModIdx = mi; const mod = curCourse.mods[mi];
    $$('mod-main').innerHTML = `<h2>${esc(mod.title)}</h2><div>${mod.content}</div><button class="btn btn-primary btn-lg" style="margin-top:24px;" onclick="Learner.startQuiz(${mi})">Start Competency Check</button>`;
  },
  startQuiz(mi) { quizSt[mi] = { ans: [] }; Learner.renderQ(mi, 0); },
  renderQ(mi, qi) {
    const q = curCourse.mods[mi].questions[qi];
    $$('mod-main').innerHTML = `<h3>Q${qi+1}</h3><p>${esc(q.q)}</p><div style="display:flex;flex-direction:column;gap:8px;">${q.opts.map((o,i)=>`<button class="btn btn-outline" onclick="Learner.answer(${mi},${qi},${i})">${esc(o)}</button>`).join('')}</div>`;
  },
  answer(mi, qi, sel) {
    const q = curCourse.mods[mi].questions[qi];
    const ok = sel === q.correct;
    quizSt[mi].ans.push({ question_id: q.id, ok });
    if(qi+1 < curCourse.mods[mi].questions.length) Learner.renderQ(mi, qi+1);
    else Learner.finishMod(mi);
  },
  async finishMod(mi) {
    if(mi+1 < curCourse.mods.length) Learner.loadMod(mi+1);
    else Learner.completeCourse();
  },
  async completeCourse() {
    const res = await learnerApi('/api/completions', { method:'POST', body: JSON.stringify({ course_id: curCourse.id, score: 100, passed: true }) });
    confetti({ particleCount: 150, spread: 70, origin: { y: 0.6 } });
    $$('c-name').textContent = curLearner.name;
    $$('c-id').textContent = res.cert_id;
    $$('cert-overlay').classList.remove('hidden');
  },
  viewCert(certId) { Toast.info('Generating PDF for ' + certId); }
};
