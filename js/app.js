// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Application Logic
// ══════════════════════════════════════════════════════════

const CONFIG = {
  WORKER_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8787'
    : 'https://trainflow-worker.theronv.workers.dev',
  DEFAULT_BRAND_NAME: 'TrainFlow',
  DEFAULT_TAGLINE: 'Training & Certification Platform',
  DEFAULT_C1: '#2563eb',
  DEFAULT_C2: '#1d4ed8',
  DEFAULT_PASS: 80,
  DEFAULT_ICON: '📋',
  MIN_PW_LEN: 8,
  TOAST_MS: 3200,
  FOCUS_DELAY: 80,
};

const WORKER_URL = CONFIG.WORKER_URL;

// ── Storage Utility (Hardened) ──
const StorageUtils = {
  get(key) {
    try { return sessionStorage.getItem(key); }
    catch (e) { return null; }
  },
  set(key, val) {
    try { sessionStorage.setItem(key, val); }
    catch (e) { /* Graceful fallback */ }
  },
  remove(key) {
    try { sessionStorage.removeItem(key); }
    catch (e) { /* Graceful fallback */ }
  }
};

// ── Token storage ──
function getToken()   { return StorageUtils.get('tf_token'); }
function setToken(t)  { StorageUtils.set('tf_token', t); }
function clearToken() { StorageUtils.remove('tf_token'); }

// ── Cached state ──
let brandCache   = { name: CONFIG.DEFAULT_BRAND_NAME, tagline: CONFIG.DEFAULT_TAGLINE, logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, pass: CONFIG.DEFAULT_PASS };
let coursesCache = [];
let assignCache  = []; // course_id list for learner
let isDemo       = false;

const MOCK_COURSES = [
  {
    id: 'demo-1', title: 'Executive Communication', icon: '🗣️', description: 'Master the art of high-stakes communication and clarity.',
    modules: [
      { id: 'm1', title: 'Clarifying the Ask', content: '<h2>The Power of Clarity</h2><p>In high-stakes environments, ambiguity is the enemy of execution.</p><h3>Key Principles</h3><ul><li>Be brief, be bright, be gone.</li><li>Lead with the bottom line.</li><li>Focus on outcomes, not activities.</li></ul>',
        questions: [
          { question: 'What is the primary goal of executive communication?', option_a: 'To show how hard you worked', option_b: 'To achieve clarity and drive action', option_c: 'To use as many slides as possible', option_d: 'To demonstrate technical mastery', correct_index: 1, explanation: 'Executives value clarity and speed above all else.' }
        ]
      },
      { id: 'm2', title: 'Handling Resistance', content: '<h2>Responding to Pushback</h2><p>Resistance is rarely personal; it is usually a sign of missing information.</p>',
        questions: [
          { question: 'How should you respond to resistance?', option_a: 'Defend your position immediately', option_b: 'Ignore it and move on', option_c: 'Acknowledge the concern and ask for clarification', option_d: 'Escalate to their manager', correct_index: 2, explanation: 'Listening and clarifying reduces friction.' }
        ]
      }
    ]
  },
  {
    id: 'demo-2', title: 'Design Systems 101', icon: '🎨', description: 'Learn how to build scalable components and consistent UIs.',
    modules: [
      { id: 'd1', title: 'The Atomic Model', content: '<h2>Atomic Design</h2><p>Design systems are built from atoms, molecules, and organisms.</p>',
        questions: [{ question: 'What is the smallest unit in Atomic Design?', options: ['Molecule', 'Atom', 'Organism', 'Template'], correct_index: 1 }]
      }
    ]
  }
];

// ── API helper — injects auth header, always returns parsed JSON ──
async function api(path, opts = {}) {
  if (isDemo) {
    if (path === '/api/brand') return brandCache;
    if (path === '/api/courses') return MOCK_COURSES;
    if (path.startsWith('/api/courses/')) return MOCK_COURSES.find(c => c.id === path.split('/').pop()) || MOCK_COURSES[0];
    if (path === '/api/admin/stats') return { 
      summary: { total_learners: 42, total_courses: 2, completions_this_month: 12, pass_rate: 94 },
      learners: [{ id: 'l1', name: 'Demo User', last_login_at: Date.now()/1000, courses_started: 2, courses_completed: 1, avg_score: 92, modules: [] }],
      courses: MOCK_COURSES.map(c => ({ title: c.title, enrolled: 12, completed: 10, avg_score: 88, pass_rate: 90 }))
    };
    if (path === '/api/assignments') return [{course_id: 'demo-1', learner_id: 'l1'}];
    if (path === '/api/learners') return [{ id: 'l1', name: 'Demo User', last_login_at: Date.now()/1000, completion_count: 1 }];
  }
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(WORKER_URL + path, { ...opts, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw Object.assign(new Error(body.error || res.statusText), { status: res.status, detail: body.detail });
  }
  return res.json();
}

// ── Normalizers — API field names → internal field names ──
function normCourse(c) {
  return {
    id: c.id, icon: c.icon || CONFIG.DEFAULT_ICON, title: c.title, desc: c.description || '',
    mods: (c.modules || []).map(m => ({
      id: m.id, title: m.title, content: m.content || '',
      questions: (m.questions || []).map(q => ({
        q: q.question, opts: [q.option_a, q.option_b, q.option_c, q.option_d],
        correct: q.correct_index, exp: q.explanation || '',
      }))
    }))
  };
}
function normRecord(r) {
  return {
    cid: r.course_id, learner: r.learner_name, score: r.score,
    passed: Boolean(r.passed),
    date: (r.completed_at || 0) * 1000,
    cid2: r.cert_id || '',
  };
}
function normBrand(b) {
  return {
    name: b.org_name || CONFIG.DEFAULT_BRAND_NAME,
    tagline: b.tagline || 'Training & Certification Platform',
    logo: b.logo_url || '',
    c1:   b.primary_color   || CONFIG.DEFAULT_C1,
    c2:   b.secondary_color || CONFIG.DEFAULT_C2,
    pass: b.pass_threshold  ?? CONFIG.DEFAULT_PASS,
  };
}

// ── Denormalizer — internal field names → API body ──
function denormCourseBody(c) {
  return {
    title: c.title, icon: c.icon || CONFIG.DEFAULT_ICON, description: c.desc || '',
    modules: (c.mods || []).map(m => ({
      id: m.id, title: m.title, content: m.content || '',
      questions: (m.questions || []).map(q => ({
        question:      q.q || q.question || '',
        options:       q.opts || q.options || ['','','',''],
        correct_index: typeof q.correct === 'number' ? q.correct : 0,
        explanation:   q.exp || q.explanation || '',
      }))
    }))
  };
}

// ── Learner JWT ──
function getLearnerToken()   { return StorageUtils.get('tf_learner_token'); }
function setLearnerToken(t)  { StorageUtils.set('tf_learner_token', t); }
function clearLearnerToken() { StorageUtils.remove('tf_learner_token'); }

// ── learnerApi — like api() but sends the learner JWT ──
async function learnerApi(path, opts = {}) {
  if (isDemo) {
    if (path === '/api/learners/me') return { id: 'demo-id', name: 'Demo Learner' };
    if (path === '/api/completions/me') return [
      { course_id: 'demo-1', learner_name: 'Demo Learner', score: 100, passed: 1, completed_at: Date.now()/1000, cert_id: 'CERT-DEMO-123' }
    ];
    if (path === '/api/learners/me/assignments') return ['demo-1'];
    if (path.startsWith('/api/progress/')) return [];
    if (path === '/api/progress' || path === '/api/completions') return { ok: true };
  }
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const token = getLearnerToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(WORKER_URL + path, { ...opts, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw Object.assign(new Error(body.error || res.statusText), { status: res.status, detail: body.detail });
  }
  return res.json();
}

// ── State ──
let curLearner = null;   // { id, name } when signed in
let curCourse  = null;
let curModIdx  = 0;
let quizSt     = {};
let cbState    = { editId: null, mods: [] };
let csvParsed  = null;

// ══════════════════ UTILITIES ══════════════════
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2,6); }

// ══════════════════ TOAST ══════════════════
const Toast = {
  show(msg, type='info') {
    const el = document.createElement('div');
    el.className = `toast t-${type}`;
    el.textContent = msg;
    document.getElementById('toast-root').appendChild(el);
    setTimeout(() => { el.style.transition='opacity 0.3s'; el.style.opacity='0'; setTimeout(()=>el.remove(),300); }, 3200);
  },
  ok(m)   { Toast.show(m,'success'); },
  err(m)  { Toast.show(m,'error'); },
  info(m) { Toast.show(m,'info'); }
};

// ══════════════════ BRANDING ══════════════════
function applyBrand() {
  const b = brandCache;
  document.documentElement.style.setProperty('--brand-1', b.c1 || CONFIG.DEFAULT_C1);
  document.documentElement.style.setProperty('--brand-2', b.c2 || CONFIG.DEFAULT_C2);
  // Text
  ['ldg-brand','l-brand','a-brand'].forEach(id => { const el = $$(id); if(el) el.textContent = b.name || CONFIG.DEFAULT_BRAND_NAME; });
  const tg = $$('ldg-tagline'); if(tg) tg.textContent = b.tagline || 'Training & Certification Platform';
  const org = $$('ldg-org');
  if(org) { if(b.name && b.name !== CONFIG.DEFAULT_BRAND_NAME) { org.textContent = b.name; org.style.display=''; } else org.style.display='none'; }
  // Logo
  ['l-logo','a-logo'].forEach(id => { const img = $$(id); if(!img) return; if(b.logo){ img.src=b.logo; img.classList.remove('hidden'); } else { img.src=''; img.classList.add('hidden'); } });
  // Branding form sync
  if($$('br-name')) $$('br-name').value = b.name||'';
  if($$('br-tag'))  $$('br-tag').value  = b.tagline||'';
  if($$('br-logo-url')) $$('br-logo-url').value = b.logo||'';
  if($$('br-c1'))   { $$('br-c1').value = b.c1||CONFIG.DEFAULT_C1; $$('br-c1-hex').value = b.c1||CONFIG.DEFAULT_C1; }
  if($$('br-c2'))   { $$('br-c2').value = b.c2||CONFIG.DEFAULT_C2; $$('br-c2-hex').value = b.c2||CONFIG.DEFAULT_C2; }
  if($$('br-pass')) $$('br-pass').value = b.pass||CONFIG.DEFAULT_PASS;
  // Preview
  const pn = $$('br-prev-name'); if(pn) pn.textContent = b.name || CONFIG.DEFAULT_BRAND_NAME;
  const pl = $$('br-prev-logo'); if(pl){ if(b.logo){pl.src=b.logo;pl.style.display='block';}else{pl.style.display='none';} }
}

function $$(id) { return document.getElementById(id); }

const App = {

  // ─── INIT ───
  async init() {
    // Restore learner identity from live token if present
    const t = getLearnerToken();
    if (t) {
      try {
        const me = await learnerApi('/api/learners/me');
        curLearner = { id: me.id, name: me.name };
      } catch { clearLearnerToken(); }
    }
    try {
      const b = await api('/api/brand');
      brandCache = normBrand(b);
    } catch { /* use defaults */ }
    applyBrand();
  },

  startDemo() {
    isDemo = true;
    curLearner = { id: 'demo-id', name: 'Demo Learner' };
    brandCache = { name: 'TrainFlow Demo', tagline: 'Experience the new UI/UX', logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, pass: CONFIG.DEFAULT_PASS };
    applyBrand();
    Toast.ok('Demo Mode Activated ✨');
    App.showLearner();
  },

  // ─── SCREEN ───
  show(id) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    $$(id).classList.add('active');
  },

  // ─── LANDING ───
  goLearner() { App.show('screen-learner'); applyBrand(); if(curLearner) App.showLearner(); else App.showPage('lp-name'); },
  goAdmin()   { App.show('screen-login'); setTimeout(()=>$$('pw-input').focus(),CONFIG.FOCUS_DELAY); },

  // ─── LEARNER LOGIN / LOGOUT ───
  async doLearnerLogin() {
    const name = $$('learner-name-input').value.trim();
    const pw   = $$('learner-pw-input').value;
    const errEl = $$('l-login-error');
    errEl.style.display = 'none';
    if (!name || !pw) { errEl.textContent = 'Please enter your name and password.'; errEl.style.display = ''; return; }
    try {
      const res = await fetch(WORKER_URL + '/api/learners/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, password: pw }),
      });
      const data = await res.json();
      if (!res.ok) { errEl.textContent = data.error || 'Sign in failed.'; errEl.style.display = ''; return; }
      setLearnerToken(data.token);
      curLearner = { id: data.id, name: data.name };
      $$('learner-pw-input').value = '';
      App.showLearner();
    } catch (e) {
      errEl.textContent = 'Could not connect. Please try again.'; errEl.style.display = '';
    }
  },
  learnerLogout() { clearLearnerToken(); curLearner = null; App.show('screen-landing'); },

  // ─── LOGIN ───
  async doLogin() {
    const password = $$('pw-input').value;
    try {
      const { token } = await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ password }),
      });
      setToken(token);
      $$('pw-input').value = '';
      applyBrand();
      App.show('screen-admin');
      App.aNav('dashboard');
    } catch (e) {
      if (e.status === 503) {
        $$('first-run-overlay').classList.remove('hidden');
      } else {
        Toast.err(e.message || 'Login failed.');
      }
    }
  },
  adminLogout() { clearToken(); App.show('screen-landing'); },

  // ─── LEARNER ───
  showLearner() {
    const pill = $$('l-user-pill');
    if(pill && curLearner) {
      pill.style.display = 'flex';
      $$('l-name-display').textContent = curLearner.name;
      $$('l-avatar').textContent = curLearner.name[0].toUpperCase();
      if($$('lcp-name')) $$('lcp-name').value = curLearner.name;
    }
    App.lNav('courses');
  },
  async updateLearnerName() {
    const name = $$('lcp-name').value.trim();
    if (!name) { Toast.err('Name is required.'); return; }
    try {
      await learnerApi('/api/learners/me/name', { method: 'PATCH', body: JSON.stringify({ name }) });
      curLearner.name = name;
      $$('l-name-display').textContent = name;
      $$('l-avatar').textContent = name[0].toUpperCase();
      Toast.ok('Name updated.');
    } catch (e) {
      Toast.err(e.message || 'Could not update name.');
    }
  },
  lNav(p) {
    ['courses','progress','certs','account'].forEach(k => {
      $$(`ln-${k}`).classList.toggle('active', k===p);
      $$(`lp-${k}`).classList.toggle('hidden', k!==p);
      $$(`lp-${k}`).classList.toggle('active', k===p);
    });
    $$('lp-name').classList.add('hidden');
    if(p==='courses')  App.renderLCourses();
    if(p==='progress') App.renderLProgress();
    if(p==='certs')    App.renderLCerts();
  },
  showPage(id) { ['lp-name','lp-courses','lp-progress','lp-certs','lp-account'].forEach(p=>{$$(p).classList.add('hidden');$$(p).classList.remove('active');}); $$(id).classList.remove('hidden'); $$(id).classList.add('active'); },

  async renderLCourses() {
    const grid = $$('l-courses-grid');
    grid.classList.add('stagger');
    try {
      const [apiCourses, apiRecs, apiAssigns] = await Promise.all([
        api('/api/courses'),
        learnerApi('/api/completions/me'),
        learnerApi('/api/learners/me/assignments').catch(() => [])
      ]);
      const courses = apiCourses.map(normCourse);
      const recs    = apiRecs.map(normRecord);
      coursesCache  = courses;
      assignCache   = apiAssigns || [];
      const b       = brandCache;
      if(!courses.length){ grid.innerHTML=`<div class="empty"><div class="empty-icon">📭</div><div class="empty-title">No courses yet</div><div class="empty-hint">Ask your manager to create training courses.</div></div>`; return; }
      
      courses.sort((a, b) => {
        const aAssigned = assignCache.includes(a.id);
        const bAssigned = assignCache.includes(b.id);
        if (aAssigned && !bAssigned) return -1;
        if (!aAssigned && bAssigned) return 1;
        return a.title.localeCompare(b.title);
      });

      grid.innerHTML = courses.map(c => {
        const best = recs.filter(r=>r.cid===c.id).sort((a,z)=>z.score-a.score)[0];
        const passed = best && best.score >= (b.pass||CONFIG.DEFAULT_PASS);
        const qc = (c.mods||[]).reduce((s,m)=>s+(m.questions||[]).length,0);
        const assigned = assignCache.includes(c.id);
        let chipHtml = '<span class="chip chip-blue">New</span>';
        if (passed) chipHtml = '<span class="chip chip-green">✓ Passed</span>';
        else if (best) chipHtml = '<span class="chip chip-amber">Retry</span>';
        else if (assigned) chipHtml = '<span class="chip" style="background:var(--accent-lt);color:var(--accent);border-color:var(--accent-md);">Mandatory</span>';

        return `<div class="course-card ${assigned ? 'assigned-card' : ''}" onclick="App.startCourse('${c.id}')" style="${assigned && !passed ? 'border: 2px solid var(--accent-md);' : ''}">
        <div class="course-icon">${esc(c.icon||'📚')}</div>
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">
          <div class="course-name">${esc(c.title)}</div>
          ${chipHtml}
        </div>
        <div class="course-desc">${esc(c.desc||'')}</div>
        <div class="course-meta">
          <span class="course-meta-item">📝 ${(c.mods||[]).length} module${(c.mods||[]).length!==1?'s':''}</span>
          <span class="course-meta-item">❓ ${qc} question${qc!==1?'s':''}</span>
          ${best?`<span class="course-meta-item">Best: ${best.score}%</span>`:''}
        </div>
      </div>`;
      }).join('');
    } catch (e) {
      grid.innerHTML = `<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-title">Could not load courses</div><div class="empty-hint">${esc(e.message)}</div></div>`;
    }
  },

  async renderLProgress() {
    const el = $$('l-progress-content');
    try {
      const [apiAssigns, apiRecs] = await Promise.all([
        learnerApi('/api/assignments/me'),
        learnerApi('/api/completions/me'),
      ]);
      const assigns = apiAssigns;
      const recs    = apiRecs.map(normRecord);
      const b       = brandCache;
      
      if (!assigns.length && !recs.length) {
        el.innerHTML = `<div class="empty"><div class="empty-icon">📊</div><div class="empty-title">No activity yet</div><div class="empty-hint">No courses assigned yet. Check back soon.</div></div>`;
        return;
      }

      const completedCount = assigns.filter(a => a.completed).length;
      const totalCount = assigns.length;
      const summaryHtml = totalCount > 0 ? `<div class="card" style="margin-bottom:var(--space-6);background:var(--brand-1);color:white;text-align:center;">
        <div style="font-size:var(--text-xs);opacity:0.8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">Mandatory Training</div>
        <div style="font-size:var(--text-xl);font-weight:700;">${completedCount} of ${totalCount} courses completed</div>
      </div>` : '';

      // Merge records for display
      const allCourseIds = [...new Set([...assigns.map(a => a.course_id), ...recs.map(r => r.cid)])];
      
      el.innerHTML = summaryHtml + allCourseIds.map(cid => {
        const assign = assigns.find(a => a.course_id === cid);
        const courseRecs = recs.filter(r => r.cid === cid);
        const best = courseRecs.sort((a, z) => z.score - a.score)[0];
        const passed = best && best.score >= (b.pass || CONFIG.DEFAULT_PASS);
        
        // Find course title/icon from cache or assignments
        const course = coursesCache.find(x => x.id === cid) || { title: assign?.course_title || 'Unknown Course', icon: '📚' };
        
        let statusLabel = 'Not Started';
        let statusCls = 'chip-blue';
        if (passed) { statusLabel = 'Completed ✓'; statusCls = 'chip-green'; }
        else if (best) { statusLabel = 'In Progress'; statusCls = 'chip-amber'; }
        
        const isOverdue = assign?.due_at && !passed && new Date(assign.due_at) < new Date();
        const dueHtml = assign?.due_at ? `<div style="font-size:var(--text-xs);${isOverdue ? 'color:var(--fail);font-weight:700;' : 'color:var(--ink-4);'}">
          ${isOverdue ? '⚠️ OVERDUE: ' : 'Due: '}${new Date(assign.due_at).toLocaleDateString()}
        </div>` : '';

        return `<div class="card" style="margin-bottom:var(--space-4);${isOverdue ? 'border-left:4px solid var(--fail);' : assign ? 'border-left:4px solid var(--brand-1);' : ''}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-4);">
          <div style="display:flex;align-items:center;gap:var(--space-3);">
            <span style="font-size:22px;">${esc(course.icon)}</span>
            <div>
              <div style="font-weight:700;">${esc(course.title)}</div>
              ${dueHtml}
            </div>
          </div>
          <span class="chip ${statusCls}">${statusLabel}</span>
        </div>
        <div style="display:flex;align-items:center;gap:var(--space-4);">
          <div class="progress-track" style="flex:1;height:6px;"><div class="progress-fill" style="width:${best ? best.score : 0}%"></div></div>
          <div style="font-family:'Cormorant Garamond',serif;font-size:24px;font-weight:700;">${best ? best.score + '%' : '—'}</div>
          ${passed ? `<button class="btn btn-outline btn-sm" onclick="App.showCert('${cid}','${esc(curLearner?.name || '')}')">Certificate</button>` : `<button class="btn btn-primary btn-sm" onclick="App.startCourse('${cid}')">${best ? 'Continue' : 'Start'}</button>`}
        </div>
      </div>`;
      }).join('');
    } catch (e) {
      el.innerHTML = `<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-title">Could not load progress</div><div class="empty-hint">${esc(e.message)}</div></div>`;
    }
  },

  async renderLCerts() {
    const el = $$('l-certs-content');
    try {
      const [apiRecs, apiCourses] = await Promise.all([
        learnerApi('/api/completions/me'),
        api('/api/courses'),
      ]);
      const allRecs = apiRecs.map(normRecord);
      const courses = apiCourses.map(normCourse);
      coursesCache  = courses;
      const passed  = allRecs.filter(r => r.passed);
      if(!passed.length){ el.innerHTML=`<div class="empty"><div class="empty-icon">🏅</div><div class="empty-title">No certificates yet</div><div class="empty-hint">Complete a course to earn your first certificate.</div></div>`; return; }
      
      const best = {};
      passed.forEach(r => { if (!best[r.cid] || r.score > best[r.cid].score) best[r.cid] = r; });
      
      el.innerHTML = Object.values(best).map(r => {
        const c = courses.find(x => x.id === r.cid) || { title: 'Unknown Course', icon: '📚' };
        return `<div class="card" style="display:flex;align-items:center;gap:var(--space-5);margin-bottom:var(--space-4);">
        <div style="font-size:36px;">📜</div>
        <div style="flex:1;">
          <div style="font-weight:700;font-size:var(--text-md);">${esc(c.title)}</div>
          <div style="font-size:var(--text-xs);color:var(--ink-4);margin-top:2px;">
            Completed ${new Date(r.date).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })} · Score: ${r.score}%
          </div>
          <div style="font-family:monospace;font-size:10px;color:var(--ink-4);margin-top:4px;">${r.cid2}</div>
        </div>
        <button class="btn btn-outline btn-sm" onclick="App.showCert('${r.cid}','${esc(curLearner?.name || '')}', '${r.cid2}')">↓ Re-download</button>
      </div>`;
      }).join('');
    } catch (e) {
      el.innerHTML = `<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-title">Could not load certificates</div><div class="empty-hint">${esc(e.message)}</div></div>`;
    }
  },

  // ─── ADMIN NAV ───
  aNav(p) {
    ['dashboard', 'courses', 'importer', 'learners', 'completions', 'branding', 'settings'].forEach(k => {
      const btn = $$(`an-${k}`);
      if (btn) btn.classList.toggle('active', k === p);
      const page = $$(`ap-${k}`);
      if (page) {
        page.classList.toggle('hidden', k !== p);
        page.classList.toggle('active', k === p);
      }
    });
    if (p === 'dashboard')   App.renderDash();
    if (p === 'courses')     App.renderACourses();
    if (p === 'learners')    App.renderLearners();
    if (p === 'completions') App.renderComps();
    if (p === 'branding')    applyBrand();
    if (p === 'importer')    App.initImporter();
  },

  // ─── AI IMPORTER ───
  _fileModules: [],
  _parsedModules: [],
  _generatedCourse: null,
  _isGenerating: false,

  initImporter() {
    App._fileModules = [];
    App._parsedModules = [];
    App._generatedCourse = null;
    App._isGenerating = false;
    App.renderFileModuleList();
    App.goPhase(1);
  },

  goPhase(n) {
    [1, 2, 3, 4].forEach(i => {
      const phase = $$(['phase-upload', 'phase-configure', 'phase-generate', 'phase-export'][i - 1]);
      if (phase) phase.classList.toggle('hidden', i !== n);
      const step = $$(`step-${i}`);
      if (step) {
        step.classList.toggle('active', i === n);
        step.classList.toggle('done', i < n);
      }
    });
  },

  handleDrop(e) {
    e.preventDefault();
    $$('imp-drop-zone').classList.remove('drag-active');
    const files = Array.from(e.dataTransfer.files).filter(f => /\.(md|markdown|txt)$/i.test(f.name));
    if (!files.length) { Toast.err('Drop .md files only.'); return; }
    files.forEach(f => App.readAndAddFile(f));
  },
  handleFileSelect(e) {
    Array.from(e.target.files).forEach(f => App.readAndAddFile(f));
    e.target.value = '';
  },
  readAndAddFile(file) {
    const reader = new FileReader();
    reader.onload = ev => App.addFileModule(ev.target.result, file.name.replace(/\.[^.]+$/, ''));
    reader.readAsText(file);
  },
  addFileModule(rawMd, defaultName) {
    const subModules = App.parseMdToModules(rawMd, defaultName);
    const id = uid();
    App._fileModules.push({ id, name: App.cleanTitle(defaultName), subModules });
    App.renderFileModuleList();
  },
  cleanTitle(s) {
    if (/^[\w-]+$/.test(s) && (s.includes('_') || s.includes('-') || s === s.toLowerCase() || s === s.toUpperCase())) {
      s = s.replace(/[-_]/g, ' ').replace(/\s+/g, ' ').trim();
    }
    return s.replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
  },
  parseMdToModules(raw, defaultTitle) {
    const lines = raw.split('\n');
    const modules = [];
    let cur = null;
    for (const line of lines) {
      const h2 = line.match(/^##\s+(.+)/);
      if (h2) {
        if (cur) modules.push(cur);
        cur = { title: App.cleanTitle(h2[1].trim()), rawLines: [] };
      } else if (cur) {
        cur.rawLines.push(line);
      }
    }
    if (cur) modules.push(cur);
    if (!modules.length) modules.push({ title: App.cleanTitle(defaultTitle), rawLines: lines });
    return modules.map(m => ({ title: m.title, content: App.mdToHtml(m.rawLines.join('\n')) }));
  },
  mdToHtml(md) {
    return (md || '').replace(/\r\n/g, '\n')
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .split('\n\n').map(block => {
        block = block.trim();
        if (!block) return '';
        if (block.startsWith('<h')) return block;
        if (block.startsWith('- ')) return '<ul>' + block.split('\n').map(l => `<li>${l.replace('- ', '')}</li>`).join('') + '</ul>';
        return `<p>${block}</p>`;
      }).join('\n');
  },
  renderFileModuleList() {
    const el = $$('file-module-list');
    if (!App._fileModules.length) { el.innerHTML = ''; $$('upload-actions').classList.add('hidden'); return; }
    const total = App._fileModules.reduce((s, f) => s + f.subModules.length, 0);
    $$('upload-module-count').textContent = `${total} module${total !== 1 ? 's' : ''} total`;
    $$('upload-actions').classList.remove('hidden');
    el.innerHTML = App._fileModules.map((fm, fi) => `
      <div class="card card-sm" style="margin-bottom:var(--space-2);display:flex;align-items:center;gap:var(--space-3)">
        <div style="flex:1"><strong>${esc(fm.name)}</strong> <span style="font-size:var(--text-xs);color:var(--ink-4)">(${fm.subModules.length} sections)</span></div>
        <button class="btn btn-ghost btn-sm" onclick="App._fileModules.splice(${fi},1);App.renderFileModuleList()">✕</button>
      </div>`).join('');
  },
  proceedFromUpload() {
    App._parsedModules = [];
    App._fileModules.forEach(fm => fm.subModules.forEach(sm => App._parsedModules.push({ title: sm.title, content: sm.content })));
    $$('ai-course-title').value = App._fileModules[0]?.name || '';
    App.renderModulePreview();
    App.goPhase(2);
  },
  renderModulePreview() {
    $$('module-preview').innerHTML = App._parsedModules.map((m, i) => `
      <div class="mod-builder" style="margin-bottom:var(--space-2)">
        <div class="mod-builder-head" onclick="this.nextElementSibling.classList.toggle('hidden')">
          <span style="flex:1">${esc(m.title)}</span>
          <span style="font-size:var(--text-xs);color:var(--ink-4)">${App.wordCount(m.content)} words ▾</span>
        </div>
        <div class="mod-builder-body hidden" style="font-size:var(--text-sm);line-height:1.6">${m.content}</div>
      </div>`).join('');
  },
  wordCount(html) { return (html || '').replace(/<[^>]*>/g, ' ').split(/\s+/).filter(Boolean).length; },

  async startGeneration() {
    if (App._isGenerating) return;
    const title = $$('ai-course-title').value.trim();
    if (!title) { Toast.err('Enter a course title.'); return; }
    App._isGenerating = true;
    App.goPhase(3);
    const qCount = parseInt($$('q-per-mod').value);
    const difficulty = $$('q-difficulty').value;
    const focus = $$('q-focus').value;
    const total = App._parsedModules.length;
    $$('gen-progress-label').textContent = `0 of ${total}`;
    $$('gen-module-list').innerHTML = App._parsedModules.map((m, i) => `
      <div id="genrow-${i}" style="font-size:var(--text-sm);color:var(--ink-3);margin-bottom:4px">
        ○ ${esc(m.title)}: <span id="genstat-${i}">Waiting...</span>
      </div>`).join('');
    const genMods = [];
    try {
      for (let i = 0; i < total; i++) {
        const mod = App._parsedModules[i];
        $$(`genstat-${i}`).textContent = 'Generating...';
        $$(`genstat-${i}`).style.color = 'var(--brand-1)';
        $$('gen-prog-bar').style.width = `${(i / total) * 100}%`;
        
        // Pass 1: Questions
        const questions = await api('/api/ai/generate', {
          method: 'POST',
          body: JSON.stringify({ type: 'questions', title: mod.title, content: mod.content, qCount, difficulty, focus })
        });
        
        // Pass 2: Summary
        const summary = await api('/api/ai/generate', {
          method: 'POST',
          body: JSON.stringify({ type: 'summary', title: mod.title, content: mod.content })
        });
        
        genMods.push({ ...mod, questions, summary });
        $$(`genstat-${i}`).textContent = 'Done';
        $$(`genstat-${i}`).style.color = 'var(--pass)';
        $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
      }
      App._generatedCourse = {
        title, icon: $$('ai-course-icon').value || CONFIG.DEFAULT_ICON, desc: $$('ai-course-desc').value,
        mods: genMods.map(m => ({
          title: m.title, content: m.content,
          summary: m.summary,
          questions: m.questions.map(q => ({
            q: q.question, opts: q.options, correct: q.correct_index, exp: q.explanation
          }))
        }))
      };
      App.renderAiReview();
      App.goPhase(4);
    } catch (e) {
      Toast.err('Generation failed: ' + e.message);
      App.goPhase(2);
    } finally { App._isGenerating = false; }
  },

  renderAiReview() {
    const c = App._generatedCourse;
    $$('review-modules').innerHTML = c.mods.map((m, i) => `
      <div class="card" style="margin-bottom:var(--space-4)">
        <div class="card-title">${esc(m.title)}</div>
        <div style="font-size:var(--text-sm);color:var(--ink-2);margin-bottom:var(--space-4)">${esc(m.summary?.intro)}</div>
        <div style="font-weight:700;font-size:var(--text-xs);margin-bottom:var(--space-2)">QUESTIONS</div>
        ${m.questions.map((q, qi) => `<div style="font-size:var(--text-sm);margin-bottom:8px">${qi + 1}. ${esc(q.q)}</div>`).join('')}
      </div>`).join('');
  },

  async saveAiCourse() {
    if (!App._generatedCourse) return;
    try {
      // Re-format slightly for the worker expectations if needed, but App.saveCourse handles its own denorm
      // We'll set cbState and call App.saveCourse() logic
      cbState.editId = null;
      cbState.mods = App._generatedCourse.mods.map(m => {
        // Integrate summary into content if needed, or keep it separate if the schema supports it.
        // Current schema for modules: { id, title, content, questions: [...] }
        let content = m.content;
        if (m.summary) {
          content = `<div class="summary-box"><strong>Summary</strong><p>${esc(m.summary.intro)}</p><ul>${(m.summary.bullets||[]).map(b=>`<li>${esc(b)}</li>`).join('')}</ul></div>` + content;
        }
        return {
          id: uid(),
          title: m.title,
          content: content,
          questions: m.questions
        };
      });
      // Set the values in the hidden builder form before calling save
      $$('cb-title').value = App._generatedCourse.title;
      $$('cb-icon').value = App._generatedCourse.icon;
      $$('cb-desc').value = App._generatedCourse.desc;
      
      await App.saveCourse();
      App.aNav('courses');
    } catch (e) {
      Toast.err('Save failed: ' + e.message);
    }
  },

  async renderDash() {
    $$('a-stats').innerHTML = '<p style="color:var(--ink-4);font-size:var(--text-sm);">Loading…</p>';
    $$('a-recent').innerHTML = ''; $$('a-course-stats').innerHTML = '';
    try {
      const { summary, learners, courses } = await api('/api/admin/stats');

      // ── Stat tiles ──────────────────────────────────────────────────────────
      $$('a-stats').innerHTML = [
        ['Total Learners',    summary.total_learners, '👥'],
        ['Total Courses',     summary.total_courses, '📚'],
        ['Completions (Mo)',  summary.completions_this_month, '🏆'],
        ['Pass Rate',         summary.pass_rate + '%', '📈'],
      ].map(([l,v,i])=>`<div class="stat-tile">
        <div style="font-size:24px;margin-bottom:var(--space-2);">${i}</div>
        <div class="stat-value">${v}</div>
        <div class="stat-label">${l}</div>
      </div>`).join('');

      // ── Learner activity table ───────────────────────────────────────────────
      App._dashLearners = learners;
      App._openLearners.clear();
      if (!learners.length) {
        $$('a-recent').innerHTML = '<p style="color:var(--ink-4);font-size:var(--text-sm);margin-top:var(--space-8);">No learner accounts yet.</p>';
      } else {
        $$('a-recent').innerHTML = `
          <div style="font-weight:700;font-size:var(--text-base);margin:var(--space-8) 0 var(--space-4);">Learner Activity</div>
          <div class="table-wrap"><table>
            <thead><tr><th>Name</th><th>Last Login</th><th>Started</th><th>Completed</th><th>Avg Score</th></tr></thead>
            <tbody id="a-learner-tbody">${App._buildLearnerRows()}</tbody>
          </table></div>`;
      }

      // ── Course activity table ────────────────────────────────────────────────
      $$('a-course-stats').innerHTML = !courses.length ? '' : `
        <div style="font-weight:700;font-size:var(--text-base);margin:var(--space-8) 0 var(--space-4);">Course Activity</div>
        <div class="table-wrap"><table>
          <thead><tr><th>Course</th><th>Enrolled</th><th>Completed</th><th>Avg Score</th><th>Pass Rate</th></tr></thead>
          <tbody>${courses.map(c=>`<tr>
            <td>${esc(c.title)}</td>
            <td>${c.enrolled}</td>
            <td>${c.completed}</td>
            <td>${c.avg_score != null ? c.avg_score+'%' : '—'}</td>
            <td><span class="chip ${c.pass_rate>=CONFIG.DEFAULT_PASS?'chip-green':'chip-red'}">${c.pass_rate}%</span></td>
          </tr>`).join('')}</tbody>
        </table></div>`;
    } catch (e) {
      $$('a-stats').innerHTML = `<div class="empty-hint" style="color:var(--fail);">${esc(e.message)}</div>`;
    }
  },

  _openLearners: new Set(),
  _dashLearners: [],

  _buildLearnerRows() {
    return (App._dashLearners || []).map(l => {
      const open = App._openLearners.has(l.id);
      const loginStr = l.last_login_at ? new Date(l.last_login_at*1000).toLocaleDateString() : '—';
      let html = `<tr style="cursor:pointer;" onclick="App._toggleLearner('${l.id}')">
        <td><span style="margin-right:6px;color:var(--ink-4);">${open?'▾':'▸'}</span>${esc(l.name)}</td>
        <td>${loginStr}</td>
        <td>${l.courses_started}</td>
        <td>${l.courses_completed}</td>
        <td>${l.avg_score != null ? l.avg_score+'%' : '—'}</td>
      </tr>`;
      if (open && l.modules.length) {
        html += l.modules.map(m=>`<tr style="background:var(--rule-2);">
          <td colspan="2" style="padding-left:var(--space-10);font-size:var(--text-sm);color:var(--ink-3);">
            <span style="color:${m.passed?'var(--pass)':'var(--fail)'};">${m.passed?'✓':'✗'}</span>
            ${esc(m.course_title)} — ${esc(m.module_title)}
          </td>
          <td colspan="2" style="font-size:var(--text-sm);color:var(--ink-3);">${m.score}%</td>
          <td style="font-size:var(--text-xs);color:var(--ink-4);">${m.completed_at?new Date(m.completed_at*1000).toLocaleDateString():'—'}</td>
        </tr>`).join('');
      }
      return html;
    }).join('');
  },

  _toggleLearner(id) {
    if (App._openLearners.has(id)) App._openLearners.delete(id);
    else App._openLearners.add(id);
    const tbody = $$('a-learner-tbody');
    if (tbody) tbody.innerHTML = App._buildLearnerRows();
  },

  _assignCourseId: null,
  async openAssign(id, title) {
    App._assignCourseId = id;
    $$('assign-subtitle').textContent = `Assign ${title} to learners`;
    $$('assign-overlay').classList.remove('hidden');
    $$('assign-list').innerHTML = '<div style="padding:var(--space-4);text-align:center;color:var(--ink-4);">Loading...</div>';
    try {
      const [learners, assigns] = await Promise.all([
        api('/api/learners'),
        api('/api/assignments')
      ]);
      const courseAssigns = assigns.filter(a => a.course_id === id);
      if (!learners.length) {
        $$('assign-list').innerHTML = '<div style="padding:var(--space-4);text-align:center;color:var(--ink-4);">No learners found.</div>';
        return;
      }
      $$('assign-list').innerHTML = learners.map(l => {
        const assign = courseAssigns.find(a => a.learner_id === l.id);
        const isAssigned = !!assign;
        const dueVal = assign?.due_at ? assign.due_at.split(' ')[0] : '';
        return `<div style="display:flex;align-items:center;justify-content:space-between;padding:var(--space-3) 0;border-bottom:1px solid var(--rule);">
          <div style="flex:1;">
            <div style="font-weight:600;">${esc(l.name)}</div>
            ${isAssigned ? `<div style="display:flex;align-items:center;gap:8px;margin-top:4px;">
              <span style="font-size:10px;color:var(--ink-4);text-transform:uppercase;">Due Date:</span>
              <input type="date" id="due-${l.id}" value="${dueVal}" style="width:auto;padding:2px 4px;font-size:11px;" onchange="App.toggleAssign('${l.id}', true)">
            </div>` : ''}
          </div>
          <button class="btn btn-sm ${isAssigned ? 'btn-ghost' : 'btn-outline'}" onclick="App.toggleAssign('${l.id}', ${isAssigned})">
            ${isAssigned ? 'Unassign' : 'Assign'}
          </button>
        </div>`;
      }).join('');
    } catch (e) {
      $$('assign-list').innerHTML = `<div style="color:var(--fail);padding:var(--space-4);">${esc(e.message)}</div>`;
    }
  },
  closeAssign() {
    $$('assign-overlay').classList.add('hidden');
    App._assignCourseId = null;
  },
  async toggleAssign(learnerId, currentlyAssigned) {
    try {
      // Check if the trigger was a date change or an unassign click
      const isDateChange = event && event.target && event.target.tagName === 'INPUT';
      
      if (currentlyAssigned && !isDateChange) {
        await api('/api/assignments', { method: 'DELETE', body: JSON.stringify({ course_id: App._assignCourseId, learner_id: learnerId }) });
      } else {
        const dueEl = $$(`due-${learnerId}`);
        const due_at = dueEl ? dueEl.value : null;
        await api('/api/assignments', { method: 'POST', body: JSON.stringify({ course_id: App._assignCourseId, learner_id: learnerId, due_at }) });
      }
      const course = coursesCache.find(c => c.id === App._assignCourseId);
      App.openAssign(App._assignCourseId, course ? course.title : 'Course');
    } catch (e) {
      Toast.err('Could not update assignment: ' + e.message);
    }
  },

  async renderACourses() {
    const grid = $$('a-courses-grid');
    grid.classList.add('stagger');
    try {
      const apiCourses = await api('/api/courses');
      const courses    = apiCourses.map(normCourse);
      coursesCache     = courses;
      if(!courses.length){ grid.innerHTML=`<div class="empty"><div class="empty-icon">📝</div><div class="empty-title">No courses</div><div class="empty-hint">Create your first training course.</div></div>`; return; }
      grid.innerHTML = courses.map(c=>{
        const qc=(c.mods||[]).reduce((s,m)=>s+(m.questions||[]).length,0);
        return `<div class="course-card">
        <div class="course-icon">${esc(c.icon||'📚')}</div>
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">
          <div class="course-name">${esc(c.title)}</div>
          <div style="display:flex;gap:4px;">
            <button class="btn btn-ghost btn-sm btn-icon" title="Assign" onclick="event.stopPropagation();App.openAssign('${c.id}', '${esc(c.title)}')">👤</button>
            <button class="btn btn-ghost btn-sm btn-icon" title="Edit" onclick="event.stopPropagation();App.editCourse('${c.id}')">✏</button>
            <button class="btn btn-ghost btn-sm btn-icon" title="Delete" onclick="event.stopPropagation();App.delCourse('${c.id}')">✕</button>
          </div>
        </div>
        <div class="course-desc">${esc(c.desc||'')}</div>
        <div class="course-meta">
          <span>${(c.mods||[]).length} module${(c.mods||[]).length!==1?'s':''}</span>
          <span>${qc} question${qc!==1?'s':''}</span>
        </div>
      </div>`;
      }).join('');
    } catch (e) {
      grid.innerHTML = `<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-title">Could not load courses</div><div class="empty-hint">${esc(e.message)}</div></div>`;
    }
  },

  async renderComps(courseId = '') {
    const tbody = $$('comp-tbody');
    try {
      const path = courseId ? `/api/admin/completions?course_id=${courseId}` : '/api/admin/completions';
      const [recsRaw, apiCourses] = await Promise.all([
        api(path),
        api('/api/courses'),
      ]);
      const recs    = recsRaw; // Already normalized by worker endpoint
      const courses = apiCourses.map(normCourse);
      coursesCache  = courses;
      
      // Populate filter if empty
      const filter = $$('comp-filter');
      if (filter.options.length <= 1) {
        courses.forEach(c => {
          const opt = document.createElement('option');
          opt.value = c.id; opt.textContent = c.title;
          filter.appendChild(opt);
        });
      }

      if(!recs.length){ 
        tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--ink-4);">No records yet.</td></tr>'; 
        $$('comp-pass-rate').textContent = '';
        return; 
      }

      const total = recs.length;
      const passed = recs.filter(r => r.passed).length;
      const rate = Math.round((passed / total) * 100);
      $$('comp-pass-rate').textContent = `Avg Pass Rate: ${rate}%`;

      tbody.innerHTML = recs.map(r=>{
        return `<tr>
        <td>${esc(r.user_name)}</td>
        <td>${esc(r.course_title)}</td>
        <td><span class="chip ${r.passed?'chip-green':'chip-red'}">${r.score}%</span></td>
        <td><span class="chip ${r.passed?'chip-green':'chip-red'}">${r.passed?'Passed':'Failed'}</span></td>
        <td>${new Date(r.completed_at * 1000).toLocaleDateString()}</td>
        <td><span style="font-family:monospace;font-size:10px;">${r.cert_id || '—'}</span></td>
      </tr>`;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--fail);">${esc(e.message)}</td></tr>`;
    }
  },

  // ─── LEARNER MANAGEMENT (ADMIN) ───
  async renderLearners() {
    const tbody = $$('learners-tbody');
    try {
      const learners = await api('/api/learners');
      if(!learners.length){ tbody.innerHTML='<tr><td colspan="4" style="text-align:center;padding:32px;color:var(--ink-4);">No learners yet. Add one to get started.</td></tr>'; return; }
      tbody.innerHTML = learners.map(l=>{
        const lastLogin = l.last_login_at ? new Date(l.last_login_at*1000).toLocaleDateString() : '—';
        const overdueBadge = l.overdue_count > 0 ? `<span class="chip chip-red" style="margin-left:8px;font-size:10px;">⚠️ ${l.overdue_count} overdue</span>` : '';
        return `<tr>
          <td>${esc(l.name)}${overdueBadge}</td>
          <td>${lastLogin}</td>
          <td>${l.completion_count}</td>
          <td style="display:flex;gap:4px;">
            <button class="btn btn-ghost btn-sm" onclick="App.openResetPw('${l.id}','${esc(l.name)}')">Reset Password</button>
            <button class="btn btn-ghost btn-sm" style="color:var(--fail);" onclick="App.openConfirmDelete('${l.id}','${esc(l.name)}')">Delete</button>
          </td>
        </tr>`;
      }).join('');
    } catch(e) {
      const detail = e.detail ? `<div style="font-size:11px;opacity:0.7;margin-top:8px;">${esc(e.detail)}</div>` : '';
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:32px;color:var(--fail);">
        ${esc(e.message)}
        ${detail}
      </td></tr>`;
    }
  },

  // Add Learner modal
  openAddLearner() { $$('al-name').value=''; $$('al-pw1').value=''; $$('al-pw2').value=''; $$('add-learner-overlay').classList.remove('hidden'); setTimeout(()=>$$('al-name').focus(),CONFIG.FOCUS_DELAY); },
  closeAddLearner() { $$('add-learner-overlay').classList.add('hidden'); },
  async submitAddLearner() {
    const name = $$('al-name').value.trim();
    const pw1  = $$('al-pw1').value;
    const pw2  = $$('al-pw2').value;
    if(!name){ Toast.err('Name is required.'); return; }
    if(pw1.length < 8){ Toast.err('Password must be at least 8 characters.'); return; }
    if(pw1 !== pw2){ Toast.err('Passwords do not match.'); return; }
    try {
      await api('/api/learners', { method:'POST', body:JSON.stringify({ name, password:pw1 }) });
      App.closeAddLearner();
      App.renderLearners();
      Toast.ok(`Account created for ${name}.`);
    } catch(e){ Toast.err(e.message || 'Could not create account.'); }
  },

  // Reset Password modal
  _resetPwId: null,
  openResetPw(id, name) { App._resetPwId=id; $$('reset-pw-subtitle').textContent=`Reset password for ${name}`; $$('rp-pw1').value=''; $$('rp-pw2').value=''; $$('reset-pw-overlay').classList.remove('hidden'); setTimeout(()=>$$('rp-pw1').focus(),CONFIG.FOCUS_DELAY); },
  closeResetPw() { $$('reset-pw-overlay').classList.add('hidden'); App._resetPwId=null; },
  async submitResetPw() {
    const pw1 = $$('rp-pw1').value, pw2 = $$('rp-pw2').value;
    if(pw1.length < 8){ Toast.err('Password must be at least 8 characters.'); return; }
    if(pw1 !== pw2){ Toast.err('Passwords do not match.'); return; }
    try {
      await api(`/api/learners/${App._resetPwId}/password`, { method:'PUT', body:JSON.stringify({ password:pw1 }) });
      App.closeResetPw();
      Toast.ok('Password reset.');
    } catch(e){ Toast.err(e.message || 'Could not reset password.'); }
  },

  // Confirm Delete modal
  _deleteId: null,
  openConfirmDelete(id, name) {
    App._deleteId = id;
    $$('confirm-delete-msg').textContent = `Delete ${name}? This will also remove all their completion records.`;
    $$('confirm-delete-btn').onclick = App.submitDelete;
    $$('confirm-delete-overlay').classList.remove('hidden');
  },
  closeConfirmDelete() { $$('confirm-delete-overlay').classList.add('hidden'); App._deleteId=null; },
  async submitDelete() {
    try {
      await api(`/api/learners/${App._deleteId}`, { method:'DELETE' });
      App.closeConfirmDelete();
      App.renderLearners();
      Toast.ok('Learner deleted.');
    } catch(e){ Toast.err(e.message || 'Could not delete learner.'); }
  },

  // Change password (learner self-service)
  async changeLearnerPw() {
    const cur  = $$('lcp-cur').value;
    const nw   = $$('lcp-new').value;
    const conf = $$('lcp-confirm').value;
    if(!cur){ Toast.err('Enter your current password.'); return; }
    if(nw.length < 8){ Toast.err('New password must be at least 8 characters.'); return; }
    if(nw !== conf){ Toast.err('Passwords do not match.'); return; }
    try {
      await learnerApi('/api/learners/me/password', { method:'PUT', body:JSON.stringify({ current_password:cur, new_password:nw }) });
      $$('lcp-cur').value=''; $$('lcp-new').value=''; $$('lcp-confirm').value='';
      Toast.ok('Password updated.');
    } catch(e){ Toast.err(e.message || 'Could not update password.'); }
  },

  // ─── COURSE BUILDER ───
  openBuilder(editId) {
    cbState.editId = editId || null;
    cbState.mods = [];
    if(editId) {
      const c = coursesCache.find(x=>x.id===editId);
      if(c) {
        $$('cb-title').value = c.title;
        $$('cb-icon').value  = c.icon||'';
        $$('cb-desc').value  = c.desc||'';
        cbState.mods = JSON.parse(JSON.stringify(c.mods||[]));
        $$('builder-title').textContent = 'Edit Course';
      }
    } else {
      $$('cb-title').value = ''; $$('cb-icon').value = ''; $$('cb-desc').value = '';
      $$('builder-title').textContent = 'New Course';
    }
    App.renderMods();
    $$('builder-overlay').classList.remove('hidden');
  },
  closeBuilder() { $$('builder-overlay').classList.add('hidden'); },
  editCourse(id)  { App.openBuilder(id); App.aNav('courses'); },
  async delCourse(id) {
    if(!confirm('Delete this course?')) return;
    try {
      await api(`/api/courses/${id}`, { method: 'DELETE' });
      coursesCache = coursesCache.filter(c => c.id !== id);
      App.renderACourses();
      Toast.ok('Course deleted.');
    } catch (e) {
      Toast.err(e.message || 'Could not delete course.');
    }
  },

  addMod() {
    cbState.mods.push({ id: uid(), title: 'New Module', content: '', questions: [] });
    App.renderMods();
  },

  renderMods() {
    const el = $$('mods-builder');
    if(!cbState.mods.length) { el.innerHTML=`<div class="empty" style="padding:var(--space-8) 0;"><div class="empty-icon">📝</div><div class="empty-title">No modules</div><div class="empty-hint">Add a module or import from CSV / JSON.</div></div>`; return; }
    el.innerHTML = cbState.mods.map((m,mi)=>`
    <div class="mod-builder">
      <div class="mod-builder-head" onclick="App.toggleMod(${mi})">
        <span style="font-size:var(--text-xs);color:var(--ink-4);font-weight:700;">MODULE ${mi+1}</span>
        <input type="text" value="${esc(m.title)}" placeholder="Module title…" onclick="event.stopPropagation()" oninput="cbState.mods[${mi}].title=this.value" style="flex:1;margin:0 var(--space-3);background:transparent;border:none;font-weight:600;font-size:var(--text-base);color:var(--ink);padding:0;box-shadow:none;" tabindex="0">
        <span style="font-size:var(--text-xs);color:var(--ink-4);">${(m.questions||[]).length} q</span>
        <button class="btn btn-ghost btn-sm btn-icon" onclick="event.stopPropagation();cbState.mods.splice(${mi},1);App.renderMods()" style="margin-left:4px;">✕</button>
      </div>
      <div class="mod-builder-body" id="mb-${mi}">
        <div class="field">
          <label>Content (HTML or plain text)</label>
          <textarea placeholder="<h2>Topic</h2><p>Content…</p>" oninput="cbState.mods[${mi}].content=this.value">${esc(m.content||'')}</textarea>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-3);">
          <label style="margin:0;">Questions (${(m.questions||[]).length})</label>
          <button class="btn btn-outline btn-sm" onclick="App.addQ(${mi})">+ Question</button>
        </div>
        <div id="qs-${mi}">${(m.questions||[]).map((q,qi)=>App.renderQBlock(mi,qi,q)).join('')}</div>
      </div>
    </div>`).join('');
  },

  toggleMod(mi) { const b=$$(`mb-${mi}`); b.style.display=b.style.display==='none'?'':'none'; },

  renderQBlock(mi, qi, q) {
    const ls=['A','B','C','D'];
    return `<div class="q-block">
      <div class="field"><label>Question ${qi+1}</label><input type="text" value="${esc(q.q||q.question||'')}" placeholder="Question text…" oninput="cbState.mods[${mi}].questions[${qi}].q=this.value;cbState.mods[${mi}].questions[${qi}].question=this.value"></div>
      <div class="q-opts-grid">${(q.opts||q.options||['','','','']).map((o,oi)=>`<div class="q-opt-row"><span class="opt-ltr">${ls[oi]}</span><input type="text" value="${esc(o)}" placeholder="Option ${ls[oi]}" oninput="(cbState.mods[${mi}].questions[${qi}].opts||(cbState.mods[${mi}].questions[${qi}].opts=['','','','']))[${oi}]=this.value;(cbState.mods[${mi}].questions[${qi}].options||(cbState.mods[${mi}].questions[${qi}].options=['','','','']))[${oi}]=this.value"></div>`).join('')}</div>
      <div class="field-row" style="margin-top:var(--space-3);">
        <div class="field" style="margin:0;"><label>Correct Answer</label><select oninput="cbState.mods[${mi}].questions[${qi}].correct=parseInt(this.value)">${['A','B','C','D'].map((l,i)=>`<option value="${i}"${q.correct===i?' selected':''}>${l}</option>`).join('')}</select></div>
        <div class="field" style="margin:0;"><label>Explanation</label><input type="text" value="${esc(q.exp||q.explanation||'')}" placeholder="Why this is correct…" oninput="cbState.mods[${mi}].questions[${qi}].exp=this.value"></div>
      </div>
      <div style="text-align:right;margin-top:8px;"><button class="btn btn-ghost btn-sm" onclick="cbState.mods[${mi}].questions.splice(${qi},1);App.renderMods()">Remove</button></div>
    </div>`;
  },

  addQ(mi) {
    cbState.mods[mi].questions.push({ q:'', opts:['','','',''], correct:0, exp:'' });
    App.renderMods();
    setTimeout(()=>{ const c=$$(`qs-${mi}`); if(c&&c.lastElementChild) c.lastElementChild.scrollIntoView({behavior:'smooth',block:'nearest'}); },50);
  },

  async saveCourse() {
    const title = $$('cb-title').value.trim();
    if(!title){ Toast.err('Please enter a course title.'); return; }
    const courseData = {
      title, icon: $$('cb-icon').value||CONFIG.DEFAULT_ICON, desc: $$('cb-desc').value,
      mods: cbState.mods.map(m=>({
        ...m,
        questions: (m.questions||[]).map(q=>({
          q: q.q||q.question||'',
          opts: q.opts||q.options||['','','',''],
          correct: typeof q.correct==='number'?q.correct:0,
          exp: q.exp||q.explanation||''
        }))
      }))
    };
    const body = denormCourseBody(courseData);
    try {
      if(cbState.editId) {
        await api(`/api/courses/${cbState.editId}`, { method: 'PUT', body: JSON.stringify(body) });
      } else {
        await api('/api/courses', { method: 'POST', body: JSON.stringify(body) });
      }
      App.closeBuilder();
      App.renderACourses();
      Toast.ok(cbState.editId?'Course updated.':'Course created.');
    } catch (e) {
      Toast.err(e.message || 'Could not save course.');
    }
  },

  // ─── CSV IMPORT ───
  csvImportOpen() { csvParsed=null; $$('csv-preview').classList.add('hidden'); $$('csv-confirm').disabled=true; $$('csv-overlay').classList.remove('hidden'); },
  csvClose()      { $$('csv-overlay').classList.add('hidden'); },
  csvDrop(e) { e.preventDefault(); $$('csv-drop-zone').classList.remove('drag-active'); const f=e.dataTransfer.files[0]; if(f) App.csvProcess(f); },
  csvFileSelected(e) { if(e.target.files[0]) App.csvProcess(e.target.files[0]); },

  csvProcess(file) {
    const reader = new FileReader();
    reader.onload = e => {
      try {
        if(file.name.endsWith('.json')) csvParsed = JSON.parse(e.target.result);
        else csvParsed = App.parseCSV(e.target.result);
        App.csvPreview();
      } catch(err) { Toast.err('Could not read file: '+err.message); }
    };
    reader.readAsText(file);
  },

  parseCSV(raw) {
    const lines = raw.trim().split(/\r?\n/);
    const hdr = lines[0].split(',').map(h=>h.replace(/^"|"$/g,'').trim());
    return lines.slice(1).filter(l=>l.trim()).map(line=>{
      // handle quoted CSV values
      const vals=[]; let cur='', inQ=false;
      for(let i=0;i<line.length;i++){
        if(line[i]==='"'){inQ=!inQ;}
        else if(line[i]===','&&!inQ){vals.push(cur.trim());cur='';}
        else cur+=line[i];
      }
      vals.push(cur.trim());
      const obj={}; hdr.forEach((h,i)=>obj[h]=vals[i]||'');
      const correctLetter = (obj.correct||obj.Correct||'A').toUpperCase();
      return {
        module: obj.module||obj.Module||'Imported',
        question: obj.question||obj.Question||obj.q||'',
        options: [obj.optionA||obj.A||'',obj.optionB||obj.B||'',obj.optionC||obj.C||'',obj.optionD||obj.D||''],
        correct: Math.max(0,['A','B','C','D'].indexOf(correctLetter)),
        explanation: obj.explanation||obj.Explanation||''
      };
    }).filter(q=>q.question);
  },

  csvPreview() {
    if(!csvParsed||!csvParsed.length){ Toast.err('No questions found.'); return; }
    const mods = [...new Set(csvParsed.map(q=>q.module||'General'))];
    const prev = $$('csv-preview');
    prev.classList.remove('hidden');
    prev.innerHTML = `<div class="card" style="background:var(--pass-lt);border-color:#bbf7d0;">
      <div style="font-weight:600;color:var(--pass);margin-bottom:var(--space-2);">✓ ${csvParsed.length} question${csvParsed.length!==1?'s':''} ready to import</div>
      <div style="font-size:var(--text-xs);color:var(--ink-3);">Modules: ${mods.map(m=>`<span class="chip chip-blue" style="margin:2px;">${esc(m)}</span>`).join('')}</div>
    </div>`;
    $$('csv-confirm').disabled = false;
  },

  csvConfirm() {
    if(!csvParsed) return;
    const byMod = {};
    csvParsed.forEach(q=>{ const m=q.module||'General'; if(!byMod[m]) byMod[m]=[]; byMod[m].push({q:q.question,opts:q.options,correct:q.correct>=0?q.correct:0,exp:q.explanation}); });
    Object.entries(byMod).forEach(([name,qs])=>{
      const ex = cbState.mods.find(m=>m.title===name);
      if(ex) ex.questions.push(...qs);
      else cbState.mods.push({id:uid(),title:name,content:`<h2>${name}</h2><p>Complete the competency questions below.</p>`,questions:qs});
    });
    App.csvClose();
    App.renderMods();
    Toast.ok(`Imported ${csvParsed.length} questions into ${Object.keys(byMod).length} module${Object.keys(byMod).length!==1?'s':''}.`);
    csvParsed = null;
  },

  // ─── COURSE VIEWER ───
  async startCourse(cid) {
    try {
      let course = coursesCache.find(c => c.id === cid);
      if (!course) {
        const raw = await api(`/api/courses/${cid}`);
        course = normCourse(raw);
      }
      curCourse = course;
      curModIdx = 0; quizSt = {};
      // Restore saved module progress from server
      if (getLearnerToken()) {
        try {
          const progress = await learnerApi(`/api/progress/${cid}`);
          curCourse.mods.forEach((m, i) => {
            const p = progress.find(r => r.module_id === m.id);
            if (p) quizSt[i] = { done: true, passed: p.passed, score: p.score, ans: [], session: null };
          });
        } catch(e) { /* silent fail, continue without saved progress */ }
      }
      $$('ch-meta').textContent = curCourse.title;
      App.show('screen-course');
      App.renderModNav();
      // Start at first incomplete (not yet passed) module
      const firstIncomplete = curCourse.mods.findIndex((_,i) => !quizSt[i]?.passed);
      App.loadMod(firstIncomplete >= 0 ? firstIncomplete : 0);
    } catch (e) {
      Toast.err('Could not load course: ' + e.message);
    }
  },

  exitCourse() { $$('screen-course').classList.remove('focus-mode'); App.show('screen-learner'); App.lNav('courses'); },
  retakeModule(mi) { delete quizSt[mi]; App.loadMod(mi); },

  renderModNav() {
    const list = $$('mod-nav-list');
    list.innerHTML = (curCourse.mods||[]).map((m,i)=>{
      const st = quizSt[i];
      let cls = i===curModIdx?'active':'';
      let icon = i+1;
      if(st?.done && st?.passed) { cls+=' done-pass'; icon='✓'; }
      else if(st?.done) { cls+=' done-fail'; icon='✗'; }
      return `<div class="mod-item ${cls}" onclick="App.loadMod(${i})">
        <div class="mod-bullet">${icon}</div>
        <span>${esc(m.title)}</span>
      </div>`;
    }).join('');
    App.updateProgress();
  },

  updateProgress() {
    const total = (curCourse.mods||[]).length;
    const done = Object.values(quizSt).filter(s => s?.passed).length;
    const pct = total ? Math.round(done/total*100) : 0;
    $$('ch-prog').style.width = pct+'%';
    $$('ch-label').textContent = `${done} / ${total} complete`;
  },

  loadMod(idx) {
    curModIdx = idx;
    App.renderModNav();
    const mod = curCourse.mods[idx];
    const main = $$('mod-main');
    const st = quizSt[idx];
    // Failed: show results screen with retry option
    if (st?.done && !st?.passed) { App.showModResults(idx); return; }
    // Passed: show content with a "already complete" banner
    const banner = st?.passed ? `<div style="background:var(--pass-lt);border:1px solid var(--pass);border-radius:var(--r);padding:var(--space-4) var(--space-5);margin-bottom:var(--space-6);display:flex;align-items:center;gap:var(--space-3);"><span style="color:var(--pass);font-size:20px;line-height:1;">✓</span><div><strong style="color:var(--pass);">Module Complete</strong> — You passed with ${st.score}%. Retake the quiz below to improve your score.</div></div>` : '';
    const btnLabel = st?.passed ? 'Retake Competency Check' : 'Begin Competency Check →';
    main.innerHTML = `<div class="module-prose">
      ${banner}
      ${mod.content || `<h2>${esc(mod.title)}</h2><p>Study this module carefully before attempting the competency check.</p>`}
      <div style="border-top:1px solid var(--rule);margin-top:var(--space-10);padding-top:var(--space-8);text-align:center;">
        <p style="color:var(--ink-3);margin-bottom:var(--space-5);">${(mod.questions||[]).length} question${(mod.questions||[]).length!==1?'s':''} in the competency check.</p>
        <button class="btn btn-primary btn-lg" onclick="App.startQuiz(${idx})">${btnLabel}</button>
      </div>
    </div>`;
  },

  async startQuiz(idx) {
    const qs = curCourse.mods[idx].questions || [];
    if (!qs.length) {
      quizSt[idx] = { done:true, passed:true, score:100, ans:[], session:null };
      App.renderModNav(); await App.checkDone();
      learnerApi('/api/progress', {
        method: 'POST',
        body: JSON.stringify({ module_id: curCourse.mods[idx].id, course_id: curCourse.id, passed: true, score: 100 }),
      }).catch(e => { /* fire and forget fail */ });
      App.loadMod(idx + 1 < curCourse.mods.length ? idx + 1 : idx);
      return;
    }
    // Store session state in quizSt — no data travels through onclick attributes
    quizSt[idx] = { done: false, session: { qs, ans: [] } };
    App.renderQ(idx, 0);
  },

  renderQ(mi, qi) {
    // Use quizSt[mi].session to hold live quiz session data — no data in onclick attrs
    const session = quizSt[mi].session;
    const qs = session.qs;
    const q = qs[qi];
    const ls = ['A','B','C','D'];
    const main = $$('mod-main');
    main.innerHTML = `<div class="quiz-wrap">
      <div class="quiz-header">
        <div class="quiz-step">${esc(curCourse.mods[mi].title)} · Question ${qi+1} of ${qs.length}</div>
        <div class="progress-track" style="height:4px;margin-bottom:var(--space-5);"><div class="progress-fill" style="width:${qi/qs.length*100}%"></div></div>
        <div class="quiz-q">${esc(q.q||q.question||'')}</div>
      </div>
      <div class="quiz-options" id="quiz-opts">
        ${(q.opts||q.options||[]).map((o,oi)=>o?`<div class="quiz-opt" data-idx="${oi}">
          <div class="opt-letter">${ls[oi]}</div><span>${esc(o)}</span>
        </div>`:'').join('')}
      </div>
    </div>`;
    // Attach click handlers via JS — safe from any special characters in question text
    main.querySelectorAll('.quiz-opt').forEach(el => {
      el.addEventListener('click', () => App.answer(mi, qi, parseInt(el.dataset.idx)));
    });
  },

  answer(mi, qi, sel) {
    const session = quizSt[mi].session;
    const qs = session.qs;
    const q = qs[qi];
    const ok = sel === q.correct;
    session.ans.push({sel, correct: q.correct, ok});

    const opts = $$('mod-main').querySelectorAll('.quiz-opt');
    opts.forEach((el, i) => {
      el.style.pointerEvents = 'none';
      if (i === q.correct) el.classList.add('correct', 'pulse');
      if (i === sel && !ok) el.classList.add('wrong', 'shake');
    });

    if (ok) Toast.ok('Correct!'); else Toast.err('Incorrect answer.');

    const fb = document.createElement('div');
    fb.className = `quiz-feedback ${ok?'fb-pass':'fb-fail'}`;
    fb.innerHTML = ok
      ? `✓ Correct${q.exp ? ` — ${esc(q.exp)}` : ''}`
      : `✗ Incorrect${q.exp ? ` — ${esc(q.exp)}` : ''}`;
    const wrap = $$('mod-main').querySelector('.quiz-wrap');
    wrap.querySelector('.quiz-options').after(fb);

    const next = document.createElement('button');
    const last = qi + 1 >= qs.length;
    next.className = 'btn btn-primary'; next.style.marginTop = 'var(--space-2)';
    next.textContent = last ? 'View Results' : 'Next →';
    next.addEventListener('click', () => last ? App.finishQuiz(mi) : App.renderQ(mi, qi + 1));
    fb.after(next);
  },

  async finishQuiz(mi) {
    const session = quizSt[mi].session;
    const ans = session.ans;
    const score = Math.round(ans.filter(a=>a.ok).length / ans.length * 100);
    const passed = score >= (brandCache.pass || CONFIG.DEFAULT_PASS);
    quizSt[mi] = { done:true, passed, score, ans, session: null };
    App.renderModNav();
    await App.checkDone();
    App.showModResults(mi);
    // Persist module result to server
    learnerApi('/api/progress', {
      method: 'POST',
      body: JSON.stringify({ module_id: curCourse.mods[mi].id, course_id: curCourse.id, passed, score }),
    }).catch(e => { /* silent fail */ });
  },

  showModResults(mi) {
    const st = quizSt[mi];
    const mod = curCourse.mods[mi];
    const isLast = mi+1 >= curCourse.mods.length;
    const r=54, c=2*Math.PI*r, offset=c-(st.score/100)*c;
    const col = st.passed?'var(--pass)':'var(--fail)';
    $$('mod-main').innerHTML = `<div class="results-wrap">
      <div class="score-ring-wrap">
        <svg viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--rule)" stroke-width="10"/>
          <circle cx="70" cy="70" r="${r}" fill="none" stroke="${col}" stroke-width="10" stroke-dasharray="${c}" stroke-dashoffset="${offset}" stroke-linecap="round"/>
        </svg>
        <div class="score-ring-inner">
          <div class="score-big" style="color:${col}">${st.score}%</div>
          <div class="score-lbl" style="color:${st.passed?'var(--pass)':'var(--fail)'}">${st.passed?'PASSED':'FAILED'}</div>
        </div>
      </div>
      <div class="results-title">${st.passed?'Module Complete':'Keep Studying'}</div>
      <div class="results-sub">${st.passed?`You passed <em>${esc(mod.title)}</em> with ${st.score}%.`:`You scored ${st.score}%. Review the material and try again.`}</div>
      <div style="display:flex;gap:var(--space-3);justify-content:center;flex-wrap:wrap;">
        ${!st.passed?`<button class="btn btn-outline btn-lg" onclick="App.retakeModule(${mi})">Review & Retry</button>`:''}
        ${st.passed&&!isLast?`<button class="btn btn-primary btn-lg" onclick="App.loadMod(${mi+1})">Next Module →</button>`:''}
        ${st.passed&&isLast?`<button class="btn btn-primary btn-lg" onclick="App.courseComplete()">Get Certificate →</button>`:''}
      </div>
    </div>`;
  },

  async checkDone() {
    const allPassed = (curCourse.mods||[]).every((_,i) => quizSt[i]?.passed);
    if (!allPassed) return null;
    const modScores = (curCourse.mods||[]).map((_,i) => quizSt[i]?.score ?? 0);
    const score  = modScores.length ? Math.round(modScores.reduce((a,b)=>a+b,0) / modScores.length) : 100;
    const passed = score >= (brandCache.pass || CONFIG.DEFAULT_PASS);
    try {
      const res = await learnerApi('/api/completions', {
        method: 'POST',
        body: JSON.stringify({ course_id: curCourse.id, score, passed }),
      });
      return res; // { id, cert_id, passed, score, completed_at }
    } catch(e) { 
      Toast.err("Couldn't save your progress. Please check your connection.");
      return { passed, score, error: true };
    }
  },

  async courseComplete() {
    try {
      const res = await App.checkDone();
      if (res && res.passed) {
        confetti({
          particleCount: 150,
          spread: 70,
          origin: { y: 0.6 },
          colors: [brandCache.c1, brandCache.c2, '#ffffff']
        });
        App.showCert(curCourse.id, curLearner.name, res.cert_id);
      } else if (res) {
        Toast.info(`Course finished. Score: ${res.score}%`);
        App.exitCourse();
      } else {
        App.exitCourse();
      }
    } catch (e) {
      App.exitCourse();
    }
  },

  // ─── CERTIFICATE ───
  async showCert(cid, learner, knownCertId) {
    try {
      const cached = coursesCache.find(c => c.id === cid);
      const fetchRecs = getLearnerToken()
        ? learnerApi('/api/completions/me')
        : api(`/api/completions/learner/${encodeURIComponent(learner)}`);
      const [course, apiRecs] = await Promise.all([
        cached ? Promise.resolve(cached) : api(`/api/courses/${cid}`).then(normCourse),
        fetchRecs,
      ]);
      const recs = apiRecs.map(normRecord).filter(r => r.cid === cid && r.passed);
      if(!recs.length||!course){ Toast.err('No passing record found.'); return; }
      const best = recs.sort((a,z)=>z.score-a.score)[0];
      const b = brandCache;
      const cId = knownCertId || best.cid2 || ('TF-' + uid().slice(0,8).toUpperCase());
      
      $$('cert-accent').style.background = b.c1||CONFIG.DEFAULT_C1;
      $$('c-org').textContent = b.name||CONFIG.DEFAULT_BRAND_NAME;
      $$('c-name').textContent = learner;
      $$('c-course').textContent = course.title;
      $$('c-date').textContent = new Date(best.date).toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'});
      $$('c-score').textContent = best.score+'%';
      $$('c-id').textContent = cId;
      
      // Verification line
      let vEl = $$('c-verify');
      if(!vEl) {
        vEl = document.createElement('div');
        vEl.id = 'c-verify';
        vEl.style.fontSize = '9px';
        vEl.style.color = 'var(--ink-4)';
        vEl.style.marginTop = '4px';
        vEl.style.textAlign = 'center';
        $$('c-id').after(vEl);
      }
      vEl.textContent = `Verify at ${WORKER_URL}/api/certificates/${cId}`;

      $$('c-sig-dept').textContent = (b.name||CONFIG.DEFAULT_BRAND_NAME) + ' Training';
      $$('cert-overlay').classList.remove('hidden');
    } catch (e) {
      Toast.err('Could not load certificate: ' + e.message);
    }
  },

  closeCert() { $$('cert-overlay').classList.add('hidden'); },

  downloadCertPDF() {
    const sheet = $$('cert-sheet');
    const controls = document.querySelector('.cert-controls');
    controls.style.visibility = 'hidden';
    Toast.info('Generating PDF…');
    html2canvas(sheet, { scale: 2, useCORS: true, backgroundColor: '#ffffff' }).then(canvas => {
      controls.style.visibility = '';
      const { jsPDF } = window.jspdf;
      const pdf = new jsPDF({ orientation: 'landscape', unit: 'px', format: [canvas.width/2, canvas.height/2] });
      pdf.addImage(canvas.toDataURL('image/png'), 'PNG', 0, 0, canvas.width/2, canvas.height/2);
      const name = $$('c-name').textContent.replace(/\s+/g,'-');
      const course = $$('c-course').textContent.replace(/\s+/g,'-');
      pdf.save(`Certificate-${name}-${course}.pdf`);
      Toast.ok('PDF downloaded!');
    }).catch(e=>{ controls.style.visibility=''; Toast.err('PDF generation failed: '+e.message); });
  },

  // ─── BRANDING ───
  previewBrand() {
    const c1 = $$('br-c1').value;
    const c2 = $$('br-c2').value;
    document.documentElement.style.setProperty('--brand-1', c1);
    document.documentElement.style.setProperty('--brand-2', c2);
    $$('br-c1-hex').value = c1; $$('br-c2-hex').value = c2;
    const name = $$('br-name').value;
    ['ldg-brand','l-brand','a-brand'].forEach(id=>{ const el=$$(id);if(el)el.textContent=name||CONFIG.DEFAULT_BRAND_NAME; });
    const pn=$$('br-prev-name'); if(pn) pn.textContent=name||CONFIG.DEFAULT_BRAND_NAME;
    const lu=$$('br-logo-url').value;
    if(lu){ const pl=$$('br-prev-logo'); if(pl){pl.src=lu;pl.style.display='block';} }
  },
  syncHex(pid, hid) {
    const v=$$( hid).value;
    if(/^#[0-9a-f]{6}$/i.test(v)){ $$(pid).value=v; App.previewBrand(); }
  },
  uploadLogo(e) {
    const f=e.target.files[0]; if(!f) return;
    const r=new FileReader();
    r.onload=ev=>{ $$('br-logo-url').value=ev.target.result; App.previewBrand(); };
    r.readAsDataURL(f);
  },
  async saveBrand() {
    const body = {
      org_name:        $$('br-name').value || CONFIG.DEFAULT_BRAND_NAME,
      tagline:         $$('br-tag').value  || 'Training & Certification Platform',
      logo_url:        $$('br-logo-url').value || '',
      primary_color:   $$('br-c1').value  || CONFIG.DEFAULT_C1,
      secondary_color: $$('br-c2').value  || CONFIG.DEFAULT_C2,
      pass_threshold:  parseInt($$('br-pass').value) || CONFIG.DEFAULT_PASS,
    };
    try {
      const updated = await api('/api/brand', { method: 'PUT', body: JSON.stringify(body) });
      brandCache = normBrand(updated);
      applyBrand();
      Toast.ok('Branding saved.');
    } catch (e) {
      Toast.err(e.message || 'Could not save branding.');
    }
  },
  async resetBrand() {
    try {
      const updated = await api('/api/brand', {
        method: 'PUT',
        body: JSON.stringify({ org_name:CONFIG.DEFAULT_BRAND_NAME, tagline:'Training & Certification Platform', logo_url:'', primary_color:CONFIG.DEFAULT_C1, secondary_color:CONFIG.DEFAULT_C2, pass_threshold:CONFIG.DEFAULT_PASS }),
      });
      brandCache = normBrand(updated);
      applyBrand();
      Toast.info('Reset to default.');
    } catch (e) {
      Toast.err(e.message || 'Could not reset branding.');
    }
  },

  // ─── SETTINGS ───
  async changePw() {
    const p=$$('np1').value, c=$$('np2').value;
    if(!p){ Toast.err('Enter a new password.'); return; }
    if(p!==c){ Toast.err('Passwords do not match.'); return; }
    try {
      await api('/api/auth/password', { method: 'PUT', body: JSON.stringify({ password: p }) });
      $$('np1').value=''; $$('np2').value='';
      Toast.ok('Password updated.');
    } catch (e) {
      Toast.err(e.message || 'Could not update password.');
    }
  },
  async exportCSV() {
    try {
      const [compData, apiCourses] = await Promise.all([
        api('/api/completions?limit=500'),
        api('/api/courses'),
      ]);
      const recs    = compData.rows.map(normRecord);
      const courses = apiCourses.map(normCourse);
      const hdr='Name,Course,Score,Passed,Date,CertID';
      const rows=recs.map(r=>{ const c=courses.find(x=>x.id===r.cid); return [`"${r.learner}"`,`"${c?.title||''}"`,`"${r.score}%"`,`"${r.passed?'Yes':'No'}"`,`"${new Date(r.date).toLocaleDateString()}"`,`"${r.cid2||''}"`].join(','); });
      App.dl('completions.csv','text/csv',[hdr,...rows].join('\n'));
      Toast.ok('CSV exported.');
    } catch (e) {
      Toast.err(e.message || 'Export failed.');
    }
  },
  async exportBackup() {
    try {
      const [apiCourses, compData, apiBrand] = await Promise.all([
        api('/api/courses'),
        api('/api/completions?limit=500'),
        api('/api/brand'),
      ]);
      App.dl('trainflow-backup.json','application/json',JSON.stringify({ version:2, date:new Date().toISOString(), courses:apiCourses, completions:compData.rows, brand:apiBrand },null,2));
      Toast.ok('Backup exported.');
    } catch (e) {
      Toast.err(e.message || 'Export failed.');
    }
  },
  importBackup(e) {
    const f=e.target.files[0]; if(!f) return;
    const r=new FileReader();
    r.onload=async ev=>{
      try {
        const d=JSON.parse(ev.target.result);
        const isV2 = d.version === 2;
        if(d.brand) {
          const brandBody = isV2
            ? { org_name:d.brand.org_name, tagline:d.brand.tagline, logo_url:d.brand.logo_url, primary_color:d.brand.primary_color, secondary_color:d.brand.secondary_color, pass_threshold:d.brand.pass_threshold }
            : { org_name:d.brand.name, tagline:d.brand.tagline, logo_url:d.brand.logo, primary_color:d.brand.c1, secondary_color:d.brand.c2, pass_threshold:d.brand.pass };
          const updated = await api('/api/brand', { method:'PUT', body:JSON.stringify(brandBody) });
          brandCache = normBrand(updated); applyBrand();
        }
        
        let imported = 0, skipped = 0;
        if(d.courses?.length) {
          // Get current courses to check for duplicates by title
          const currentCourses = await api('/api/courses');
          const existingTitles = new Set(currentCourses.map(c => c.title.toLowerCase()));

          for(const c of d.courses) {
            if (existingTitles.has(c.title.toLowerCase())) {
              skipped++;
              continue;
            }
            const body = isV2
              ? { title:c.title, icon:c.icon, description:c.description, modules:(c.modules||[]).map(m=>({ title:m.title, content:m.content, questions:(m.questions||[]).map(q=>({ question:q.question, options:[q.option_a,q.option_b,q.option_c,q.option_d], correct_index:q.correct_index, explanation:q.explanation })) })) }
              : denormCourseBody(c);
            await api('/api/courses', { method:'POST', body:JSON.stringify(body) });
            imported++;
          }
        }
        App.renderDash();
        Toast.ok(`Backup restored. Imported ${imported} courses, skipped ${skipped} duplicates.`);
      } catch(err) { Toast.err('Could not restore backup: ' + err.message); }
    };
    r.readAsText(f); e.target.value='';
  },
  async clearRecords() {
    if(!confirm('Clear all completion records?')) return;
    try {
      await api('/api/completions', { method: 'DELETE' });
      App.renderComps();
      Toast.ok('Records cleared.');
    } catch (e) {
      Toast.err(e.message || 'Could not clear records.');
    }
  },
  dl(name,type,content) { const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([content],{type})); a.download=name; a.click(); }
};

App.init();