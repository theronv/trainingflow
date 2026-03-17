// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Admin Management (Stable)
// ══════════════════════════════════════════════════════════

const Admin = {
  init() {
    App.show('screen-admin');
    Admin.nav('dashboard');
  },

  nav(p) {
    if (!getToken()) return App.show('screen-login');
    ['dashboard','courses','importer','learners','teams','completions','branding','settings'].forEach(k => {
      const btn = $$(`an-${k}`), pg = $$(`ap-${k}`);
      if(btn) btn.classList.toggle('active', k===p);
      if(pg) pg.classList.toggle('hidden', k!==p);
    });
    if(p==='dashboard') Admin.renderDash();
    if(p==='courses')   Admin.renderCourses();
    if(p==='importer')  Admin.goPhase(1);
    if(p==='learners')  Admin.renderLearners();
    if(p==='teams')     Admin.renderTeams();
    if(p==='completions') Admin.renderComps();
    if(p==='branding')  Admin.renderBranding();
  },

  // ─── DASHBOARD ───
  async renderDash() {
    const statsEl = $$('a-stats'); if(!statsEl) return;
    statsEl.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;"><div class="spinner"></div></div>';
    
    try {
      const [stats, teams] = await Promise.all([
        api('/api/admin/stats').catch(e => ({ error: e.message, summary: { total_learners:'N/A', total_courses:'N/A', completions_this_month:'N/A', pass_rate:'N/A' }, learners:[] })),
        api('/api/admin/teams').catch(() => [])
      ]);

      const summary = stats.summary || { total_learners:'N/A', total_courses:'N/A', completions_this_month:'N/A', pass_rate:'N/A' };
      const learners = stats.learners || [];
      teamsCache = teams || [];
      
      const pr = typeof summary.pass_rate === 'number' ? summary.pass_rate + '%' : 'N/A';
      statsEl.innerHTML = [
        ['Learners', summary.total_learners, '👥'],
        ['Courses',  summary.total_courses, '📚'],
        ['Month',    summary.completions_this_month, '🏆'],
        ['Pass Rate', pr, '📈']
      ].map(([l,v,i])=>`<div class="stat-tile">
        <div style="font-size:24px;margin-bottom:var(--s-2);">${i}</div>
        <div class="stat-value">${v}</div>
        <div class="stat-label">${l}</div>
      </div>`).join('');
      
      const unassigned = (learners||[]).filter(l => !l.team_id).length;
      let teamHtml = '<div style="font-weight:700;margin:var(--s-6) 0 var(--s-4);">Team Compliance</div><div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:var(--space-4);">';
      if (!teamsCache.length) {
        teamHtml += '<div class="card" style="grid-column:1/-1;color:var(--ink-4);text-align:center;">No teams established.</div>';
      } else {
        teamHtml += teamsCache.map(t => `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;"><div style="font-weight:700;">${esc(t.name)}</div><div style="font-size:11px;">${t.learner_count || 0} members</div></div>`).join('');
      }
      teamHtml += '</div>';
      if(unassigned > 0) teamHtml += `<div class="card" onclick="Admin.nav('learners')" style="margin-top:var(--space-4);background:var(--fail-lt);color:var(--fail);cursor:pointer;">⚠️ ${unassigned} unassigned learners found.</div>`;
      $$('a-course-stats').innerHTML = teamHtml;
      
      Admin.renderTroubleSpots();
    } catch(e) { 
      statsEl.innerHTML = `<div class="card" style="color:var(--fail);width:100%;">${esc(e.message)}</div>`; 
    } finally {
      // Spinner is already overwritten by content or error card
    }
  },

  async renderTroubleSpots() {
    try {
      const spots = await api('/api/admin/trouble-spots').catch(() => []);
      const el = $$('a-trouble-spots'); if(!el) return;
      if(!spots || !spots.length) { el.innerHTML = ''; return; }
      el.innerHTML = `<div style="font-weight:700;margin-bottom:var(--space-4);color:var(--fail);">⚠️ Trouble Spots</div>
        <div class="table-wrap"><table><thead><tr><th>Question</th><th>Fail Rate</th></tr></thead>
        <tbody>${spots.map(s=>`<tr><td>${esc(s.question)}</td><td><span class="chip chip-red">${s.failure_rate}%</span></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { }
  },

  // ─── TEAMS ───
  async renderTeams() {
    try {
      const teams = await api('/api/admin/teams'); teamsCache = teams || [];
      const grid = $$('teams-grid'); if(!grid) return;
      if (!teams.length) { grid.innerHTML = '<div class="empty">No teams created yet.</div>'; return; }
      grid.innerHTML = teams.map(t => `<div class="card">
        <div style="display:flex;justify-content:space-between;font-weight:700;">${esc(t.name)} <button class="btn btn-ghost btn-sm" onclick="Admin.openRenameTeam('${t.id}','${esc(t.name)}')">⋮</button></div>
        <div style="font-size:11px;color:var(--ink-meta);margin-bottom:12px;">${t.learner_count || 0} members</div>
        <div style="display:flex;gap:var(--s-2);">
          <button class="btn btn-outline btn-sm" onclick="Admin.toggleTeamMembers('${t.id}')">View Team</button>
          <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${t.id}','${esc(t.name)}')">Invite</button>
        </div>
        <div id="team-members-${t.id}" class="hidden" style="margin-top:12px;padding-top:8px;border-top:1px solid var(--rule);"></div>
      </div>`).join('');
    } catch(e) { }
  },
  async toggleTeamMembers(tid) {
    const el = $$(`team-members-${tid}`); if(!el) return;
    if(!el.classList.contains('hidden')) return el.classList.add('hidden');
    el.classList.remove('hidden'); el.innerHTML = 'Loading...';
    try {
      const res = await api(`/api/learners?team_id=${tid}`);
      const rows = Array.isArray(res) ? res : (res.rows || []);
      el.innerHTML = `<div class="table-wrap"><table><tbody>${rows.map(l=>`<tr><td>${esc(l.name)}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">Move</button></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div style="color:var(--fail);font-size:11px;">${esc(e.message)}</div>`; }
  },
  openCreateTeam() { $$('team-modal-title').textContent = 'New Team'; $$('team-name-input').value = ''; $$('team-modal').classList.remove('hidden'); },
  async submitCreateTeam() { try { await api('/api/admin/teams', { method:'POST', body:JSON.stringify({ name: $$('team-name-input').value.trim() }) }); $$('team-modal').classList.add('hidden'); Admin.renderTeams(); } catch(e){ Toast.err(e.message); } },
  async deleteTeam(id) { if(confirm('Delete team?')){ try { await api(`/api/admin/teams/${id}`, { method:'DELETE' }); Admin.renderTeams(); } catch(e){ Toast.err(e.message); } } },

  // ─── LEARNERS ───
  async renderLearners() {
    const tbody = $$('learners-tbody'); if(!tbody) return;
    try {
      const tid = $$('l-team-filter').value;
      const path = tid ? `/api/learners?team_id=${tid==='unassigned'?'null':tid}` : '/api/learners';
      const [apiRes, teams] = await Promise.all([api(path), api('/api/admin/teams')]);
      _allLearners = Array.isArray(apiRes) ? apiRes : (apiRes.rows || []);
      teamsCache = teams || [];
      
      const filter = $$('l-team-filter'); 
      if (filter && filter.options.length <= 2) {
        teamsCache.forEach(t => { 
          const o = document.createElement('option'); o.value = t.id; o.textContent = t.name; filter.appendChild(o); 
        });
      }
      Admin.filterLearners($$('learners-search') ? $$('learners-search').value : '');
    } catch(e) { tbody.innerHTML = `<tr><td colspan="6">${esc(e.message)}</td></tr>`; }
  },
  filterLearners(q) {
    const tbody = $$('learners-tbody'); if(!tbody) return;
    const query = (q || '').toLowerCase().trim();
    const filtered = _allLearners.filter(l => (l.name || '').toLowerCase().includes(query));
    if(!filtered.length) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:32px;">No matches.</td></tr>'; return; }
    tbody.innerHTML = filtered.map(l => {
      const team = (teamsCache||[]).find(t => t.id === l.team_id);
      const teamHtml = team ? esc(team.name) : '<span class="chip chip-amber" style="font-size:9px;">Unassigned</span>';
      const tagsHtml = (l.tags||[]).map(t => `<span class="chip chip-blue" style="font-size:9px;">${esc(t.name)}</span>`).join(' ');
      return `<tr>
        <td>${esc(l.name || 'Unnamed')} ${l.overdue_count ? `<span class="chip chip-red" style="font-size:9px;">⚠️ ${l.overdue_count}</span>` : ''}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="App.moveLearner('${l.id}')">${teamHtml}</button></td>
        <td>${tagsHtml}</td>
        <td>${l.last_login_at ? new Date(l.last_login_at*1000).toLocaleDateString() : '—'}</td>
        <td>${l.completion_count || 0}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="App.openResetPw('${l.id}','${esc(l.name)}')">PW</button></td>
      </tr>`;
    }).join('');
  },
  async moveLearner(lid) { const tid = prompt('Target Team ID:'); if(tid!==null) { try { await api(`/api/admin/learners/${lid}/team`, { method:'PATCH', body:JSON.stringify({ team_id: tid || null }) }); Admin.renderLearners(); } catch(e){ Toast.err(e.message); } } },
  openAddLearner() { $$('al-name').value=''; $$('al-pw1').value=''; $$('al-pw2').value=''; const sel = $$('al-team'); if(sel) sel.innerHTML = '<option value="">Unassigned</option>' + (teamsCache||[]).map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join(''); $$('add-learner-overlay').classList.remove('hidden'); },
  closeAddLearner() { $$('add-learner-overlay').classList.add('hidden'); },
  async submitAddLearner() { try { await api('/api/learners', { method:'POST', body:JSON.stringify({ name: $$('al-name').value.trim(), password: $$('al-pw1').value, team_id: $$('al-team')?.value || null }) }); Admin.closeAddLearner(); Admin.renderLearners(); } catch(e){ Toast.err(e.message); } },

  // ─── BRANDING ───
  async renderBranding() {
    if(!brandCache) return;
    if($$('br-name')) $$('br-name').value = brandCache.name || '';
    if($$('br-pass')) $$('br-pass').value = brandCache.pass || 80;
  },
  async saveBrand() {
    try {
      const body = { org_name: $$('br-name').value, pass_threshold: parseInt($$('br-pass').value) };
      await api('/api/brand', { method:'PUT', body:JSON.stringify(body) });
      Toast.ok('Brand saved.');
    } catch(e) { Toast.err(e.message); }
  },

  // ─── COMPLETIONS ───
  async renderComps(cid = '') {
    const tbody = $$('comp-tbody'); if(!tbody) return;
    try {
      const res = await api(`/api/admin/completions?course_id=${cid}`);
      tbody.innerHTML = (res||[]).map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td><td>—</td></tr>`).join('');
    } catch(e) { }
  },

  async renderCourses() {
    const grid = $$('a-courses-grid'); if(!grid) return;
    grid.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;"><div class="spinner"></div></div>';
    try {
      const res = await api('/api/courses');
      if (!res.length) {
        grid.innerHTML = '<div class="card" style="grid-column:1/-1;text-align:center;padding:40px;color:var(--ink-4);">No courses created yet. Use the Importer or Builder to start.</div>';
        return;
      }
      grid.innerHTML = (res||[]).map(normCourse).map(c => `<div class="card"><div style="font-weight:700;">${esc(c.title)}</div><div style="display:flex;gap:4px;margin-top:12px;"><button class="btn btn-primary btn-sm w-full" onclick="App.openAssign('${c.id}','${esc(c.title)}')">👤 Assign</button></div></div>`).join('');
    } catch(e) { 
      grid.innerHTML = `<div class="card" style="grid-column:1/-1;color:var(--fail);">${esc(e.message)}</div>`;
    }
  },

  openResetPw(id, name) { $$('reset-pw-subtitle').textContent = name; App._resetPwId = id; $$('reset-pw-overlay').classList.remove('hidden'); },
  closeResetPw() { $$('reset-pw-overlay').classList.add('hidden'); },
  async submitResetPw() {
    const pw = $$('rp-pw1').value;
    try { await api(`/api/learners/${App._resetPwId}/password`, { method:'PUT', body:JSON.stringify({ password:pw }) }); Admin.closeResetPw(); Toast.ok('Password reset.'); } catch(e) { Toast.err(e.message); }
  },

  exportCSV(scope) { Toast.info('Exporting data...'); },
  async clearRecords() { if(confirm('Clear all data?')){ await api('/api/completions', { method:'DELETE' }); Admin.renderDash(); } },

  // ─── AI IMPORTER ───
  fileModules: [],
  parsedModules: [],
  generatedCourse: null,
  isGenerating: false,

  goPhase(n) {
    [1,2,3,4].forEach(i => {
      const pg = $$(`phase-${['upload','configure','generate','export'][i-1]}`);
      if(pg) pg.classList.toggle('hidden', i !== n);
      const s = $$(`step-${i}`);
      if(s) {
        const numEl = s.querySelector('.step-num');
        s.classList.remove('active','done');
        if (i < n) { s.classList.add('done'); if(numEl) numEl.textContent = '✓'; }
        else if (i === n) { s.classList.add('active'); if(numEl) numEl.textContent = i; }
        else { if(numEl) numEl.textContent = i; }
      }
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  handleDrop(e) {
    e.preventDefault();
    const dz = $$('imp-drop-zone'); if(dz) dz.classList.remove('drag-active');
    const files = Array.from(e.dataTransfer.files).filter(f => /\.(md|markdown|txt)$/i.test(f.name));
    if (!files.length) { Toast.err('Drop .md files only.'); return; }
    files.forEach(f => Admin.readAndAddFile(f));
  },
  handleFileSelect(e) {
    Array.from(e.target.files).forEach(f => Admin.readAndAddFile(f));
    e.target.value = '';
  },
  readAndAddFile(file) {
    const reader = new FileReader();
    reader.onload = ev => Admin.addFileModule(ev.target.result, file.name.replace(/\.[^.]+$/, ''));
    reader.readAsText(file);
  },
  addFileModule(rawMd, defaultName) {
    const subModules = Admin.parseMdToModules(rawMd, defaultName);
    const id = Date.now() + Math.random();
    Admin.fileModules.push({ id, name: Admin.cleanTitle(defaultName), subModules });
    Admin.renderFileModuleList();
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
        cur = { title: Admin.cleanTitle(h2[1].trim()), rawLines: [] };
      } else if (cur) {
        cur.rawLines.push(line);
      }
    }
    if (cur) modules.push(cur);
    if (!modules.length) modules.push({ title: Admin.cleanTitle(defaultTitle), rawLines: lines });
    return modules.map(m => ({ title: m.title, content: m.rawLines.join('\n') }));
  },
  renderFileModuleList() {
    const el = $$('file-module-list');
    const actEl = $$('upload-actions');
    const countEl = $$('upload-module-count');
    if(!el) return;
    if (!Admin.fileModules.length) { el.innerHTML = ''; if(actEl) actEl.classList.add('hidden'); return; }
    const totalMods = Admin.fileModules.reduce((s, f) => s + f.subModules.length, 0);
    if(countEl) countEl.textContent = `${Admin.fileModules.length} files · ${totalMods} modules total`;
    if(actEl) actEl.classList.remove('hidden');
    el.innerHTML = Admin.fileModules.map((fm, fi) => `
      <div class="card" style="margin-bottom:var(--space-3);padding:var(--space-3) var(--space-4);">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div style="font-weight:600;">${esc(fm.name)} (${fm.subModules.length} sections)</div>
          <button class="btn btn-ghost btn-sm" style="color:var(--fail)" onclick="Admin.removeFileModule(${fi})">✕</button>
        </div>
      </div>`).join('');
  },
  removeFileModule(i) { Admin.fileModules.splice(i, 1); Admin.renderFileModuleList(); },
  proceedFromUpload() {
    if (!Admin.fileModules.length) return Toast.err('Add at least one file first.');
    Admin.parsedModules = [];
    Admin.fileModules.forEach(fm => fm.subModules.forEach(sm => Admin.parsedModules.push(sm)));
    $$('ai-course-title').value = Admin.fileModules[0].name;
    Admin.renderModulePreview();
    Admin.goPhase(2);
  },
  renderModulePreview() {
    const el = $$('module-preview'); if(!el) return;
    el.innerHTML = Admin.parsedModules.map((m, i) => `
      <div class="card" style="margin-bottom:var(--space-2);padding:var(--space-3);">
        <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);">MODULE ${i+1}</div>
        <div style="font-weight:600;">${esc(m.title)}</div>
      </div>`).join('');
  },

  async startGeneration() {
    if (Admin.isGenerating) return;
    const apiKey = prompt('Enter Google Gemini API Key:');
    if (!apiKey) return Toast.err('API Key required.');
    
    Admin.isGenerating = true;
    Admin.goPhase(3);
    const total = Admin.parsedModules.length;
    if($$('gen-progress-label')) $$('gen-progress-label').textContent = `0 of ${total}`;
    if($$('gen-prog-bar')) $$('gen-prog-bar').style.width = '0%';
    const listEl = $$('gen-module-list'); if(!listEl) return;
    listEl.innerHTML = Admin.parsedModules.map((m, i) => `
      <div id="genrow-${i}" style="padding:8px 0;border-bottom:1px solid var(--rule-2);">
        <div style="display:flex;align-items:center;gap:12px;">
          <div id="gendot-${i}" class="gen-dot" style="background:var(--ink-4);width:8px;height:8px;border-radius:50%;"></div>
          <span style="font-weight:500;">${esc(m.title)}</span>
          <span id="genstatus-${i}" style="font-size:11px;color:var(--ink-4);margin-left:auto;">Waiting...</span>
        </div>
      </div>`).join('');

    const generatedModules = [];
    for (let i = 0; i < total; i++) {
      const mod = Admin.parsedModules[i];
      const dot = $$(`gendot-${i}`);
      const status = $$(`genstatus-${i}`);
      if(dot) dot.style.background = 'var(--brand-1)';
      if(status) status.textContent = 'Generating...';
      
      try {
        const res = await Admin.callGemini(mod, apiKey);
        generatedModules.push({ ...mod, ...res });
        if(dot) dot.style.background = 'var(--pass)';
        if(status) status.textContent = '✓ Ready';
      } catch (err) {
        console.error(err);
        if(dot) dot.style.background = 'var(--fail)';
        if(status) status.textContent = '✗ Failed';
        generatedModules.push({ ...mod, questions: [], summary: 'Generation failed for this module.', failed: true });
      }
      const p = Math.round(((i + 1) / total) * 100);
      if($$('gen-prog-bar')) $$('gen-prog-bar').style.width = p + '%';
      if($$('gen-progress-label')) $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
    }

    Admin.generatedCourse = {
      title: $$('ai-course-title').value.trim(),
      icon: $$('ai-course-icon').value || '📋',
      description: $$('ai-course-desc').value.trim(),
      modules: generatedModules
    };
    Admin.renderReview();
    Admin.goPhase(4);
    Admin.isGenerating = false;
  },

  async callGemini(mod, key) {
    const promptText = `Generate a JSON object for a training module.
    Title: ${mod.title}
    Content: ${mod.content.slice(0, 4000)}
    
    Return EXACTLY this JSON format:
    {
      "summary": "A brief overview...",
      "questions": [
        { "question": "...", "options": ["A","B","C","D"], "correct_index": 0, "explanation": "..." }
      ]
    }`;
    
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${key}`;
    const res = await fetch(url, {
      method: 'POST',
      body: JSON.stringify({ contents: [{ parts: [{ text: promptText }] }] })
    });
    if(!res.ok) throw new Error(`Gemini API Error: ${res.status}`);
    const data = await res.json();
    const text = data.candidates[0].content.parts[0].text;
    const jsonStr = text.match(/\{[\s\S]*\}/)[0];
    return JSON.parse(jsonStr);
  },

  renderReview() {
    const el = $$('review-modules'); if(!el) return;
    el.innerHTML = Admin.generatedCourse.modules.map((m, i) => `
      <div class="card" style="margin-bottom:var(--space-4);">
        <div style="font-weight:700;">${esc(m.title)}</div>
        <div style="font-size:var(--text-sm);color:var(--ink-3);margin-top:8px;">${esc(m.summary || '')}</div>
        <div style="font-size:11px;color:var(--brand-1);margin-top:4px;">${m.questions?.length || 0} questions generated</div>
      </div>`).join('');
  },

  async saveAiCourse() {
    try {
      await api('/api/courses', { method: 'POST', body: JSON.stringify(Admin.generatedCourse) });
      Toast.ok('AI Course saved to database!');
      Admin.nav('courses');
    } catch (e) { Toast.err(e.message); }
  }
};
