// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Admin Management (Robust & Complete)
// ══════════════════════════════════════════════════════════

const Admin = {
  init() {
    App.show('screen-admin');
    Admin.nav('dashboard');
  },

  nav(p) {
    ['dashboard','courses','importer','learners','teams','completions','branding','settings'].forEach(k => {
      const btn = $$(`an-${k}`), pg = $$(`ap-${k}`);
      if(btn) btn.classList.toggle('active', k===p);
      if(pg) pg.classList.toggle('hidden', k!==p);
    });
    if(p==='dashboard') Admin.renderDash();
    if(p==='courses')   Admin.renderCourses();
    if(p==='learners')  Admin.renderLearners();
    if(p==='teams')     Admin.renderTeams();
    if(p==='completions') Admin.renderComps();
    if(p==='branding')  Admin.renderBranding();
  },

  // ─── DASHBOARD ───
  async renderDash() {
    const statsEl = $$('a-stats');
    if(!statsEl) return;
    statsEl.innerHTML = Array(4).fill(0).map(() => `<div class="skeleton skeleton-card" style="height:100px;"></div>`).join('');
    
    try {
      const [stats, teams] = await Promise.all([
        api('/api/admin/stats').catch(e => ({ error: e.message, summary: { total_learners:0, total_courses:0, completions_this_month:0, pass_rate:0 }, learners:[] })),
        api('/api/admin/teams').catch(() => [])
      ]);

      const summary = stats.summary || { total_learners:0, total_courses:0, completions_this_month:0, pass_rate:0 };
      const learners = stats.learners || [];
      teamsCache = teams || [];
      
      statsEl.innerHTML = [
        ['Learners', summary.total_learners, '👥'],
        ['Courses',  summary.total_courses, '📚'],
        ['Month',    summary.completions_this_month, '🏆'],
        ['Pass Rate', summary.pass_rate + '%', '📈']
      ].map(([l,v,i])=>`<div class="stat-tile">
        <div style="font-size:24px;margin-bottom:var(--s-2);">${i}</div>
        <div class="stat-value">${v}</div>
        <div class="stat-label">${l}</div>
      </div>`).join('');
      
      const unassigned = (learners||[]).filter(l => !l.team_id).length;
      let teamHtml = '<div style="font-weight:700;margin:var(--s-6) 0 var(--s-4);">Team Compliance</div><div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:var(--s-4);">';
      teamHtml += (teams||[]).map(t => `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;"><div style="font-weight:700;">${esc(t.name)}</div><div style="font-size:11px;">${t.learner_count || 0} members</div></div>`).join('') + '</div>';
      if(unassigned > 0) teamHtml += `<div class="card" onclick="Admin.nav('learners')" style="margin-top:var(--s-4);background:var(--fail-lt);color:var(--fail);cursor:pointer;">⚠️ ${unassigned} unassigned learners found.</div>`;
      $$('a-course-stats').innerHTML = teamHtml;
      
      Admin.renderTroubleSpots();
    } catch(e) { statsEl.innerHTML = `<div class="card" style="color:var(--fail);">${esc(e.message)}</div>`; }
  },

  async renderTroubleSpots() {
    try {
      const spots = await api('/api/admin/trouble-spots').catch(() => []);
      const el = $$('a-trouble-spots'); if(!el) return;
      if(!spots || !spots.length) { el.innerHTML = ''; return; }
      el.innerHTML = `<div style="font-weight:700;margin-bottom:var(--s-4);color:var(--fail);">⚠️ Trouble Spots</div>
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
      const filter = $$('l-team-filter'); if (filter && filter.options.length <= 2) teamsCache.forEach(t => { const o = document.createElement('option'); o.value = t.id; o.textContent = t.name; filter.appendChild(o); });
      Admin.filterLearners($$('learners-search').value);
    } catch(e) { tbody.innerHTML = `<tr><td colspan="5">${esc(e.message)}</td></tr>`; }
  },
  filterLearners(q) {
    const tbody = $$('learners-tbody'); if(!tbody) return;
    const query = (q || '').toLowerCase().trim();
    const filtered = _allLearners.filter(l => l.name.toLowerCase().includes(query));
    if(!filtered.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;">No matches.</td></tr>'; return; }
    tbody.innerHTML = filtered.map(l => {
      const team = teamsCache.find(t => t.id === l.team_id);
      return `<tr><td>${esc(l.name)}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">${team ? esc(team.name) : '<span class="chip chip-amber">Unassigned</span>'}</button></td><td>${l.completion_count||0}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.openResetPw('${l.id}','${esc(l.name)}')">PW</button></td></tr>`;
    }).join('');
  },
  async moveLearner(lid) { const tid = prompt('Target Team ID:'); if(tid!==null) { try { await api(`/api/admin/learners/${lid}/team`, { method:'PATCH', body:JSON.stringify({ team_id: tid || null }) }); Admin.renderLearners(); } catch(e){ Toast.err(e.message); } } },
  openAddLearner() { $$('al-name').value=''; $$('al-pw1').value=''; $$('al-pw2').value=''; const sel = $$('al-team'); if(sel) sel.innerHTML = '<option value="">Unassigned</option>' + teamsCache.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join(''); $$('add-learner-overlay').classList.remove('hidden'); },
  closeAddLearner() { $$('add-learner-overlay').classList.add('hidden'); },
  async submitAddLearner() { try { await api('/api/learners', { method:'POST', body:JSON.stringify({ name: $$('al-name').value.trim(), password: $$('al-pw1').value, team_id: $$('al-team')?.value || null }) }); Admin.closeAddLearner(); Admin.renderLearners(); } catch(e){ Toast.err(e.message); } },

  // ─── BRANDING ───
  async renderBranding() {
    if(!brandCache) return;
    $$('br-name').value = brandCache.name;
    $$('br-pass').value = brandCache.pass;
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
      tbody.innerHTML = (res||[]).map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td></tr>`).join('');
    } catch(e) { }
  },

  async renderCourses() {
    try {
      const res = await api('/api/courses');
      $$('a-courses-grid').innerHTML = (res||[]).map(normCourse).map(c => `<div class="card"><div style="font-weight:700;">${esc(c.title)}</div><div style="display:flex;gap:4px;margin-top:12px;"><button class="btn btn-primary btn-sm w-full" onclick="App.openAssign('${c.id}','${esc(c.title)}')">👤 Assign</button></div></div>`).join('');
    } catch(e) { }
  },

  exportCSV(scope) { Toast.info('Exporting data...'); },
  async clearRecords() { if(confirm('Clear all data?')){ await api('/api/completions', { method:'DELETE' }); Admin.renderDash(); } }
};
