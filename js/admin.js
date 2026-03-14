// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Admin Management (Robust)
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
    if(p==='branding')  applyBrand();
  },

  // ─── DASHBOARD ───
  async renderDash() {
    const statsEl = $$('a-stats');
    if(!statsEl) return;
    statsEl.innerHTML = '<div style="padding:20px;color:var(--ink-4);">Loading insights...</div>';
    
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
        <div style="font-size:24px;margin-bottom:var(--space-2);">${i}</div>
        <div class="stat-value">${v}</div>
        <div class="stat-label">${l}</div>
      </div>`).join('');
      
      const unassigned = learners.filter(l => !l.team_id).length;
      let teamHtml = '<div style="font-weight:700;margin:var(--space-8) 0 var(--space-4);">Team Compliance</div>';
      
      if (teams && teams.length > 0) {
        teamHtml += '<div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:var(--space-4);">';
        teamHtml += teams.map(t => `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;">
          <div style="font-weight:700;">${esc(t.name)}</div>
          <div style="font-size:11px;color:var(--ink-3);">${t.learner_count || 0} members</div>
        </div>`).join('') + '</div>';
      } else {
        teamHtml += `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;text-align:center;border-style:dashed;color:var(--brand-1);">Create your first team to organize learners →</div>`;
      }

      if(unassigned > 0) {
        teamHtml += `<div class="card" onclick="Admin.nav('learners')" style="margin-top:var(--space-4);background:var(--fail-lt);color:var(--fail);cursor:pointer;display:flex;align-items:center;gap:12px;">
          <span style="font-size:18px;">⚠️</span>
          <div style="font-weight:600;">${unassigned} unassigned learners found. Click to manage.</div>
        </div>`;
      }
      
      const csEl = $$('a-course-stats');
      if(csEl) csEl.innerHTML = teamHtml;
      
      Admin.renderTroubleSpots();
      
      const recentEl = $$('a-recent');
      if(recentEl) {
        recentEl.innerHTML = learners.length 
          ? `<div style="font-weight:700;margin-bottom:var(--space-4);">Recent Activity</div>
             <div class="table-wrap"><table><thead><tr><th>Learner</th><th>Status</th></tr></thead>
             <tbody>${learners.slice(0,5).map(l=>`<tr><td>${esc(l.name)}</td><td>${l.completion_count || 0} completed</td></tr>`).join('')}</tbody></table></div>`
          : '';
      }

    } catch(e) {
      statsEl.innerHTML = `<div class="card" style="color:var(--fail);border-color:var(--fail);">
        <strong>Dashboard Error</strong><br>
        <small>${esc(e.message)}</small>
      </div>`;
    }
  },

  async renderTroubleSpots() {
    const el = $$('a-trouble-spots');
    if(!el) return;
    try {
      const spots = await api('/api/admin/trouble-spots').catch(() => []);
      if(!spots || !spots.length) { el.innerHTML = ''; return; }
      el.innerHTML = `<div style="font-weight:700;margin-bottom:var(--space-4);color:var(--fail);">⚠️ Trouble Spots</div>
        <div class="table-wrap"><table><thead><tr><th>Question</th><th>Fail Rate</th></tr></thead>
        <tbody>${spots.map(s=>`<tr><td>${esc(s.question)}</td><td><span class="chip chip-red">${s.failure_rate}%</span></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { el.innerHTML = ''; }
  },

  // ─── TEAMS ───
  async renderTeams() {
    const grid = $$('teams-grid');
    if(!grid) return;
    grid.innerHTML = '<div style="padding:20px;color:var(--ink-4);">Loading teams...</div>';
    try {
      const teams = await api('/api/admin/teams');
      teamsCache = teams || [];
      if (!teams || !teams.length) { grid.innerHTML = '<div class="empty">No teams created yet.</div>'; return; }
      grid.innerHTML = teams.map(t => `<div class="card">
        <div style="display:flex;justify-content:space-between;font-weight:700;">
          ${esc(t.name)} 
          <button class="btn btn-ghost btn-sm" onclick="Admin.openRenameTeam('${t.id}','${esc(t.name)}')">⋮</button>
        </div>
        <div style="font-size:11px;color:var(--ink-4);margin-bottom:12px;">${t.learner_count || 0} members · ${t.manager_count || 0} manager(s)</div>
        <div style="display:flex;gap:4px;">
          <button class="btn btn-outline btn-sm" onclick="Admin.toggleTeamMembers('${t.id}')">View Team</button>
          <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${t.id}','${esc(t.name)}')">Invite</button>
        </div>
        <div id="team-members-${t.id}" class="hidden" style="margin-top:12px;padding-top:8px;border-top:1px solid var(--rule);"></div>
      </div>`).join('');
    } catch(e) { 
      grid.innerHTML = `<div class="card" style="color:var(--fail);">Failed to load teams: ${esc(e.message)}</div>`;
    }
  },

  async toggleTeamMembers(tid) {
    const el = $$(`team-members-${tid}`); if(!el) return;
    if(!el.classList.contains('hidden')) return el.classList.add('hidden');
    el.classList.remove('hidden'); el.innerHTML = 'Loading...';
    try {
      const learners = await api(`/api/learners?team_id=${tid}`);
      el.innerHTML = `<div class="table-wrap"><table><tbody>${learners.map(l=>`<tr>
        <td style="font-size:12px;">${esc(l.name)}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">Move</button></td>
      </tr>`).join('')}</tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div style="font-size:11px;color:var(--fail);">${esc(e.message)}</div>`; }
  },

  // ─── LEARNERS ───
  async renderLearners() {
    const tbody = $$('learners-tbody');
    if(!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--ink-4);">Loading learners...</td></tr>';
    const tid = $$('l-team-filter') ? $$('l-team-filter').value : '';
    try {
      const path = tid ? `/api/learners?team_id=${tid==='unassigned'?'null':tid}` : '/api/learners';
      const learners = await api(path);
      _allLearners = learners || [];
      Admin.filterLearners($$('learners-search') ? $$('learners-search').value : '');
    } catch(e) { 
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--fail);">${esc(e.message)}</td></tr>`;
    }
  },

  filterLearners(q) {
    const tbody = $$('learners-tbody'); if(!tbody) return;
    const query = (q || '').toLowerCase().trim();
    const filtered = _allLearners.filter(l => l.name.toLowerCase().includes(query));
    if (!filtered.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--ink-4);">No matching learners.</td></tr>'; return; }
    
    tbody.innerHTML = filtered.map(l => {
      const team = (teamsCache||[]).find(t => t.id === l.team_id);
      const teamHtml = team ? esc(team.name) : '<span class="chip chip-amber" style="font-size:9px;">Unassigned</span>';
      return `<tr>
        <td>${esc(l.name)} ${l.overdue_count ? `<span class="chip chip-red" style="font-size:9px;">⚠️ ${l.overdue_count}</span>` : ''}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">${teamHtml}</button></td>
        <td>${l.last_login_at ? new Date(l.last_login_at*1000).toLocaleDateString() : '—'}</td>
        <td>${l.completion_count || 0}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="Admin.openResetPw('${l.id}','${esc(l.name)}')">PW</button></td>
      </tr>`;
    }).join('');
  },

  async moveLearner(lid) {
    const tid = prompt('Target Team ID (leave blank to unassign):');
    if(tid !== null) {
      try {
        await api(`/api/admin/learners/${lid}/team`, { method:'PATCH', body:JSON.stringify({ team_id: tid || null }) });
        Admin.renderLearners();
      } catch(e) { Toast.err(e.message); }
    }
  },

  openResetPw(id, name) {
    const sub = $$('reset-pw-subtitle'); if(sub) sub.textContent = name;
    App._resetPwId = id;
    const el = $$('reset-pw-overlay'); if(el) el.classList.remove('hidden');
  },
  closeResetPw() { const el = $$('reset-pw-overlay'); if(el) el.classList.add('hidden'); },
  async submitResetPw() {
    const pw = $$('rp-pw1').value;
    try {
      await api(`/api/learners/${App._resetPwId}/password`, { method:'PUT', body:JSON.stringify({ password:pw }) });
      Admin.closeResetPw();
      Toast.ok('Password reset.');
    } catch(e) { Toast.err(e.message); }
  },

  // ─── COURSES ───
  async renderCourses() {
    const grid = $$('a-courses-grid'); if(!grid) return;
    try {
      const res = await api('/api/courses');
      grid.innerHTML = (res||[]).map(normCourse).map(c => `
        <div class="card">
          <div style="font-weight:700;">${esc(c.title)}</div>
          <div style="display:flex;gap:4px;margin-top:12px;">
            <button class="btn btn-primary btn-sm w-full" onclick="App.openAssign('${c.id}','${esc(c.title)}')">👤 Assign</button>
            <button class="btn btn-outline btn-sm" onclick="Builder.editCourse('${c.id}')">✏ Edit</button>
          </div>
        </div>`).join('');
    } catch(e) { }
  },

  // ─── COMPLETIONS ───
  async renderComps(courseId = '') {
    const tbody = $$('comp-tbody'); if(!tbody) return;
    try {
      const filter = $$('comp-filter');
      const cid = courseId || (filter ? filter.value : '');
      const res = await api(`/api/admin/completions?course_id=${cid}`);
      tbody.innerHTML = (res||[]).map(r => `<tr>
        <td>${esc(r.user_name)}</td>
        <td>${esc(r.course_title)}</td>
        <td>${r.score}%</td>
        <td>${r.passed?'Passed':'Failed'}</td>
        <td>${new Date(r.completed_at*1000).toLocaleDateString()}</td>
      </tr>`).join('');
    } catch(e) { }
  },

  async clearRecords() {
    if(!confirm('Clear all learner records?')) return;
    try {
      await api('/api/completions', { method:'DELETE' });
      Toast.ok('Records cleared.');
      Admin.renderDash();
    } catch(e) { Toast.err(e.message); }
  }
};
