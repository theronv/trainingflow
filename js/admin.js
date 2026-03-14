// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Admin Management
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
    try {
      const [stats, teams] = await Promise.all([api('/api/admin/stats'), api('/api/admin/teams')]);
      const { summary, learners } = stats;
      teamsCache = teams || [];
      
      $$('a-stats').innerHTML = [['Learners', summary.total_learners, '👥'],['Courses', summary.total_courses, '📚'],['Month', summary.completions_this_month, '🏆'],['Pass Rate', summary.pass_rate + '%', '📈']].map(([l,v,i])=>`<div class="stat-tile">
        <div style="font-size:24px;margin-bottom:var(--space-2);">${i}</div>
        <div class="stat-value">${v}</div>
        <div class="stat-label">${l}</div>
      </div>`).join('');
      
      const unassigned = (learners||[]).filter(l => !l.team_id).length;
      let teamHtml = '<div style="font-weight:700;margin:var(--space-8) 0 var(--space-4);">Team Compliance</div><div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:var(--space-4);">';
      teamHtml += (teams||[]).map(t => `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;"><div style="font-weight:700;">${esc(t.name)}</div><div style="font-size:11px;">${t.learner_count} members</div></div>`).join('') + '</div>';
      if(unassigned > 0) teamHtml += `<div class="card" onclick="Admin.nav('learners')" style="margin-top:var(--space-4);background:var(--fail-lt);color:var(--fail);cursor:pointer;">⚠️ ${unassigned} unassigned learners.</div>`;
      $$('a-course-stats').innerHTML = teamHtml;
      
      Admin.renderTroubleSpots();
    } catch(e) {
      const msg = e.detail ? `${e.message}: ${e.detail}` : e.message;
      $$('a-stats').innerHTML = `<div class="card" style="color:var(--fail);border-color:var(--fail);">Failed to load dashboard: ${esc(msg)}</div>`;
    }
  },

  async renderTroubleSpots() {
    try {
      const spots = await api('/api/admin/trouble-spots');
      if(!spots || !spots.length) { $$('a-trouble-spots').innerHTML = ''; return; }
      $$('a-trouble-spots').innerHTML = `<div style="font-weight:700;margin-bottom:var(--space-4);color:var(--fail);">⚠️ Trouble Spots</div><div class="table-wrap"><table><thead><tr><th>Question</th><th>Failure Rate</th></tr></thead><tbody>${spots.map(s=>`<tr><td>${esc(s.question)}</td><td><span class="chip chip-red">${s.failure_rate}%</span></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { }
  },

  // ─── TEAMS ───
  async renderTeams() {
    try {
      const teams = await api('/api/admin/teams');
      teamsCache = teams || [];
      if (!teams.length) { $$('teams-grid').innerHTML = '<div class="empty">No teams created yet.</div>'; return; }
      $$('teams-grid').innerHTML = teams.map(t => `
        <div class="card">
          <div style="display:flex;justify-content:space-between;font-weight:700;">${esc(t.name)} <button class="btn btn-ghost btn-sm" onclick="Admin.openRenameTeam('${t.id}','${esc(t.name)}')">⋮</button></div>
          <div style="font-size:11px;color:var(--ink-4);margin-bottom:12px;">${t.learner_count} members · ${t.manager_count} manager(s)</div>
          <div style="display:flex;gap:4px;">
            <button class="btn btn-outline btn-sm" onclick="Admin.toggleTeamMembers('${t.id}')">View Team</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${t.id}','${esc(t.name)}')">Invite</button>
            ${!t.learner_count && !t.manager_count ? `<button class="btn btn-ghost btn-sm" style="color:var(--fail);" onclick="Admin.deleteTeam('${t.id}')">✕</button>` : ''}
          </div>
          <div id="team-members-${t.id}" class="hidden" style="margin-top:12px;padding-top:8px;border-top:1px solid var(--rule);"></div>
        </div>`).join('');
    } catch(e) { 
      const msg = e.detail ? `${e.message}: ${e.detail}` : e.message;
      $$('teams-grid').innerHTML = `<div class="card" style="color:var(--fail);">Failed to load teams: ${esc(msg)}</div>`;
    }
  },
  async toggleTeamMembers(tid) {
    const el = $$(`team-members-${tid}`); if(!el.classList.contains('hidden')) return el.classList.add('hidden');
    el.classList.remove('hidden'); el.innerHTML = 'Loading...';
    try {
      const learners = await api(`/api/learners?team_id=${tid}`);
      el.innerHTML = `<div class="table-wrap"><table><tbody>${learners.map(l=>`<tr><td>${esc(l.name)}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">Move</button></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div style="color:var(--fail);font-size:11px;">${esc(e.message)}</div>`; }
  },
  openCreateTeam() {
    $$('team-modal-title').textContent = 'New Team';
    $$('team-name-input').value = '';
    $$('team-modal-btn').textContent = 'Create Team';
    $$('team-modal-btn').onclick = Admin.submitCreateTeam;
    $$('team-modal').classList.remove('hidden');
  },
  async submitCreateTeam() {
    const name = $$('team-name-input').value.trim();
    if(!name) return;
    try {
      await api('/api/admin/teams', { method:'POST', body:JSON.stringify({ name }) });
      $$('team-modal').classList.add('hidden');
      Admin.renderTeams();
    } catch(e) { Toast.err(e.message); }
  },
  async deleteTeam(id) {
    if(!confirm('Delete this team?')) return;
    try {
      await api(`/api/admin/teams/${id}`, { method:'DELETE' });
      Admin.renderTeams();
    } catch(e) { Toast.err(e.message); }
  },
  openRenameTeam(id, name) {
    $$('team-modal-title').textContent = 'Rename Team';
    $$('team-name-input').value = name;
    $$('team-modal-btn').textContent = 'Rename';
    $$('team-modal-btn').onclick = () => Admin.submitRenameTeam(id);
    $$('team-modal').classList.remove('hidden');
  },
  async submitRenameTeam(id) {
    const name = $$('team-name-input').value.trim();
    if(!name) return;
    try {
      await api(`/api/admin/teams/${id}`, { method:'PATCH', body:JSON.stringify({ name }) });
      $$('team-modal').classList.add('hidden');
      Admin.renderTeams();
    } catch(e) { Toast.err(e.message); }
  },

  // ─── INVITES ───
  _inviteTeamId: null,
  openGenerateInvite(tid, name) {
    Admin._inviteTeamId = tid;
    $$('invite-subtitle').textContent = `For ${name}`;
    $$('invite-expiry').value = '';
    $$('invite-form').classList.remove('hidden');
    $$('invite-result').classList.add('hidden');
    $$('invite-modal').classList.remove('hidden');
  },
  async submitGenerateInvite() {
    try {
      const res = await api('/api/admin/invites', { method:'POST', body:JSON.stringify({ team_id: Admin._inviteTeamId, expires_at: $$('invite-expiry').value || null }) });
      $$('generated-code').textContent = res.code;
      $$('invite-expiry-label').textContent = res.expires_at ? `Expires: ${new Date(res.expires_at).toLocaleDateString()}` : 'Never expires';
      $$('invite-form').classList.add('hidden');
      $$('invite-result').classList.remove('hidden');
    } catch(e) { Toast.err(e.message); }
  },
  copyInviteCode() { navigator.clipboard.writeText($$('generated-code').textContent); Toast.ok('Copied ✓'); },
  async toggleInvites() {
    const el = $$('invites-section');
    if(!el.classList.contains('hidden')) return el.classList.add('hidden');
    el.classList.remove('hidden');
    Admin.renderInvites();
  },
  async renderInvites() {
    try {
      const res = await api('/api/admin/invites');
      $$('invites-tbody').innerHTML = (res||[]).map(i => `<tr><td>${i.code}</td><td>${esc(i.team_name)}</td><td>${i.used?'Used':'Active'}</td><td>${new Date(i.created_at).toLocaleDateString()}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.revokeInvite(${i.id})">Revoke</button></td></tr>`).join('');
    } catch(e) { }
  },
  async revokeInvite(id) {
    try {
      await api(`/api/admin/invites/${id}`, { method:'DELETE' });
      Admin.renderInvites();
    } catch(e) { }
  },

  // ─── LEARNERS ───
  async renderLearners() {
    const tid = $$('l-team-filter').value;
    try {
      const [learners, teams] = await Promise.all([
        api(tid ? `/api/learners?team_id=${tid==='unassigned'?'null':tid}` : '/api/learners'),
        api('/api/admin/teams')
      ]);
      _allLearners = learners || [];
      teamsCache = teams || [];
      Admin.filterLearners($$('learners-search').value);
    } catch(e) { 
      const msg = e.detail ? `${e.message}: ${e.detail}` : e.message;
      $$('learners-tbody').innerHTML = `<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--fail);">${esc(msg)}</td></tr>`;
    }
  },
  filterLearners(q) {
    const query = q.toLowerCase().trim();
    const filtered = _allLearners.filter(l => l.name.toLowerCase().includes(query));
    if (!filtered.length) { $$('learners-tbody').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--ink-4);">No matching learners.</td></tr>'; return; }
    
    $$('learners-tbody').innerHTML = filtered.map(l => {
      const team = (teamsCache||[]).find(t => t.id === l.team_id);
      const teamHtml = team ? esc(team.name) : '<span class="chip chip-amber" style="font-size:9px;">Unassigned</span>';
      return `<tr>
        <td>${esc(l.name)}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">${teamHtml}</button></td>
        <td>${(l.tags||[]).map(t=>`<span class="chip chip-blue" style="font-size:9px;">${esc(t.name)}</span>`).join(' ')}</td>
        <td>${l.last_login_at ? new Date(l.last_login_at*1000).toLocaleDateString() : '—'}</td>
        <td>${l.completion_count}</td>
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
    $$('reset-pw-subtitle').textContent = name;
    App._resetPwId = id;
    $$('reset-pw-overlay').classList.remove('hidden');
  },
  closeResetPw() { $$('reset-pw-overlay').classList.add('hidden'); },
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
    try {
      const res = await api('/api/courses');
      $$('a-courses-grid').innerHTML = (res||[]).map(normCourse).map(c => `
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
    try {
      const cid = courseId || $$('comp-filter').value;
      const res = await api(`/api/admin/completions?course_id=${cid}`);
      $$('comp-tbody').innerHTML = (res||[]).map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td></tr>`).join('');
    } catch(e) { }
  },

  // ─── SETTINGS ───
  async clearRecords() {
    if(!confirm('Clear all learner records?')) return;
    try {
      await api('/api/completions', { method:'DELETE' });
      Toast.ok('Records cleared.');
    } catch(e) { Toast.err(e.message); }
  }
};
