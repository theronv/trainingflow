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
      if($$(`an-${k}`)) $$(`an-${k}`).classList.toggle('active', k===p);
      if($$(`ap-${k}`)) $$(`ap-${k}`).classList.toggle('hidden', k!==p);
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
      $$('a-stats').innerHTML = [['Learners', summary.total_learners, '👥'],['Courses', summary.total_courses, '📚'],['Month', summary.completions_this_month, '🏆'],['Pass Rate', summary.pass_rate + '%', '📈']].map(([l,v,i])=>`<div class="stat-tile"><div style="font-size:24px;">${i}</div><div class="stat-value">${v}</div><div class="stat-label">${l}</div></div>`).join('');
      
      const unassigned = learners.filter(l => !l.team_id).length;
      let teamHtml = '<div style="font-weight:700;margin:var(--space-8) 0 var(--space-4);">Team Compliance</div><div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:var(--space-4);">';
      teamHtml += teams.map(t => `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;"><div style="font-weight:700;">${esc(t.name)}</div><div style="font-size:11px;">${t.learner_count} members</div></div>`).join('') + '</div>';
      if(unassigned) teamHtml += `<div class="card" onclick="Admin.nav('learners')" style="margin-top:var(--space-4);background:var(--fail-lt);color:var(--fail);cursor:pointer;">⚠️ ${unassigned} unassigned learners found.</div>`;
      $$('a-course-stats').innerHTML = teamHtml;
      
      Admin.renderTroubleSpots();
    } catch(e) { }
  },

  async renderTroubleSpots() {
    try {
      const spots = await api('/api/admin/trouble-spots');
      if(!spots.length) { $$('a-trouble-spots').innerHTML = ''; return; }
      $$('a-trouble-spots').innerHTML = `<div style="font-weight:700;margin-bottom:var(--space-4);color:var(--fail);">⚠️ Trouble Spots</div><div class="table-wrap"><table><thead><tr><th>Question</th><th>Failure Rate</th></tr></thead><tbody>${spots.map(s=>`<tr><td>${esc(s.question)}</td><td><span class="chip chip-red">${s.failure_rate}%</span></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { }
  },

  // ─── TEAMS ───
  async renderTeams() {
    try {
      const teams = await api('/api/admin/teams');
      teamsCache = teams;
      $$('teams-grid').innerHTML = teams.map(t => `
        <div class="card">
          <div style="display:flex;justify-content:space-between;font-weight:700;">${esc(t.name)} <button class="btn btn-ghost btn-sm" onclick="Admin.openRenameTeam('${t.id}','${esc(t.name)}')">⋮</button></div>
          <div style="font-size:11px;color:var(--ink-4);margin-bottom:12px;">${t.learner_count} members · ${t.manager_count} manager(s)</div>
          <div style="display:flex;gap:4px;">
            <button class="btn btn-outline btn-sm" onclick="Admin.toggleTeamMembers('${t.id}')">View</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${t.id}','${esc(t.name)}')">Invite</button>
          </div>
          <div id="team-members-${t.id}" class="hidden" style="margin-top:12px;border-top:1px solid var(--rule);"></div>
        </div>`).join('');
    } catch(e) { }
  },
  async toggleTeamMembers(tid) {
    const el = $$(`team-members-${tid}`); if(!el.classList.contains('hidden')) return el.classList.add('hidden');
    el.classList.remove('hidden'); el.innerHTML = 'Loading...';
    const learners = await api(`/api/learners?team_id=${tid}`);
    el.innerHTML = `<div class="table-wrap"><table><tbody>${learners.map(l=>`<tr><td>${esc(l.name)}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">Move</button></td></tr>`).join('')}</tbody></table></div>`;
  },
  openCreateTeam() { $$('team-modal-title').textContent = 'New Team'; $$('team-name-input').value = ''; $$('team-modal-btn').onclick = Admin.submitCreateTeam; $$('team-modal').classList.remove('hidden'); },
  async submitCreateTeam() { await api('/api/admin/teams', { method:'POST', body:JSON.stringify({ name: $$('team-name-input').value }) }); $$('team-modal').classList.add('hidden'); Admin.renderTeams(); },

  // ─── INVITES ───
  _inviteTeamId: null,
  openGenerateInvite(tid, name) { Admin._inviteTeamId = tid; $$('invite-subtitle').textContent = `For ${name}`; $$('invite-modal').classList.remove('hidden'); $$('invite-form').classList.remove('hidden'); $$('invite-result').classList.add('hidden'); },
  async submitGenerateInvite() {
    const res = await api('/api/admin/invites', { method:'POST', body:JSON.stringify({ team_id: Admin._inviteTeamId, expires_at: $$('invite-expiry').value }) });
    $$('generated-code').textContent = res.code; $$('invite-form').classList.add('hidden'); $$('invite-result').classList.remove('hidden');
  },
  toggleInvites() { const el = $$('invites-section'); el.classList.toggle('hidden'); if(!el.classList.contains('hidden')) Admin.renderInvites(); },
  async renderInvites() {
    const res = await api('/api/admin/invites');
    $$('invites-tbody').innerHTML = res.map(i => `<tr><td>${i.code}</td><td>${esc(i.team_name)}</td><td>${i.used?'Used':'Active'}</td><td>${new Date(i.created_at).toLocaleDateString()}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.revokeInvite(${i.id})">Revoke</button></td></tr>`).join('');
  },
  async revokeInvite(id) { await api(`/api/admin/invites/${id}`, { method:'DELETE' }); Admin.renderInvites(); },

  // ─── LEARNERS ───
  async renderLearners() {
    const tid = $$('l-team-filter').value;
    const learners = await api(tid ? `/api/learners?team_id=${tid==='unassigned'?'null':tid}` : '/api/learners');
    _allLearners = learners; Admin.filterLearners($$('learners-search').value);
  },
  filterLearners(q) {
    const query = q.toLowerCase().trim();
    const filtered = _allLearners.filter(l => l.name.toLowerCase().includes(query));
    $$('learners-tbody').innerHTML = filtered.map(l => `<tr><td>${esc(l.name)}</td><td>${l.team_id?'Joined':'<span class="chip chip-amber">Unassigned</span>'}</td><td>${l.completion_count}</td><td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">Move</button></td></tr>`).join('');
  },
  async moveLearner(lid) {
    const tid = prompt('Target Team ID (leave blank to unassign):');
    if(tid !== null) { await api(`/api/admin/learners/${lid}/team`, { method:'PATCH', body:JSON.stringify({ team_id: tid || null }) }); Admin.renderLearners(); }
  },

  // ─── COURSES ───
  async renderCourses() {
    const res = await api('/api/courses');
    $$('a-courses-grid').innerHTML = res.map(normCourse).map(c => `<div class="card">
      <div style="font-weight:700;">${esc(c.title)}</div>
      <div style="display:flex;gap:4px;margin-top:12px;">
        <button class="btn btn-primary btn-sm w-full" onclick="Builder.openAssign('${c.id}','${esc(c.title)}')">👤 Assign</button>
        <button class="btn btn-outline btn-sm" onclick="Builder.editCourse('${c.id}')">✏ Edit</button>
      </div>
    </div>`).join('');
  },

  // ─── COMPLETIONS ───
  async renderComps(courseId = '') {
    const filter = $$('comp-filter');
    const cid = courseId || filter.value;
    const res = await api(`/api/admin/completions?limit=${COMP_LIMIT}&offset=${compOffset}${cid ? `&course_id=${cid}` : ''}`);
    $$('comp-tbody').innerHTML = res.map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td><td>${r.cert_id||'—'}</td></tr>`).join('');
  }
};
