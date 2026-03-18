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
      if(pg) { pg.classList.toggle('hidden', k!==p); pg.classList.toggle('active', k===p); }
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
      if (!teams.length) { grid.innerHTML = '<div class="empty">No teams created yet.</div>'; }
      else {
        grid.innerHTML = teams.map(t => `<div class="card">
          <div style="display:flex;justify-content:space-between;font-weight:700;">${esc(t.name)} <button class="btn btn-ghost btn-sm" onclick="Admin.openRenameTeam('${t.id}','${esc(t.name)}')">⋮</button></div>
          <div style="font-size:11px;color:var(--ink-meta);margin-bottom:12px;">${t.learner_count || 0} learner${t.learner_count !== 1 ? 's' : ''} · ${t.manager_count || 0} manager${t.manager_count !== 1 ? 's' : ''}</div>
          <div style="display:flex;gap:var(--s-2);flex-wrap:wrap;">
            <button class="btn btn-outline btn-sm" onclick="Admin.toggleTeamMembers('${t.id}')">View Members</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openAddManager('${t.id}','${esc(t.name)}')">+ Manager</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${t.id}','${esc(t.name)}')">+ Invite</button>
          </div>
          <div id="team-members-${t.id}" class="hidden" style="margin-top:12px;padding-top:8px;border-top:1px solid var(--rule);"></div>
        </div>`).join('');
      }
      Admin.renderInviteCodes();
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
  openCreateTeam() {
    $$('team-modal-title').textContent = 'New Team';
    $$('team-name-input').value = '';
    $$('team-modal-btn').textContent = 'Create Team';
    $$('team-modal-btn').onclick = Admin.submitCreateTeam;
    $$('team-modal').classList.remove('hidden');
  },
  async submitCreateTeam() { try { await api('/api/admin/teams', { method:'POST', body:JSON.stringify({ name: $$('team-name-input').value.trim() }) }); $$('team-modal').classList.add('hidden'); Admin.renderTeams(); } catch(e){ Toast.err(e.message); } },
  openRenameTeam(id, name) {
    $$('team-modal-title').textContent = 'Rename Team';
    $$('team-name-input').value = name;
    $$('team-modal-btn').textContent = 'Save';
    $$('team-modal-btn').onclick = () => Admin.submitRenameTeam(id);
    $$('team-modal').classList.remove('hidden');
  },
  async submitRenameTeam(id) {
    try {
      await api(`/api/admin/teams/${id}`, { method:'PATCH', body:JSON.stringify({ name: $$('team-name-input').value.trim() }) });
      $$('team-modal').classList.add('hidden');
      Admin.renderTeams();
    } catch(e){ Toast.err(e.message); }
  },
  openGenerateInvite(teamId, teamName) {
    App._inviteTeamId = teamId;
    $$('invite-subtitle').textContent = `For team: ${esc(teamName)}`;
    $$('invite-form').classList.remove('hidden');
    $$('invite-result').classList.add('hidden');
    $$('invite-modal').classList.remove('hidden');
  },
  openAddManager(teamId, teamName) {
    App._editLearnerId = null;
    $$('al-modal-title').textContent = 'Add Manager';
    $$('al-modal-sub').textContent = `Create a manager account for team: ${esc(teamName)}`;
    $$('al-name').value = ''; $$('al-pw1').value = ''; $$('al-pw2').value = '';
    $$('al-role').value = 'manager';
    const sel = $$('al-team');
    if(sel) {
      sel.innerHTML = '<option value="">Unassigned</option>' + (teamsCache||[]).map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
      sel.value = teamId;
    }
    $$('al-pw-section').classList.remove('hidden');
    $$('al-submit-btn').textContent = 'Create Manager';
    App._alSubmitFn = async () => { await Admin.submitAddLearner(); if(!$$('add-learner-overlay').classList.contains('hidden')) return; Admin.renderTeams(); };
    $$('add-learner-overlay').classList.remove('hidden');
    setTimeout(() => $$('al-name').focus(), CONFIG.FOCUS_DELAY);
  },
  async deleteTeam(id) { if(confirm('Delete team?')){ try { await api(`/api/admin/teams/${id}`, { method:'DELETE' }); Admin.renderTeams(); } catch(e){ Toast.err(e.message); } } },

  async renderInviteCodes() {
    const tbody = $$('invites-tbody'); if(!tbody) return;
    try {
      const invites = await api('/api/admin/invites');
      if (!invites.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--ink-4);">No invite codes yet. Use "+ Invite" on a team card to generate one.</td></tr>';
        return;
      }
      tbody.innerHTML = invites.map(inv => {
        const statusChip = inv.used
          ? `<span class="chip chip-amber" style="font-size:9px;">Used</span>`
          : `<span class="chip chip-blue"  style="font-size:9px;">Active</span>`;
        const created = inv.created_at ? new Date(inv.created_at).toLocaleDateString() : '—';
        const expires = inv.expires_at  ? new Date(inv.expires_at).toLocaleDateString()  : '—';
        return `<tr>
          <td style="font-family:monospace;letter-spacing:0.08em;font-weight:600;">${esc(inv.code)}</td>
          <td>${inv.team_name ? esc(inv.team_name) : '<span style="color:var(--ink-4);">—</span>'}</td>
          <td>${statusChip}</td>
          <td>${created}</td>
          <td>${expires}</td>
          <td>${!inv.used ? `<button class="btn btn-ghost btn-sm" style="color:var(--fail)" onclick="Admin.revokeInvite(${inv.id})">Revoke</button>` : '—'}</td>
        </tr>`;
      }).join('');
    } catch(e) { if(tbody) tbody.innerHTML = `<tr><td colspan="6" style="color:var(--fail);">${esc(e.message)}</td></tr>`; }
  },
  async revokeInvite(id) {
    if(!confirm('Revoke this invite code?')) return;
    try {
      await api(`/api/admin/invites/${id}`, { method:'DELETE' });
      Toast.ok('Invite revoked.');
      Admin.renderInviteCodes();
    } catch(e) { Toast.err(e.message); }
  },

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
      const roleChip = l.role === 'manager' ? '<span class="chip chip-blue" style="font-size:9px;">Mgr</span> ' : '';
      return `<tr>
        <td>${roleChip}${esc(l.name || 'Unnamed')} ${l.overdue_count ? `<span class="chip chip-red" style="font-size:9px;">⚠️ ${l.overdue_count}</span>` : ''}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="App.openEditLearner('${l.id}','${esc(l.name)}','${l.team_id||''}','${l.role||'learner'}')">${teamHtml}</button></td>
        <td>${tagsHtml}</td>
        <td>${l.last_login_at ? new Date(l.last_login_at*1000).toLocaleDateString() : '—'}</td>
        <td>${l.completion_count || 0}</td>
        <td style="white-space:nowrap;">
          <button class="btn btn-ghost btn-sm" title="Reset password" onclick="App.openResetPw('${l.id}','${esc(l.name)}')">🔑</button>
          <button class="btn btn-ghost btn-sm" title="Edit user" onclick="App.openEditLearner('${l.id}','${esc(l.name)}','${l.team_id||''}','${l.role||'learner'}')">✏️</button>
          <button class="btn btn-ghost btn-sm" title="Delete user" style="color:var(--fail)" onclick="App.openDeleteLearner('${l.id}','${esc(l.name)}','${l.role||'learner'}')">✕</button>
        </td>
      </tr>`;
    }).join('');
  },
  async moveLearner(lid) {
    let learner = _allLearners.find(l => l.id === lid);
    if (!learner) {
      try { learner = await api(`/api/learners/${lid}`); } catch(e) { Toast.err(e.message); return; }
    }
    Admin.openEditLearner(learner.id, learner.name, learner.team_id, learner.role);
  },
  openAddLearner() {
    App._editLearnerId = null;
    $$('al-modal-title').textContent = 'Add User';
    $$('al-modal-sub').textContent = 'Set credentials for login.';
    $$('al-name').value = ''; $$('al-pw1').value = ''; $$('al-pw2').value = '';
    $$('al-role').value = 'learner';
    const sel = $$('al-team');
    if(sel) sel.innerHTML = '<option value="">Unassigned</option>' + (teamsCache||[]).map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
    $$('al-pw-section').classList.remove('hidden');
    $$('al-submit-btn').textContent = 'Create Account';
    App._alSubmitFn = Admin.submitAddLearner;
    $$('add-learner-overlay').classList.remove('hidden');
    setTimeout(() => $$('al-name').focus(), CONFIG.FOCUS_DELAY);
  },
  closeAddLearner() { $$('add-learner-overlay').classList.add('hidden'); App._alSubmitFn = null; },
  async submitAddLearner() {
    const name = $$('al-name').value.trim();
    const pw1  = $$('al-pw1').value;
    const pw2  = $$('al-pw2').value;
    const role = $$('al-role').value;
    const teamId = $$('al-team').value || null;
    if (!name) return Toast.err('Name is required.');
    if (pw1.length < CONFIG.MIN_PW_LEN) return Toast.err(`Password must be at least ${CONFIG.MIN_PW_LEN} characters.`);
    if (pw1 !== pw2) return Toast.err('Passwords do not match.');
    try {
      await api('/api/learners', { method:'POST', body:JSON.stringify({ name, password: pw1, role, team_id: teamId }) });
      Admin.closeAddLearner();
      Toast.ok('Account created.');
      Admin.renderLearners();
    } catch(e) { Toast.err(e.message); }
  },
  openEditLearner(id, name, teamId, role) {
    App._editLearnerId = id;
    $$('al-modal-title').textContent = 'Edit User';
    $$('al-modal-sub').textContent = 'Update name, team, or role. Password is unchanged.';
    $$('al-name').value = name;
    $$('al-role').value = role || 'learner';
    const sel = $$('al-team');
    if(sel) {
      sel.innerHTML = '<option value="">Unassigned</option>' + (teamsCache||[]).map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
      sel.value = teamId || '';
    }
    $$('al-pw-section').classList.add('hidden');
    $$('al-submit-btn').textContent = 'Save Changes';
    App._alSubmitFn = Admin.submitEditLearner;
    $$('add-learner-overlay').classList.remove('hidden');
  },
  async submitEditLearner() {
    const name   = $$('al-name').value.trim();
    const role   = $$('al-role').value;
    const teamId = $$('al-team').value || null;
    if (!name) return Toast.err('Name is required.');
    try {
      await api(`/api/learners/${App._editLearnerId}`, { method:'PATCH', body:JSON.stringify({ name, role, team_id: teamId }) });
      Admin.closeAddLearner();
      Toast.ok('User updated.');
      Admin.renderLearners();
    } catch(e) { Toast.err(e.message); }
  },
  openDeleteLearner(id, name, role) {
    const label = role === 'manager' ? 'Manager' : 'Learner';
    $$('confirm-delete-title').textContent = `Delete ${label}`;
    $$('confirm-delete-msg').textContent = `Permanently delete "${name}"? This cannot be undone.`;
    $$('confirm-delete-btn').onclick = () => Admin.submitDeleteLearner(id);
    $$('confirm-delete-overlay').classList.remove('hidden');
  },
  async submitDeleteLearner(id) {
    try {
      await api(`/api/learners/${id}`, { method:'DELETE' });
      $$('confirm-delete-overlay').classList.add('hidden');
      Toast.ok('User deleted.');
      Admin.renderLearners();
    } catch(e) { Toast.err(e.message); }
  },

  // ─── BRANDING ───
  renderBranding() {
    if(!brandCache) return;
    const b = brandCache;
    if($$('br-name'))     $$('br-name').value     = b.name || '';
    if($$('br-tag'))      $$('br-tag').value       = b.tagline || '';
    if($$('br-pass'))     $$('br-pass').value      = b.pass || 80;
    if($$('br-logo-url')) $$('br-logo-url').value  = b.logo && !b.logo.startsWith('data:') ? b.logo : '';
    // Color pickers + hex inputs
    const hex = b.c1 || CONFIG.DEFAULT_C1;
    if($$('br-c1'))     $$('br-c1').value     = hex;
    if($$('br-c1-hex')) $$('br-c1-hex').value = hex;
    const hex2 = b.c2 || CONFIG.DEFAULT_C2;
    if($$('br-c2'))     $$('br-c2').value     = hex2;
    if($$('br-c2-hex')) $$('br-c2-hex').value = hex2;
    // Live preview
    const pn = $$('br-prev-name'); if (pn) pn.textContent = b.name;
    const pl = $$('br-prev-logo');
    if (pl) { pl.src = b.logo || ''; pl.style.display = b.logo ? 'block' : 'none'; }
  },
  async saveBrand() {
    try {
      const hex = $$('br-c1')?.value || CONFIG.DEFAULT_C1;
      const body = {
        org_name: $$('br-name').value,
        pass_threshold: parseInt($$('br-pass').value),
        primary_color: hex,
        secondary_color: $$('br-c2')?.value || CONFIG.DEFAULT_C2,
        logo_url: brandCache.logo && !brandCache.logo.startsWith('data:') ? brandCache.logo : ($$('br-logo-url')?.value || ''),
      };
      await api('/api/brand', { method:'PUT', body:JSON.stringify(body) });
      if (/^#[0-9a-fA-F]{6}$/.test(hex)) localStorage.setItem('trainflow_brand_color', hex);
      brandCache = { ...brandCache, name: body.org_name, c1: hex, c2: body.secondary_color, pass: body.pass_threshold };
      applyBrand();
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
    grid.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;grid-column:1/-1"><div class="spinner"></div></div>';
    try {
      const [courses, sections] = await Promise.all([api('/api/courses'), api('/api/sections').catch(() => [])]);
      sectionsCache = sections || [];
      Admin._renderSectionsBar(sections);

      if (!courses.length) {
        grid.innerHTML = '<div class="card" style="grid-column:1/-1;text-align:center;padding:40px;color:var(--ink-4);">No courses created yet. Use the Importer or Builder to start.</div>';
        return;
      }

      // Group courses by section
      const bySec = {};
      const unsec = [];
      sections.forEach(s => { bySec[s.id] = []; });
      courses.forEach(c => {
        if(c.section_id && bySec[c.section_id]) bySec[c.section_id].push(c);
        else unsec.push(c);
      });

      let html = '';
      sections.forEach(s => {
        html += `<div style="grid-column:1/-1;margin-top:var(--space-6);padding-bottom:var(--space-2);border-bottom:2px solid var(--rule);">
          <div style="font-size:var(--text-xs);font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-4);">Section</div>
          <div style="font-weight:700;font-size:var(--text-lg);">${esc(s.name)}</div>
        </div>`;
        if(!bySec[s.id].length) {
          html += `<div style="grid-column:1/-1;color:var(--ink-4);font-size:var(--text-sm);padding:var(--space-3) 0;">No courses in this section yet.</div>`;
        } else {
          html += bySec[s.id].map(c => Admin._courseCard(c, sections)).join('');
        }
      });
      if(unsec.length) {
        if(sections.length) html += `<div style="grid-column:1/-1;margin-top:var(--space-6);padding-bottom:var(--space-2);border-bottom:2px solid var(--rule);"><div style="font-weight:700;font-size:var(--text-lg);color:var(--ink-3);">Unsectioned</div></div>`;
        html += unsec.map(c => Admin._courseCard(c, sections)).join('');
      }
      grid.innerHTML = html;
    } catch(e) {
      grid.innerHTML = `<div class="card" style="grid-column:1/-1;color:var(--fail);">${esc(e.message)}</div>`;
    }
  },

  _renderSectionsBar(sections) {
    const bar = $$('a-sections-bar'); if(!bar) return;
    if(!sections.length) { bar.innerHTML = '<span style="font-size:var(--text-sm);color:var(--ink-4);">No sections — click "+ New Section" to group your courses.</span>'; return; }
    bar.innerHTML = sections.map(s => `
      <span class="chip chip-blue" style="display:inline-flex;align-items:center;gap:4px;padding-right:4px;">
        ${esc(s.name)}
        <button onclick="Admin.openRenameSection('${s.id}','${esc(s.name)}')" style="background:none;border:none;cursor:pointer;padding:0 2px;font-size:11px;color:inherit;opacity:.7;">✏</button>
        <button onclick="Admin.deleteSection('${s.id}')" style="background:none;border:none;cursor:pointer;padding:0 2px;font-size:11px;color:var(--fail);">✕</button>
      </span>`).join('');
  },

  _courseCard(c, sections) {
    const secOpts = sections.map(s => `<option value="${s.id}" ${c.section_id===s.id?'selected':''}>${esc(s.name)}</option>`).join('');
    return `<div class="card">
      <div style="font-weight:700;">${esc(c.title)}</div>
      ${sections.length ? `<select class="btn btn-ghost btn-sm" style="width:100%;margin-top:8px;text-align:left;" onchange="Admin.setCourseSection('${c.id}',this.value)">
        <option value="">No section</option>${secOpts}
      </select>` : ''}
      <div style="display:flex;gap:4px;margin-top:12px;">
        <button class="btn btn-primary btn-sm w-full" onclick="App.openAssign('${c.id}','${esc(c.title)}')">👤 Assign</button>
      </div>
    </div>`;
  },

  async setCourseSection(courseId, sectionId) {
    try {
      await api(`/api/courses/${courseId}`, { method:'PATCH', body:JSON.stringify({ section_id: sectionId || null }) });
      Admin.renderCourses();
    } catch(e) { Toast.err(e.message); }
  },

  openCreateSection() {
    $$('section-modal-title').textContent = 'New Section';
    $$('section-name-input').value = '';
    $$('section-modal-btn').textContent = 'Create Section';
    $$('section-modal-btn').onclick = Admin.submitCreateSection;
    $$('section-modal').classList.remove('hidden');
    setTimeout(() => $$('section-name-input').focus(), 50);
  },
  openRenameSection(id, name) {
    $$('section-modal-title').textContent = 'Rename Section';
    $$('section-name-input').value = name;
    $$('section-modal-btn').textContent = 'Save';
    $$('section-modal-btn').onclick = () => Admin.submitRenameSection(id);
    $$('section-modal').classList.remove('hidden');
    setTimeout(() => $$('section-name-input').focus(), 50);
  },
  async submitCreateSection() {
    const name = $$('section-name-input').value.trim();
    if(!name) return Toast.err('Section name required.');
    try { await api('/api/sections', { method:'POST', body:JSON.stringify({ name }) }); $$('section-modal').classList.add('hidden'); Admin.renderCourses(); }
    catch(e) { Toast.err(e.message); }
  },
  async submitRenameSection(id) {
    const name = $$('section-name-input').value.trim();
    if(!name) return Toast.err('Section name required.');
    try { await api(`/api/sections/${id}`, { method:'PATCH', body:JSON.stringify({ name }) }); $$('section-modal').classList.add('hidden'); Admin.renderCourses(); }
    catch(e) { Toast.err(e.message); }
  },
  async deleteSection(id) {
    if(!confirm('Delete this section? Courses will become unsectioned.')) return;
    try { await api(`/api/sections/${id}`, { method:'DELETE' }); Admin.renderCourses(); }
    catch(e) { Toast.err(e.message); }
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
    const claudeKey = $$('claude-api-key')?.value.trim();
    const geminiKey = $$('gemini-api-key')?.value.trim();
    if (!claudeKey && !geminiKey) return Toast.err('Enter a Claude or Gemini API key in the AI Settings card.');

    Admin.isGenerating = true;
    if($$('gen-pass-label')) $$('gen-pass-label').textContent = 'Generating…';
    Admin.goPhase(3);

    const qCount   = parseInt($$('q-per-mod')?.value   || '5');
    const difficulty = $$('q-difficulty')?.value || 'applied';
    const focus      = $$('q-focus')?.value      || 'general';
    const total = Admin.parsedModules.length;

    if($$('gen-progress-label')) $$('gen-progress-label').textContent = `0 of ${total}`;
    if($$('gen-prog-bar')) $$('gen-prog-bar').style.width = '0%';
    const listEl = $$('gen-module-list'); if(!listEl) return;
    listEl.innerHTML = Admin.parsedModules.map((m, i) => `
      <div style="padding:8px 0;border-bottom:1px solid var(--rule-2);">
        <div style="display:flex;align-items:center;gap:12px;">
          <div id="gendot-${i}" style="background:var(--ink-4);width:8px;height:8px;border-radius:50%;flex-shrink:0;"></div>
          <span style="font-weight:500;">${esc(m.title)}</span>
          <span id="genstatus-${i}" style="font-size:11px;color:var(--ink-4);margin-left:auto;">Waiting…</span>
        </div>
      </div>`).join('');

    const generatedModules = [];
    for (let i = 0; i < total; i++) {
      const mod = Admin.parsedModules[i];
      const dot    = $$(`gendot-${i}`);
      const status = $$(`genstatus-${i}`);
      if(dot) dot.style.background = 'var(--brand-1)';
      if(status) status.textContent = 'Generating…';
      try {
        const res = await api('/api/ai/generate', {
          method: 'POST',
          body: JSON.stringify({
            title: mod.title, content: mod.content,
            q_count: qCount, difficulty, focus,
            claude_key: claudeKey || undefined,
            gemini_key: geminiKey || undefined
          })
        });
        generatedModules.push({ ...mod, ...res });
        if(dot) dot.style.background = 'var(--pass)';
        if(status) status.textContent = `✓ ${res._provider || 'AI'} · ${res.questions?.length || 0}q`;
      } catch(err) {
        if(dot) dot.style.background = 'var(--fail)';
        if(status) status.textContent = `✗ ${(err.message || 'Failed').slice(0, 50)}`;
        generatedModules.push({ ...mod, questions: [], summary: '', failed: true });
      }
      const p = Math.round(((i + 1) / total) * 100);
      if($$('gen-prog-bar')) $$('gen-prog-bar').style.width = p + '%';
      if($$('gen-progress-label')) $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
    }

    if($$('gen-pass-label')) $$('gen-pass-label').textContent = 'Generation complete!';
    Admin.generatedCourse = {
      title: $$('ai-course-title').value.trim(),
      icon:  $$('ai-course-icon').value || '📋',
      description: $$('ai-course-desc').value.trim(),
      modules: generatedModules
    };
    Admin.renderReview();
    Admin.goPhase(4);
    Admin.isGenerating = false;
  },

  renderReview() {
    const el = $$('review-modules'); if(!el) return;
    const c = Admin.generatedCourse;
    const letters = ['A','B','C','D'];

    // Course header summary
    const header = `<div class="card" style="margin-bottom:var(--space-5);background:var(--accent-lt);border:1px solid var(--rule);">
      <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;">Course</div>
      <div style="font-size:var(--text-lg);font-weight:700;margin-top:2px;">${esc(c.icon || '📋')} ${esc(c.title || 'Untitled')}</div>
      ${c.description ? `<div style="font-size:var(--text-sm);color:var(--ink-3);margin-top:4px;">${esc(c.description)}</div>` : ''}
      <div style="font-size:11px;color:var(--ink-4);margin-top:var(--space-3);">${c.modules.length} module${c.modules.length !== 1 ? 's' : ''} · ${c.modules.reduce((s,m) => s + (m.questions?.length || 0), 0)} questions total</div>
    </div>`;

    const modulesHtml = c.modules.map((m, mi) => {
      const qCount = m.questions?.length || 0;
      const failed = m.failed;

      const questionsHtml = qCount ? m.questions.map((q, qi) => `
        <div style="margin-top:var(--space-4);padding-top:var(--space-3);border-top:1px solid var(--rule-2);">
          <div style="font-weight:600;font-size:var(--text-sm);margin-bottom:var(--space-2);">Q${qi + 1}. ${esc(q.question)}</div>
          ${(q.options || []).map((opt, oi) => opt ? `
            <div style="font-size:var(--text-sm);padding:4px 10px;border-radius:4px;margin-bottom:2px;${oi === q.correct_index ? 'background:var(--pass-lt);color:var(--pass);font-weight:600;' : 'color:var(--ink-3);'}">
              ${letters[oi]}. ${esc(opt)}
            </div>` : '').join('')}
          ${q.explanation ? `<div style="font-size:11px;color:var(--ink-4);margin-top:var(--space-2);font-style:italic;">💡 ${esc(q.explanation)}</div>` : ''}
        </div>`).join('') : '';

      return `<div class="card" style="margin-bottom:var(--space-4);">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:var(--space-3);">
          <div style="flex:1;min-width:0;">
            <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;">Module ${mi + 1}</div>
            <div style="font-weight:700;margin-top:2px;">${esc(m.title)}</div>
            ${m.summary ? `<div style="font-size:var(--text-sm);color:var(--ink-3);margin-top:4px;">${esc(m.summary)}</div>` : ''}
          </div>
          <div style="flex-shrink:0;">
            ${failed
              ? '<span class="chip chip-red">✗ Failed</span>'
              : `<span class="chip chip-green">✓ ${qCount}q</span> <span class="chip" style="background:var(--accent-lt);color:var(--brand-1);font-size:9px;">${esc(m._provider || 'AI')}</span>`}
          </div>
        </div>
        ${questionsHtml}
      </div>`;
    }).join('');

    el.innerHTML = header + modulesHtml;
  },

  async saveAiCourse() {
    const btn = document.querySelector('[onclick="App.saveAiCourse()"]');
    if(btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      await api('/api/courses', { method: 'POST', body: JSON.stringify(Admin.generatedCourse) });
      Toast.ok('Course saved!');
      // Reset importer state
      Admin.fileModules = []; Admin.parsedModules = []; Admin.generatedCourse = null; Admin.isGenerating = false;
      Admin.nav('courses');
    } catch(e) {
      Toast.err(e.message);
      if(btn) { btn.disabled = false; btn.textContent = 'Save to Database'; }
    }
  }
};
