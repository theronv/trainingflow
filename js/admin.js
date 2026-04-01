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
      let teamHtml = '<div style="font-weight:700;margin:var(--s-6) 0 var(--s-4);">Team Compliance</div><div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:var(--space-4);align-items:stretch;">';
      if (!teamsCache.length) {
        teamHtml += '<div class="card" style="grid-column:1/-1;color:var(--ink-4);text-align:center;">No teams established.</div>';
      } else {
        teamHtml += teamsCache.map(t => `<div class="card" onclick="Admin.nav('teams')" style="cursor:pointer;margin-top:0;"><div style="font-weight:700;">${esc(t.name)}</div><div style="font-size:11px;">${t.learner_count || 0} members</div></div>`).join('');
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
        grid.innerHTML = teams.map(t => `<div class="card team-card">
          <div style="font-weight:700;margin-bottom:4px;">${esc(t.name)}</div>
          <div style="font-size:11px;color:var(--ink-meta);margin-bottom:12px;">${t.learner_count || 0} learner${t.learner_count !== 1 ? 's' : ''} · ${t.manager_count || 0} manager${t.manager_count !== 1 ? 's' : ''}</div>
          <div class="team-card-actions">
            <button class="btn btn-outline btn-sm" onclick="Admin.toggleTeamMembers('${t.id}')">View Members</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openAddManager('${t.id}','${esc(t.name)}')">+ Manager</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${t.id}','${esc(t.name)}')">+ Invite</button>
            <button class="btn btn-outline btn-sm" onclick="Admin.openRenameTeam('${t.id}','${esc(t.name)}')">Rename</button>
            <button class="btn btn-outline btn-sm" style="color:var(--fail);border-color:var(--fail);" onclick="Admin.deleteTeam('${t.id}')">Delete</button>
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
  async submitCreateTeam() {
    const name = $$('team-name-input').value.trim();
    if (!name) return Toast.err('Please enter a team name.');
    try {
      await api('/api/admin/teams', { method: 'POST', body: JSON.stringify({ name }) });
      $$('team-modal').classList.add('hidden');
      await Admin.renderTeams();
    } catch(e) { Toast.err(e.message); }
  },
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
    const expiry = $$('invite-expiry'); if (expiry) expiry.value = '';
    const btn = $$('invite-form')?.querySelector('.btn-primary');
    if (btn) { btn.disabled = false; btn.textContent = 'Generate Code'; }
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
  async deleteTeam(id) {
    if (!confirm('Delete this team? All members will become unassigned. This cannot be undone.')) return;
    try {
      await api(`/api/admin/teams/${id}`, { method: 'DELETE' });
      Toast.ok('Team deleted.');
      await Admin.renderTeams();
    } catch(e) { Toast.err(e.message); }
  },

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
        const teamName = inv.team_name ? esc(inv.team_name) : '';
        return `<tr>
          <td style="font-family:monospace;letter-spacing:0.08em;font-weight:600;">${esc(inv.code)}</td>
          <td>${teamName || '<span style="color:var(--ink-4);">—</span>'}</td>
          <td>${statusChip}</td>
          <td>${created}</td>
          <td>${expires}</td>
          <td style="white-space:nowrap;">
            ${!inv.used ? `
              <button class="btn btn-outline btn-sm" onclick="Admin.copyInviteCode('${esc(inv.code)}')">Copy Code</button>
              <button class="btn btn-ghost btn-sm" onclick="Admin.copyInviteMessage('${esc(inv.code)}','${teamName}')" title="Copy a ready-to-send onboarding message">Copy Message</button>
              <button class="btn btn-ghost btn-sm" style="color:var(--fail)" onclick="Admin.revokeInvite(${inv.id})">Revoke</button>
            ` : '—'}
          </td>
        </tr>`;
      }).join('');
    } catch(e) { if(tbody) tbody.innerHTML = `<tr><td colspan="6" style="color:var(--fail);">${esc(e.message)}</td></tr>`; }
  },
  copyInviteCode(code) {
    navigator.clipboard.writeText(code).then(() => Toast.ok(`Code "${code}" copied to clipboard.`)).catch(() => Toast.err('Copy failed — please copy manually: ' + code));
  },

  copyInviteMessage(code, teamName) {
    const orgName = brandCache.name || 'TrainFlow';
    const url = window.location.origin + window.location.pathname;
    const team = teamName ? ` (${teamName})` : '';
    const msg = `Hi,\n\nYou've been added as a manager on ${orgName}${team}.\n\nTo set up your account:\n1. Go to: ${url}\n2. Click Manager → Register with Invite Code\n3. Enter your invite code: ${code}\n\nOnce registered you can add your team and assign training.\n\nWelcome aboard!`;
    navigator.clipboard.writeText(msg).then(() => Toast.ok('Onboarding message copied to clipboard.')).catch(() => Toast.err('Copy failed.'));
  },

  async revokeInvite(id) {
    if(!confirm('Revoke this invite code?')) return;
    try {
      await api(`/api/admin/invites/${id}`, { method:'DELETE' });
      Toast.ok('Invite revoked.');
      Admin.renderInviteCodes();
    } catch(e) { Toast.err(e.message); }
  },

  // ─── TAGS ───
  _tagsCache: [],
  async loadTagsList() {
    try {
      const tags = await api('/api/admin/tags');
      Admin._tagsCache = tags || [];
      const el = $$('tags-list'); if (!el) return;
      if (!tags.length) {
        el.innerHTML = '<div style="color:var(--ink-4);font-size:var(--text-sm);padding:var(--space-2);">No tags yet. Create one above.</div>';
        return;
      }
      el.innerHTML = tags.map(t => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:var(--space-2) 0;border-bottom:1px solid var(--rule);">
          <span class="chip chip-blue">${esc(t.name)}</span>
          <button class="btn btn-ghost btn-sm" style="color:var(--fail);" onclick="Admin.deleteTag('${t.id}')">✕</button>
        </div>`).join('');
    } catch(e) { Toast.err(e.message); }
  },
  async createTag() {
    const input = $$('new-tag-name');
    const name = input?.value.trim();
    if (!name) return Toast.err('Enter a tag name.');
    try {
      await api('/api/admin/tags', { method: 'POST', body: JSON.stringify({ name }) });
      if (input) input.value = '';
      await Admin.loadTagsList();
    } catch(e) { Toast.err(e.message); }
  },
  async deleteTag(id) {
    if (!confirm('Delete this tag? It will be removed from all learners.')) return;
    try {
      await api(`/api/admin/tags/${id}`, { method: 'DELETE' });
      await Admin.loadTagsList();
      Toast.ok('Tag deleted.');
    } catch(e) { Toast.err(e.message); }
  },
  async openLearnerTagsModal(learnerId, learnerName) {
    const sub = $$('lt-subtitle'); if (sub) sub.textContent = learnerName;
    const list = $$('lt-tags-list'); if (list) list.innerHTML = '<div class="spinner" style="width:20px;height:20px;margin:16px auto;"></div>';
    $$('learner-tags-modal').classList.remove('hidden');
    try {
      const [allTags, learnerTags] = await Promise.all([
        api('/api/admin/tags'),
        api(`/api/admin/learners/${learnerId}/tags`)
      ]);
      Admin._tagsCache = allTags || [];
      const assigned = new Set((learnerTags || []).map(t => t.id));
      if (!allTags.length) {
        list.innerHTML = '<div style="color:var(--ink-4);font-size:var(--text-sm);">No tags created yet. Use "Manage Tags" to create some.</div>';
        return;
      }
      list.innerHTML = allTags.map(t => `
        <div style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) 0;border-bottom:1px solid var(--rule);">
          <input type="checkbox" id="lt-${t.id}" ${assigned.has(t.id) ? 'checked' : ''}
            onchange="Admin.toggleLearnerTag('${learnerId}','${t.id}',this.checked)">
          <label for="lt-${t.id}" style="margin:0;">${esc(t.name)}</label>
        </div>`).join('');
    } catch(e) { if(list) list.innerHTML = `<div style="color:var(--fail);">${esc(e.message)}</div>`; }
  },
  async toggleLearnerTag(learnerId, tagId, checked) {
    try {
      if (checked) {
        await api(`/api/admin/learners/${learnerId}/tags`, { method: 'POST', body: JSON.stringify({ tag_id: tagId }) });
      } else {
        await api(`/api/admin/learners/${learnerId}/tags/${tagId}`, { method: 'DELETE' });
      }
    } catch(e) { Toast.err(e.message); }
  },

  // ─── LEARNERS ───
  async renderLearners(page = 1) {
    Admin._learnersPage = page;
    const tbody = $$('learners-tbody'); if(!tbody) return;
    try {
      const tid = $$('l-team-filter').value;
      let path = tid ? `/api/learners?team_id=${tid==='unassigned'?'null':tid}` : '/api/learners';
      path += `${path.includes('?') ? '&' : '?'}page=${page}`;
      const [apiRes, teams] = await Promise.all([api(path), api('/api/admin/teams')]);

      // Handle both paginated { rows, total, pages } and legacy plain array
      const isPaginated = apiRes && !Array.isArray(apiRes) && apiRes.rows;
      _allLearners = isPaginated ? apiRes.rows : (Array.isArray(apiRes) ? apiRes : (apiRes.rows || []));
      const totalPages = isPaginated ? apiRes.pages : 1;
      const totalCount = isPaginated ? apiRes.total : _allLearners.length;

      teamsCache = teams || [];
      const filter = $$('l-team-filter');
      if (filter && filter.options.length <= 2) {
        teamsCache.forEach(t => {
          const o = document.createElement('option'); o.value = t.id; o.textContent = t.name; filter.appendChild(o);
        });
      }
      Admin.filterLearners($$('learners-search') ? $$('learners-search').value : '');

      // Render pagination controls
      let pgEl = $$('learners-pagination');
      if (!pgEl) {
        pgEl = document.createElement('div');
        pgEl.id = 'learners-pagination';
        pgEl.style.cssText = 'display:flex;align-items:center;gap:var(--space-3);justify-content:flex-end;margin-top:var(--space-4);flex-wrap:wrap;';
        tbody.closest('.table-wrap')?.after(pgEl);
      }
      if (totalPages <= 1) { pgEl.innerHTML = ''; return; }
      pgEl.innerHTML = `
        <span style="font-size:var(--text-sm);color:var(--ink-3);">${totalCount} learners · Page ${page} of ${totalPages}</span>
        <button class="btn btn-outline btn-sm" ${page <= 1 ? 'disabled' : ''} onclick="Admin.renderLearners(${page - 1})">← Prev</button>
        <button class="btn btn-outline btn-sm" ${page >= totalPages ? 'disabled' : ''} onclick="Admin.renderLearners(${page + 1})">Next →</button>`;
    } catch(e) { tbody.innerHTML = `<tr><td colspan="5">${esc(e.message)}</td></tr>`; }
  },
  filterLearners(q) {
    const tbody = $$('learners-tbody'); if(!tbody) return;
    const query = (q || '').toLowerCase().trim();
    const filtered = _allLearners.filter(l => (l.name || '').toLowerCase().includes(query));
    if(!filtered.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;">No matches.</td></tr>'; return; }
    tbody.innerHTML = filtered.map(l => {
      const team = (teamsCache||[]).find(t => t.id === l.team_id);
      const teamHtml = team ? esc(team.name) : '<span class="chip chip-amber" style="font-size:9px;">Unassigned</span>';
      const roleChip = l.role === 'manager' ? '<span class="chip chip-blue" style="font-size:9px;">Mgr</span> ' : '';
      return `<tr>
        <td>${roleChip}${esc(l.name || 'Unnamed')} ${l.overdue_count ? `<span class="chip chip-red" style="font-size:9px;">⚠️ ${l.overdue_count}</span>` : ''}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="App.openEditLearner('${l.id}','${esc(l.name)}','${l.team_id||''}','${l.role||'learner'}')">${teamHtml}</button></td>
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
    const btn = $$('al-submit-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      await api('/api/learners', { method:'POST', body:JSON.stringify({ name, password: pw1, role, team_id: teamId }) });
      Admin.closeAddLearner();
      Toast.ok('Account created.');
      Admin.renderLearners();
    } catch(e) { Toast.err(e.message); }
    finally { if (btn) { btn.disabled = false; btn.textContent = orig; } }
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
    const hex3 = b.c3 || CONFIG.DEFAULT_C3;
    if($$('br-c3'))     $$('br-c3').value     = hex3;
    if($$('br-c3-hex')) $$('br-c3-hex').value = hex3;
    // Logo preview box
    const lpb = $$('br-prev-logo-box'); const lph = $$('br-prev-logo-placeholder');
    if (lpb) { lpb.src = b.logo || ''; lpb.style.display = b.logo ? 'block' : 'none'; }
    if (lph) lph.style.display = b.logo ? 'none' : '';
    // Live preview
    const pn = $$('br-prev-name'); if (pn) pn.textContent = b.name;
    const pl = $$('br-prev-logo'); if (pl) { pl.src = b.logo || ''; pl.style.display = b.logo ? 'block' : 'none'; }
    const ptag = $$('br-prev-tagline'); if (ptag) ptag.textContent = b.tagline || CONFIG.DEFAULT_TAGLINE;
    const pcorg = $$('br-prev-cert-org'); if (pcorg) { pcorg.textContent = b.name; pcorg.style.color = hex; }
    // Font selector
    const fontSel = $$('br-font');
    if (fontSel) fontSel.value = b.fontUrl ? 'Custom' : (b.font || CONFIG.DEFAULT_FONT);
    Admin._toggleCustomFont(!!b.fontUrl);
    const cfName = $$('br-font-custom-name');
    if (cfName) cfName.textContent = b.fontUrl ? 'Custom font loaded ✓' : '';
  },
  _toggleCustomFont(show) {
    const el = $$('br-font-custom');
    if (el) el.classList.toggle('hidden', !show);
  },
  async saveBrand(btn) {
    const orig = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      const hex  = $$('br-c1')?.value || CONFIG.DEFAULT_C1;
      const hex2 = $$('br-c2')?.value || CONFIG.DEFAULT_C2;
      const hex3 = $$('br-c3')?.value || CONFIG.DEFAULT_C3;
      const logoVal = brandCache.logo || $$('br-logo-url')?.value || '';
      const fontFamily = $$('br-font')?.value || CONFIG.DEFAULT_FONT;
      const fontUrl = fontFamily === 'Custom' ? (brandCache.fontUrl || '') : '';
      const body = {
        org_name: $$('br-name').value,
        tagline: $$('br-tag')?.value || '',
        pass_threshold: parseInt($$('br-pass').value),
        primary_color: hex,
        secondary_color: hex2,
        accent_color: hex3,
        logo_url: logoVal,
        font_family: fontFamily,
        font_url: fontUrl,
      };
      await api('/api/brand', { method:'PUT', body:JSON.stringify(body) });
      if (/^#[0-9a-fA-F]{6}$/.test(hex)) localStorage.setItem('trainflow_brand_color', hex);
      brandCache = { ...brandCache, name: body.org_name, tagline: body.tagline, c1: hex, c2: hex2, c3: hex3, logo: logoVal, pass: body.pass_threshold, font: fontFamily, fontUrl };
      applyBrand();
      Toast.ok('Brand saved.');
    } catch(e) { Toast.err(e.message); }
    finally { if (btn) { btn.disabled = false; btn.textContent = orig; } }
  },

  // ─── COMPLETIONS ───
  async renderComps(cid = '') {
    const tbody = $$('comp-tbody'); if(!tbody) return;
    try {
      const res = await api(`/api/admin/completions?course_id=${cid}`);
      if (!res || !res.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--ink-4);padding:32px;">No completions recorded yet.</td></tr>';
        return;
      }
      tbody.innerHTML = (res||[]).map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'<span class="chip chip-green">Passed</span>':'<span class="chip chip-red">Failed</span>'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td><td style="font-family:monospace;font-size:11px;">${r.cert_id || '—'}</td></tr>`).join('');
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
        <button class="btn btn-outline btn-sm" onclick="App.openBuilder('${c.id}')">Edit</button>
        <button class="btn btn-outline btn-sm" onclick="Admin.previewCourse('${c.id}')">Preview</button>
        <button class="btn btn-primary btn-sm w-full" onclick="App.openAssign('${c.id}','${esc(c.title)}')">👤 Assign</button>
        <button class="btn btn-outline btn-sm" style="color:var(--fail);border-color:var(--fail);" onclick="Admin.deleteCourse('${c.id}','${esc(c.title)}')">Delete</button>
      </div>
    </div>`;
  },

  async setCourseSection(courseId, sectionId) {
    try {
      await api(`/api/courses/${courseId}`, { method:'PATCH', body:JSON.stringify({ section_id: sectionId || null }) });
      Admin.renderCourses();
    } catch(e) { Toast.err(e.message); }
  },

  async previewCourse(cid) {
    try {
      const res = await api(`/api/courses/${cid}`);
      curCourse = normCourse(res);
      quizSt = {};
      Learner._prog = { course_id: cid, module_idx: 0, modules: [] };
      window._adminPreview = true;
      App.show('screen-course');
      $$('mod-nav-list').innerHTML = curCourse.mods.map((m, i) => `
        <div class="mod-item" id="mod-nav-${i}" onclick="Learner.loadMod(${i})">
          <span class="mod-bullet" id="mod-bullet-${i}">${i + 1}</span>
          <div class="mod-item-body">
            <div class="mod-item-title">${esc(m.title)}</div>
            ${m.summary ? `<div class="mod-item-summary">${esc(m.summary.length > 65 ? m.summary.slice(0, 65) + '…' : m.summary)}</div>` : ''}
          </div>
        </div>`).join('');
      $$('ch-meta').textContent = esc(curCourse.title);
      Learner.loadMod(0);
    } catch(e) { window._adminPreview = false; Toast.err(e.message); }
  },

  async deleteCourse(courseId, title) {
    if (!confirm(`Delete "${title}"? This will remove all modules, questions, assignments, and completion records for this course.`)) return;
    try {
      await api(`/api/courses/${courseId}`, { method:'DELETE' });
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
    if (!pw || pw.length < 8) return Toast.err('Password must be at least 8 characters.');
    const btn = $$('reset-pw-overlay')?.querySelector('.btn-primary');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      await api(`/api/learners/${App._resetPwId}/password`, { method:'PUT', body:JSON.stringify({ password:pw }) });
      Admin.closeResetPw();
      Toast.ok('Password reset.');
    } catch(e) { Toast.err(e.message); }
    finally { if (btn) { btn.disabled = false; btn.textContent = orig; } }
  },

  async exportCSV(scope) {
    try {
      const isTeam = scope === 'team';
      const filterId = isTeam
        ? ($$('m-comp-filter')?.value || '')
        : ($$('comp-filter')?.value || '');
      const url = `/api/admin/completions${filterId ? `?course_id=${encodeURIComponent(filterId)}` : ''}`;
      const res = isTeam ? await managerApi(url) : await api(url);
      if (!res || !res.length) return Toast.info('No completions to export.');
      const rows = [
        ['Learner', 'Course', 'Score (%)', 'Status', 'Date', 'Certificate ID'],
        ...res.map(r => [
          r.user_name,
          r.course_title,
          r.score,
          r.passed ? 'Passed' : 'Failed',
          new Date(r.completed_at * 1000).toLocaleDateString(),
          r.cert_id || ''
        ])
      ];
      const csv = rows.map(row => row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `trainflow-completions-${new Date().toISOString().slice(0,10)}.csv`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch(e) { Toast.err(e.message); }
  },
  async clearRecords() { if(confirm('Clear all completion records? This cannot be undone — learner progress, quiz scores, and certificates will be permanently deleted.')){ await api('/api/completions', { method:'DELETE' }); Admin.renderDash(); } },

  // ─── AI IMPORTER ───
  fileModules: [],
  parsedModules: [],
  generatedCourse: null,
  isGenerating: false,

  // AI Settings persistence
  saveAiKeys() {
    const claude = $$('claude-api-key').value.trim();
    const gemini = $$('gemini-api-key').value.trim();
    if (claude) localStorage.setItem('trainflow_claude_key', claude);
    if (gemini) localStorage.setItem('trainflow_gemini_key', gemini);
    Admin.toggleAiEdit(false);
    Toast.ok('Keys saved locally.');
  },

  async requestAiEdit() {
    const pw = prompt("Please enter your admin password to change AI keys:");
    if (!pw) return;
    try {
      // Use the same validation endpoint/logic as admin login
      const res = await fetch(`${CONFIG.WORKER_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pw })
      });
      if (res.ok) {
        Admin.toggleAiEdit(true);
      } else {
        Toast.err("Incorrect password.");
      }
    } catch (e) {
      Toast.err("Authentication failed.");
    }
  },

  toggleAiEdit(show) {
    $$('ai-keys-edit').classList.toggle('hidden', !show);
    $$('ai-keys-display').classList.toggle('hidden', show);
    $$('btn-ai-edit').classList.toggle('hidden', show);
    if (!show) {
      const c = localStorage.getItem('trainflow_claude_key');
      const g = localStorage.getItem('trainflow_gemini_key');
      $$('claude-key-masked').textContent = c ? '••••••••••••••••' : 'Not set';
      $$('claude-key-masked').style.color = c ? 'var(--pass)' : 'var(--ink-4)';
      $$('gemini-key-masked').textContent = g ? '••••••••••••••••' : 'Not set';
      $$('gemini-key-masked').style.color = g ? 'var(--pass)' : 'var(--ink-4)';
    }
  },

  loadSavedAiKeys() {
    const c = localStorage.getItem('trainflow_claude_key');
    const g = localStorage.getItem('trainflow_gemini_key');
    if (c || g) {
      if (c) $$('claude-api-key').value = c;
      if (g) $$('gemini-api-key').value = g;
      Admin.toggleAiEdit(false);
    }
  },

  async callAI(prompt, systemPrompt = '', maxTokens = 1000) {
    const claudeKey = localStorage.getItem('trainflow_claude_key');
    const geminiKey = localStorage.getItem('trainflow_gemini_key');
    if (!claudeKey && !geminiKey) throw new Error('Please configure an API key first.');

    let lastError = null;

    if (claudeKey) {
      try {
        const res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: { 'x-api-key': claudeKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json', 'anthropic-dangerous-direct-browser-access': 'true' },
          body: JSON.stringify({
            model: 'claude-sonnet-4-6',
            max_tokens: maxTokens,
            system: systemPrompt,
            messages: [{ role: 'user', content: prompt }]
          })
        });
        if (res.ok) {
          const data = await res.json();
          return { text: data.content[0].text, provider: 'Claude' };
        }
        const errBody = await res.json().catch(() => ({}));
        if (res.status === 401) {
          lastError = new Error('Invalid Claude API key. Click "Change keys" to update it.');
        } else {
          lastError = new Error(`Claude error (${res.status}): ${errBody?.error?.message || res.statusText}`);
        }
        console.warn('Claude failed:', lastError.message);
      } catch (e) {
        lastError = e;
        console.warn('Claude request failed, trying fallback...', e);
      }
    }

    if (geminiKey) {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiKey}`;
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: (systemPrompt ? systemPrompt + "\n\n" : "") + prompt }] }] })
        });
        if (res.ok) {
          const data = await res.json();
          return { text: data.candidates[0].content.parts[0].text, provider: 'Gemini' };
        }
        const errBody = await res.json().catch(() => ({}));
        lastError = new Error(res.status === 400 ? 'Invalid Gemini API key.' : `Gemini error (${res.status}): ${errBody?.error?.message || res.statusText}`);
        console.warn('Gemini failed:', lastError.message);
      } catch (e) {
        lastError = e;
        console.warn('Gemini request failed:', e);
      }
    }
    throw lastError || new Error('AI Generation failed. Check your API keys.');
  },

  async autofillCourseDetails() {
    const btn = $$('btn-ai-autofill');
    const orig = btn.innerHTML;
    btn.innerHTML = '<div class="spinner" style="width:12px;height:12px"></div>';
    btn.disabled = true;
    try {
      const combined = Admin.parsedModules.slice(0, 3).map(m => m.content.slice(0, 1000)).join('\n\n');
      const prompt = `Based on this content, suggest a Course Title, a short Description (max 150 chars), and a single relevant emoji.\n\nCONTENT:\n${combined}\n\nReturn JSON only: {"title": "...", "description": "...", "icon": "..."}`;
      const res = await Admin.callAI(prompt, "You are a senior instructional designer. Return JSON only.");
      const json = JSON.parse(res.text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim());
      if (json.title) $$('ai-course-title').value = json.title;
      if (json.description) $$('ai-course-desc').value = json.description;
      if (json.icon) $$('ai-course-icon').value = json.icon;
      Toast.ok('Course details auto-filled.');
    } catch (e) { Toast.err(e.message); }
    finally { btn.innerHTML = orig; btn.disabled = false; }
  },

  goPhase(n) {
    if (n === 1) Admin.loadSavedAiKeys();
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
    const MAX_BYTES = 2 * 1024 * 1024; // 2MB
    if (file.size > MAX_BYTES) {
      const mb = (file.size / 1024 / 1024).toFixed(1);
      Toast.err(`"${file.name}" is ${mb}MB — max 2MB. Split the file or trim content before uploading.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = ev => Admin.addFileModule(ev.target.result, file.name.replace(/\.[^.]+$/, ''));
    reader.readAsText(file);
  },
  addFileModule(rawMd, defaultName) {
    const result = Admin.parseMdToModules(rawMd, defaultName);
    const id = Date.now() + Math.random();
    Admin.fileModules.push({
      id,
      name: result.docTitle,
      subModules: result.modules,
      description: result.docDesc,
      icon: result.docIcon,
      sourceUrl: result.docUrl
    });
    Admin.renderFileModuleList();
  },
  cleanTitle(s) {
    if (!s) return '';
    if (/^[\w-]+$/.test(s) && (s.includes('_') || s.includes('-') || s === s.toLowerCase() || s === s.toUpperCase())) {
      s = s.replace(/[-_]/g, ' ').replace(/\s+/g, ' ').trim();
    }
    return s.replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
  },
  parseMdToModules(raw, defaultTitle) {
    let lines = raw.split('\n');
    let docTitle = defaultTitle, docDesc = '', docIcon = '', docUrl = '';

    // Extract metadata
    let i = 0;
    while (i < lines.length && i < 15) {
      const line = lines[i].trim();
      if (!line) { i++; continue; }
      const tm = line.match(/^(Title|Course Title):\s*(.+)/i);
      const dm = line.match(/^(Description):\s*(.+)/i);
      const im = line.match(/^(Icon):\s*(.+)/i);
      const um = line.match(/^URL Source:\s*(.+)/i);
      if (tm) { docTitle = tm[2].trim(); lines[i] = ''; }
      else if (dm) { docDesc = dm[2].trim(); lines[i] = ''; }
      else if (im) { docIcon = im[2].trim(); lines[i] = ''; }
      else if (um) { docUrl = um[1].trim(); lines[i] = ''; }
      else if (line.match(/^Markdown Content:/i)) lines[i] = '';
      else if (!line.match(/^([-* ]){3,}$/)) break;
      i++;
    }

    // Change 1 — Pre-processor: strip navigation noise from content lines (after metadata)
    const isNavLink = l => {
      const t = l.trim();
      if (/^[-*]\s*\[[ x]\]\s*\[/.test(t)) return true;           // checkbox nav
      if (/^[-*]?\s*\[.+\]\(https?:\/\/[^)]+\)[\s.,;]*$/.test(t)) return true; // lone link line
      if (/^https?:\/\/\S+$/.test(t)) return true;                 // bare URL
      return false;
    };
    const isAnchorOnlyHeading = l => /^#{1,6}\s+\[.+\]\(https?:\/\/.+\)\s*$/.test(l);
    const isBoilerplate = l => /^(©|\(c\)|copyright|all rights reserved|privacy policy|terms of (use|service)|cookie)/i.test(l.trim());

    // Group content lines into blank-separated paragraphs; drop nav-dense paragraphs (>70% link lines)
    const contentLines = lines.slice(i);
    const paragraphs = [];
    let curPara = [];
    for (const l of contentLines) {
      if (!l.trim()) { if (curPara.length) { paragraphs.push(curPara); curPara = []; } paragraphs.push(['']); }
      else curPara.push(l);
    }
    if (curPara.length) paragraphs.push(curPara);

    const filteredContent = paragraphs.flatMap(para => {
      if (para.length === 1 && !para[0].trim()) return para;
      const nonEmpty = para.filter(l => l.trim());
      if (nonEmpty.length >= 3 && nonEmpty.filter(isNavLink).length / nonEmpty.length > 0.7) return [];
      return para.filter(l => !isAnchorOnlyHeading(l) && !isBoilerplate(l));
    });

    const metaLines = lines.slice(0, i).filter(l => l.trim() !== '');
    const cleanLines = [...metaLines, ...filteredContent];

    const hasH2 = cleanLines.some(l => l.startsWith('## '));
    // Change 2 — Heading hierarchy: try ### after ## but before HR
    const hasH3 = !hasH2 && cleanLines.some(l => l.startsWith('### '));
    const hasHR = !hasH2 && !hasH3 && cleanLines.some(l => /^([-* ]){3,}$/.test(l.trim()));

    const modules = []; let cur = null;
    if (hasH2) {
      for (const line of cleanLines) {
        const h2 = line.match(/^##\s+(.+)/);
        if (h2) {
          if (cur) modules.push(cur);
          cur = { title: Admin.cleanTitle(h2[1].trim()), rawLines: [] };
        } else if (cur) cur.rawLines.push(line);
        else if (line.trim() && !docDesc) docDesc += line + ' ';
      }
    } else if (hasH3) {
      for (const line of cleanLines) {
        const h3 = line.match(/^###\s+(.+)/);
        if (h3) {
          if (cur) modules.push(cur);
          cur = { title: Admin.cleanTitle(h3[1].trim()), rawLines: [] };
        } else if (cur) cur.rawLines.push(line);
        else if (line.trim() && !docDesc) docDesc += line + ' ';
      }
    } else if (hasHR) {
      cur = { title: Admin.cleanTitle(docTitle), rawLines: [] };
      let sectionIdx = 1;
      for (const line of cleanLines) {
        if (/^([-* ]){3,}$/.test(line.trim())) {
          if (cur.rawLines.some(l => l.trim())) {
            modules.push(cur);
            sectionIdx++;
            cur = { title: `${Admin.cleanTitle(docTitle)} - Part ${sectionIdx}`, rawLines: [] };
          }
        } else cur.rawLines.push(line);
      }
    }
    if (cur && cur.rawLines.some(l => l.trim())) modules.push(cur);
    if (!modules.length) modules.push({ title: Admin.cleanTitle(docTitle), rawLines: cleanLines });

    // Change 3 — Post-parse quality filter: drop modules with <40 real content words
    const contentWords = text => text.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/[#*_`>~]/g, ' ').split(/\s+/).filter(w => w.length > 2).length;

    return {
      docTitle: Admin.cleanTitle(docTitle),
      docDesc: docDesc.trim(),
      docIcon: docIcon,
      docUrl: docUrl,
      modules: modules
        .filter(m => contentWords(m.rawLines.join('\n')) >= 40)
        .map(m => {
          // Extract a URL Source line embedded within this section's content
          let sectionUrl = '';
          const filteredLines = m.rawLines.filter(line => {
            const um = line.match(/^URL Source:\s*(.+)/i);
            if (um) { sectionUrl = um[1].trim(); return false; }
            return true;
          });
          return { title: m.title, content: filteredLines.join('\n'), reference_url: sectionUrl || docUrl };
        })
    };
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
    const totalMods = Admin.fileModules.reduce((s, f) => s + f.subModules.length, 0);
    const MAX_MODS = 20;
    if (totalMods > MAX_MODS) {
      Toast.err(`${totalMods} modules detected — max is ${MAX_MODS}. Remove ${totalMods - MAX_MODS} module(s) from the list above before proceeding.`);
      return;
    }
    Admin.parsedModules = [];
    Admin.fileModules.forEach(fm => fm.subModules.forEach(sm => Admin.parsedModules.push({ ...sm, reference_url: sm.reference_url || fm.sourceUrl || '' })));

    const first = Admin.fileModules[0];
    $$('ai-course-title').value = first.name;
    $$('ai-course-desc').value = first.description || '';
    $$('ai-course-icon').value = first.icon || '📋';
    
    Admin.renderModulePreview();
    Admin.goPhase(2);
  },
  renderModulePreview() {
    const el = $$('module-preview'); if(!el) return;
    el.innerHTML = `
      <div style="font-size:var(--text-sm);font-weight:600;color:var(--ink-2);margin-bottom:var(--space-3);">
        Review and edit module titles and source URLs before generating.
      </div>` +
    Admin.parsedModules.map((m, i) => {
      const wc = (m.content || '').trim().split(/\s+/).length;
      return `
      <div class="card" style="margin-bottom:var(--space-2);padding:var(--space-3);">
        <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-2);">
          <span style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);white-space:nowrap;">MODULE ${i+1}</span>
          <span style="font-size:10px;color:var(--ink-4);margin-left:auto;">~${wc} words</span>
        </div>
        <input type="text" value="${esc(m.title)}"
          style="width:100%;font-weight:600;border:1px solid var(--border);border-radius:4px;padding:5px 8px;background:var(--bg);color:var(--ink-1);font-size:var(--text-sm);"
          placeholder="Module title"
          onchange="Admin.parsedModules[${i}].title = this.value">
        <input type="url" value="${esc(m.reference_url || '')}"
          style="width:100%;margin-top:6px;font-size:11px;border:1px solid var(--border);border-radius:4px;padding:4px 8px;background:var(--bg);color:var(--ink-3);"
          placeholder="Source URL (auto-detected from scraper)"
          onchange="Admin.parsedModules[${i}].reference_url = this.value">
      </div>`;
    }).join('');
  },

  async startGeneration() {
    if (Admin.isGenerating) return;
    // Auto-save any keys currently typed in the input fields
    const claudeInput = $$('claude-api-key')?.value.trim();
    const geminiInput = $$('gemini-api-key')?.value.trim();
    if (claudeInput) localStorage.setItem('trainflow_claude_key', claudeInput);
    if (geminiInput) localStorage.setItem('trainflow_gemini_key', geminiInput);
    const claudeKey = localStorage.getItem('trainflow_claude_key');
    const geminiKey = localStorage.getItem('trainflow_gemini_key');
    if (!claudeKey && !geminiKey) return Toast.err('Enter a Claude or Gemini API key in the AI Settings card.');

    // Gate 3: warn about content truncation for long modules
    const CHAR_LIMIT = 4000;
    const longMods = Admin.parsedModules.filter(m => (m.content || '').length > CHAR_LIMIT);
    if (longMods.length > 0) {
      Toast.info(`${longMods.length} module(s) exceed ${CHAR_LIMIT} characters — only the first ${CHAR_LIMIT} chars will be used for AI generation. Consider trimming long modules for best results.`);
    }

    Admin.isGenerating = true;
    try {
    Admin.goPhase(3);

    const qCount   = parseInt($$('q-per-mod')?.value   || '5');
    const difficulty = $$('q-difficulty')?.value || 'applied';
    const focus      = $$('q-focus')?.value      || 'general';
    const total = Admin.parsedModules.length;

    const listEl = $$('gen-module-list'); if(!listEl) return;
    listEl.innerHTML = Admin.parsedModules.map((m, i) => `
      <div style="padding:10px 0;border-bottom:1px solid var(--rule-2);">
        <div style="display:flex;align-items:center;gap:12px;">
          <div id="gendot-${i}" class="gen-dot" style="background:var(--ink-4);width:8px;height:8px;border-radius:50%;flex-shrink:0;"></div>
          <div style="flex:1">
            <div style="font-weight:600;font-size:13px" id="gentitle-${i}">${esc(m.title)}</div>
            <div style="display:flex;gap:12px;margin-top:2px">
              <span id="genstatus-q-${i}" style="font-size:10px;color:var(--ink-4)">Content: waiting</span>
              <span id="genstatus-s-${i}" style="font-size:10px;color:var(--ink-4)">Summary: waiting</span>
            </div>
          </div>
        </div>
      </div>`).join('');

    const generatedModules = [];
    
    // PASS 1: QUESTIONS
    $$('gen-pass-label').textContent = 'Pass 1: Writing Questions';
    for (let i = 0; i < total; i++) {
      const mod = Admin.parsedModules[i];
      const dot = $$(`gendot-${i}`);
      const qStatus = $$(`genstatus-q-${i}`);
      if(dot) dot.style.background = 'var(--brand-1)';
      qStatus.innerHTML = '<span style="color:var(--brand-1)">Generating…</span>';
      $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
      $$('gen-prog-bar').style.width = `${(i / total) * 50}%`;

      try {
        const prompt = Admin._buildQuestionPrompt(mod.title, mod.content, qCount, difficulty, focus);
        const res = await Admin.callAI(prompt, "You are an expert instructional designer. Return JSON only, no markdown.", 3000);
        const parsed = JSON.parse(res.text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim());
        const questions = parsed.questions || parsed; // fallback if AI returns bare array
        const aiTitle = parsed.title || mod.title;
        const objectives = Array.isArray(parsed.learning_objectives) ? parsed.learning_objectives : [];
        const titleEl = $$(`gentitle-${i}`);
        if (titleEl && aiTitle !== mod.title) titleEl.textContent = aiTitle;
        generatedModules.push({ ...mod, title: aiTitle, learning_objectives: objectives, questions, _provider: res.provider });
        qStatus.innerHTML = `<span style="color:var(--pass)">✓ ${questions.length} q · ${objectives.length} objectives</span>`;
      } catch(err) {
        console.error(err);
        qStatus.innerHTML = `<span style="color:var(--fail)">✗ Failed</span>`;
        generatedModules.push({ ...mod, questions: [], learning_objectives: [], failed: true });
      }
    }

    // PASS 2: SUMMARIES
    $$('gen-pass-label').textContent = 'Pass 2: Creating Summaries';
    for (let i = 0; i < generatedModules.length; i++) {
      const mod = generatedModules[i];
      const sStatus = $$(`genstatus-s-${i}`);
      const dot = $$(`gendot-${i}`);
      sStatus.innerHTML = '<span style="color:var(--brand-1)">Writing…</span>';
      $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
      $$('gen-prog-bar').style.width = `${50 + (i / total) * 50}%`;

      try {
        const prompt = `Write a learner-friendly summary of this training module. 
        MODULE: ${mod.title}
        CONTENT: ${mod.content.slice(0, 4000)}
        
        Return a single string (max 250 chars) that provides a clear overview of the key takeaways.`;
        const res = await Admin.callAI(prompt, "You are a senior instructional designer.", 500);
        generatedModules[i].summary = res.text.trim();
        sStatus.innerHTML = `<span style="color:var(--pass)">✓ Ready</span>`;
        if(dot) dot.style.background = 'var(--pass)';
      } catch(err) {
        sStatus.innerHTML = `<span style="color:var(--ink-4)">✗ Skipped</span>`;
        if(dot && !mod.failed) dot.style.background = 'var(--pass)';
      }
    }

    $$('gen-pass-label').textContent = 'Generation complete!';
    $$('gen-prog-bar').style.width = '100%';
    Admin.generatedCourse = {
      title: $$('ai-course-title').value.trim(),
      icon:  $$('ai-course-icon').value || '📋',
      description: $$('ai-course-desc').value.trim(),
      modules: generatedModules
    };
    Admin.renderReview();
    Admin.goPhase(4);
    Admin.isGenerating = false;
    } catch(fatalErr) {
      console.error('Generation failed:', fatalErr);
      Admin.isGenerating = false;
      Admin.generatedCourse = null;
      Admin.goPhase(2);
      Toast.err('Generation failed: ' + fatalErr.message + '. Please try again.');
    }
  },

  _buildQuestionPrompt(title, content, qCount, difficulty, focus) {
    const focusInstr = {
      general: 'Test comprehension of the key concepts.',
      support: 'Focus on support scenarios and customer interactions.',
      process: 'Focus on the correct sequence of steps and procedures.',
      technical: 'Focus on specific values, limits, and technical requirements.'
    };
    const diffInstr = {
      foundational: 'Test basic recall and recognition.',
      applied: 'Test application of knowledge in scenarios.',
      analytical: 'Test judgment and nuanced understanding.'
    };
    return `You are an expert instructional designer. Analyze this training module and return a JSON object.

MODULE TITLE (may be generic): ${title}
CONTENT:
${content.slice(0, 4000)}

Return ONLY this JSON structure (no markdown, no extra text):
{
  "title": "A concise, descriptive module title (max 8 words, derived from the actual content)",
  "learning_objectives": ["Learners will be able to ...", "Understand ...", "Apply ..."],
  "questions": [
    {"question": "...", "options": ["A", "B", "C", "D"], "correct_index": 0, "explanation": "Why this answer is correct..."}
  ]
}

RULES:
- Write exactly ${qCount} questions
- ${focusInstr[focus]}
- ${diffInstr[difficulty]}
- Each question must have exactly 4 options
- learning_objectives: 3-5 bullet points starting with action verbs
- title: must reflect the actual content, not be generic like "Part 2"`;
  },

  renderReview() {
    const el = $$('review-modules'); if(!el) return;
    const c = Admin.generatedCourse;
    const letters = ['A','B','C','D'];

    // Course header summary
    const header = `<div class="card" style="margin-bottom:var(--space-5);background:var(--bg-2);border:1px solid var(--border);">
      <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;">Course Preview</div>
      <div style="font-size:var(--text-lg);font-weight:700;margin-top:2px;">${esc(c.icon || '📋')} ${esc(c.title || 'Untitled')}</div>
      ${c.description ? `<div style="font-size:var(--text-sm);color:var(--ink-3);margin-top:4px;">${esc(c.description)}</div>` : ''}
      <div style="font-size:11px;color:var(--ink-4);margin-top:var(--space-3);">${c.modules.length} module${c.modules.length !== 1 ? 's' : ''} · ${c.modules.reduce((s,m) => s + (m.questions?.length || 0), 0)} questions total</div>
    </div>`;

    const modulesHtml = c.modules.map((m, mi) => {
      const qCount = m.questions?.length || 0;
      const failed = m.failed;
      const objectives = Array.isArray(m.learning_objectives) ? m.learning_objectives : [];

      const objectivesHtml = objectives.length ? `
        <div style="margin-top:var(--space-3);">
          <div style="font-size:10px;font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Learning Objectives</div>
          <ul style="margin:0;padding-left:var(--space-5);">
            ${objectives.map(o => `<li style="font-size:12px;color:var(--ink-2);margin-bottom:3px;">${esc(o)}</li>`).join('')}
          </ul>
        </div>` : '';

      const sourceHtml = m.reference_url ? `
        <div style="margin-top:var(--space-3);display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg-2);border-radius:6px;border:1px solid var(--border);">
          <span style="font-size:12px;">🔗</span>
          <span style="font-size:11px;color:var(--ink-4);">Source:</span>
          <a href="${esc(m.reference_url)}" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--brand-1);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(m.reference_url)}</a>
        </div>` : '';

      const questionsHtml = qCount ? m.questions.map((q, qi) => `
        <div style="margin-top:var(--space-4);padding-top:var(--space-3);border-top:1px solid var(--rule-2);">
          <div style="font-weight:600;font-size:var(--text-sm);margin-bottom:var(--space-2);">Q${qi + 1}. ${esc(q.question)}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
            ${(q.options || []).map((opt, oi) => opt ? `
              <div style="font-size:12px;padding:6px 10px;border-radius:6px;border:1px solid var(--border);${oi === q.correct_index ? 'background:var(--pass-lt);border-color:#bbf7d0;color:var(--pass);font-weight:600;' : 'color:var(--ink-3);'}">
                <span style="opacity:.5;margin-right:4px">${letters[oi]}</span> ${esc(opt)}
              </div>` : '').join('')}
          </div>
          ${q.explanation ? `<div style="font-size:11px;color:var(--ink-4);margin-top:var(--space-2);padding:8px;background:var(--bg-2);border-radius:4px">💡 ${esc(q.explanation)}</div>` : ''}
        </div>`).join('') : '';

      return `<div class="card" style="margin-bottom:var(--space-4);">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:var(--space-3);">
          <div style="flex:1;min-width:0;">
            <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;">Module ${mi + 1}</div>
            <div style="font-weight:700;margin-top:2px;">${esc(m.title)}</div>
            ${m.summary ? `<div style="font-size:var(--text-sm);color:var(--ink-2);margin-top:8px;line-height:1.5;padding-left:12px;border-left:2px solid var(--pass)">${esc(m.summary)}</div>` : ''}
            ${objectivesHtml}
            ${sourceHtml}
          </div>
          <div style="flex-shrink:0;">
            ${failed
              ? '<span class="chip chip-red">✗ Failed</span>'
              : `<span class="chip chip-green" style="font-size:10px">✓ ${qCount} questions</span> <span class="chip" style="background:var(--bg-2);color:var(--brand-1);font-size:9px;">${esc(m._provider || 'AI')}</span>`}
          </div>
        </div>
        ${questionsHtml}
      </div>`;
    }).join('');

    el.innerHTML = header + modulesHtml;
  },

  async saveAiCourse() {
    const btn = document.querySelector('[onclick="App.saveAiCourse()"]');

    // Gate 4: warn on large payloads before hitting the Worker
    const payload = JSON.stringify(Admin.generatedCourse);
    const payloadKB = Math.round(payload.length / 1024);
    if (payloadKB > 500) {
      const ok = confirm(`This course is large (~${payloadKB}KB). Saving may take a moment. Continue?`);
      if (!ok) return;
    }

    if(btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      await api('/api/courses', { method: 'POST', body: payload });
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
