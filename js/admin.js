// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Admin Management (Stable)
// ══════════════════════════════════════════════════════════

const Admin = {
  _navSeq: 0,
  _compOffset: 0,

  init() {
    App.show('screen-admin');
    Admin.nav('dashboard');
  },

  nav(p) {
    if (!getToken()) return App.show('screen-login');
    Admin._navSeq++;
    ['dashboard','courses','importer','learners','teams','completions','branding','settings'].forEach(k => {
      const btn = $$(`an-${k}`), pg = $$(`ap-${k}`);
      if(btn) btn.classList.toggle('active', k===p);
      if(pg) { pg.classList.toggle('hidden', k!==p); pg.classList.toggle('active', k===p); }
    });
    if(p==='dashboard') Admin.renderDash();
    if(p==='courses')   Admin.renderCourses();
    if(p==='importer')  Importer.goPhase(1);
    if(p==='learners')  Admin.renderLearners();
    if(p==='teams')     Admin.renderTeams();
    if(p==='completions') Admin.renderComps();
    if(p==='branding')  Admin.renderBranding();
  },

  // ─── DASHBOARD ───
  async renderDash() {
    const seq = Admin._navSeq;
    const statsEl = $$('a-stats'); if(!statsEl) return;
    statsEl.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;"><div class="spinner"></div></div>';

    try {
      const [stats, teams, recent] = await Promise.all([
        api('/api/admin/stats').catch(e => ({ error: e.message, summary: { total_learners:'N/A', total_courses:'N/A', completions_this_month:'N/A', pass_rate:'N/A' }, learners:[] })),
        api('/api/admin/teams').catch(() => []),
        api('/api/admin/completions').catch(() => [])
      ]);
      if (Admin._navSeq !== seq) return;

      const summary = stats.summary || { total_learners:'N/A', total_courses:'N/A', completions_this_month:'N/A', pass_rate:'N/A' };
      const learners = stats.learners || [];
      teamsCache = teams || [];

      // ── Stat tiles ──
      const pr = typeof summary.pass_rate === 'number' ? summary.pass_rate + '%' : 'N/A';
      const tiles = [
        { label: 'Learners',   value: summary.total_learners,         icon: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>' },
        { label: 'Courses',    value: summary.total_courses,           icon: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>' },
        { label: 'This Month', value: summary.completions_this_month,  icon: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/></svg>' },
        { label: 'Pass Rate',  value: pr,                              icon: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>' },
      ];
      statsEl.innerHTML = tiles.map(({ label, value, icon }) => `<div class="stat-tile">
        <div class="stat-icon">${icon}</div>
        <div class="stat-value">${value}</div>
        <div class="stat-label">${label}</div>
      </div>`).join('');

      // ── Recent activity ──
      const recentEl = $$('a-recent');
      if (recentEl) {
        const items = (Array.isArray(recent) ? recent : []).slice(0, 6);
        if (!items.length) {
          recentEl.innerHTML = `<div class="dash-section-label">Recent Activity</div><div class="empty-state-sm">No completions recorded yet.</div>`;
        } else {
          recentEl.innerHTML = `<div class="dash-section-label">Recent Activity</div>
            <div class="activity-list">${items.map(c => {
              const date = new Date(c.completed_at * 1000).toLocaleDateString(undefined, { month:'short', day:'numeric' });
              const chip = c.passed
                ? '<span class="chip chip-brand-accent">Pass</span>'
                : '<span class="chip chip-red">Fail</span>';
              return `<div class="activity-item">
                <div class="activity-info">
                  <div class="activity-name">${esc(c.user_name)}</div>
                  <div class="activity-course">${esc(c.course_title)}</div>
                </div>
                <div class="activity-meta">${chip}<span class="activity-date">${date}</span></div>
              </div>`;
            }).join('')}</div>`;
        }
      }

      // ── Team compliance table ──
      const unassigned = (learners||[]).filter(l => !l.team_id).length;
      let teamHtml = '<div class="dash-section-label">Team Compliance</div>';
      if (!teamsCache.length) {
        teamHtml += '<div class="empty-state-sm">No teams established yet.</div>';
      } else {
        teamHtml += `<div class="table-wrap"><table>
          <thead><tr><th>Team</th><th>Members</th><th>Managers</th></tr></thead>
          <tbody>${teamsCache.map(t => `<tr>
            <td><span class="link-cell" onclick="Admin.nav('teams')">${esc(t.name)}</span></td>
            <td>${t.learner_count || 0}</td>
            <td>${t.manager_count || 0}</td>
          </tr>`).join('')}</tbody>
        </table></div>`;
      }
      if (unassigned > 0) teamHtml += `<div class="card" onclick="Admin.nav('learners')" style="margin-top:var(--space-3);background:var(--fail-lt);color:var(--fail);cursor:pointer;">⚠ ${unassigned} unassigned learner${unassigned !== 1 ? 's' : ''} found. Click to review.</div>`;
      $$('a-course-stats').innerHTML = teamHtml;

      Admin.renderTroubleSpots();
    } catch(e) {
      statsEl.innerHTML = `<div class="card" style="color:var(--fail);width:100%;">${esc(e.message)}</div>`;
    }
  },

  async renderTroubleSpots() {
    try {
      const spots = await api('/api/admin/trouble-spots').catch(() => []);
      const el = $$('a-trouble-spots'); if(!el) return;
      if(!spots || !spots.length) { el.innerHTML = ''; return; }
      el.innerHTML = `<div class="dash-section-label" style="color:var(--fail);">Trouble Spots</div>
        <div class="table-wrap"><table><thead><tr><th>Question</th><th>Fail Rate</th></tr></thead>
        <tbody>${spots.map(s=>`<tr><td>${esc(s.question)}</td><td><span class="chip chip-red">${s.failure_rate}%</span></td></tr>`).join('')}</tbody></table></div>`;
    } catch(e) { console.warn('renderTroubleSpots:', e.message); }
  },

  // ─── TEAMS ───
  _selectedTeamId: null,

  async renderTeams() {
    const seq = Admin._navSeq;
    try {
      const teams = await api('/api/admin/teams');
      if (Admin._navSeq !== seq) return;
      teamsCache = teams || [];
      const listEl = $$('teams-list'); if (!listEl) return;

      if (!teams.length) {
        listEl.innerHTML = '<div class="empty-state-sm">No teams yet.</div>';
        const detail = $$('team-detail');
        if (detail) detail.innerHTML = '<div class="team-detail-empty">Create your first team to get started.</div>';
        return;
      }

      listEl.innerHTML = teams.map(t => `
        <div class="team-list-item" id="tli-${t.id}" onclick="Admin.selectTeam('${t.id}')">
          <div class="team-list-name">${esc(t.name)}</div>
          <div class="team-list-meta">${t.learner_count || 0} member${t.learner_count !== 1 ? 's' : ''} · ${t.manager_count || 0} manager${t.manager_count !== 1 ? 's' : ''}</div>
        </div>`).join('');

      const toSelect = (Admin._selectedTeamId && teams.find(t => t.id === Admin._selectedTeamId))
        ? Admin._selectedTeamId
        : teams[0].id;
      Admin.selectTeam(toSelect);
    } catch(e) { const el = $$('teams-list'); if(el) el.innerHTML = `<div class="empty-state-sm" style="color:var(--fail);">${esc(e.message)}</div>`; }
  },

  async selectTeam(tid) {
    Admin._selectedTeamId = tid;
    document.querySelectorAll('.team-list-item').forEach(el => el.classList.remove('active'));
    const listItem = $$(`tli-${tid}`); if (listItem) listItem.classList.add('active');

    const team = teamsCache.find(t => t.id === tid); if (!team) return;
    const detail = $$('team-detail'); if (!detail) return;

    detail.innerHTML = `
      <div class="team-detail-head">
        <div>
          <div class="team-detail-name">${esc(team.name)}</div>
          <div class="team-detail-meta">${team.learner_count || 0} learner${team.learner_count !== 1 ? 's' : ''} · ${team.manager_count || 0} manager${team.manager_count !== 1 ? 's' : ''}</div>
        </div>
        <div class="team-detail-actions">
          <button class="btn btn-outline btn-sm" onclick="Admin.openAddManager('${tid}','${esc(team.name)}')">+ Manager</button>
          <button class="btn btn-outline btn-sm" onclick="Admin.openGenerateInvite('${tid}','${esc(team.name)}')">+ Invite</button>
          <button class="btn btn-outline btn-sm" onclick="Admin.openRenameTeam('${tid}','${esc(team.name)}')">Rename</button>
          <button class="btn btn-outline btn-sm" style="color:var(--fail);border-color:var(--fail);" onclick="Admin.deleteTeam('${tid}')">Delete</button>
        </div>
      </div>
      <div class="dash-section-label" style="margin-top:var(--space-5);margin-bottom:var(--space-3);">Members</div>
      <div id="team-members-detail"><div style="display:flex;justify-content:center;padding:var(--space-6);"><div class="spinner"></div></div></div>
      <div class="dash-section-label" style="margin-top:var(--space-6);margin-bottom:var(--space-3);">Invite Codes</div>
      <div id="team-invites-detail"><div style="display:flex;justify-content:center;padding:var(--space-6);"><div class="spinner"></div></div></div>`;

    // Load members
    try {
      const res = await api(`/api/learners?team_id=${tid}`);
      const rows = Array.isArray(res) ? res : (res.rows || []);
      const membersEl = $$('team-members-detail'); if (!membersEl) return;
      if (!rows.length) {
        membersEl.innerHTML = '<div class="empty-state-sm">No members yet. Generate an invite code to add learners.</div>';
      } else {
        membersEl.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th>Name</th><th>Role</th><th>Actions</th></tr></thead>
          <tbody>${rows.map(l => {
            const roleChip = l.role === 'manager'
              ? '<span class="chip chip-blue" style="font-size:9px;">Manager</span>'
              : '<span class="chip chip-green" style="font-size:9px;">Learner</span>';
            return `<tr>
              <td>${esc(l.name)}</td>
              <td>${roleChip}</td>
              <td><button class="btn btn-ghost btn-sm" onclick="Admin.moveLearner('${l.id}')">Move</button></td>
            </tr>`;
          }).join('')}</tbody>
        </table></div>`;
      }
    } catch(e) {
      const el = $$('team-members-detail');
      if (el) el.innerHTML = `<div style="color:var(--fail);font-size:var(--text-sm);">${esc(e.message)}</div>`;
    }

    // Load invite codes for this team
    try {
      const invites = await api('/api/admin/invites');
      const teamInvites = (invites || []).filter(inv => inv.team_id === tid);
      const invEl = $$('team-invites-detail'); if (!invEl) return;
      if (!teamInvites.length) {
        invEl.innerHTML = '<div class="empty-state-sm">No invite codes yet. Use "+ Invite" above to generate one.</div>';
      } else {
        invEl.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th>Code</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
          <tbody>${teamInvites.map(inv => {
            const statusChip = inv.used
              ? '<span class="chip chip-amber" style="font-size:9px;">Used</span>'
              : '<span class="chip chip-blue" style="font-size:9px;">Active</span>';
            const expires = inv.expires_at ? new Date(inv.expires_at).toLocaleDateString() : 'Never';
            return `<tr>
              <td style="font-family:monospace;letter-spacing:0.08em;font-weight:600;">${esc(inv.code)}</td>
              <td>${statusChip}</td>
              <td>${expires}</td>
              <td style="white-space:nowrap;">${!inv.used ? `
                <button class="btn btn-ghost btn-sm" onclick="Admin.copyInviteCode('${esc(inv.code)}')">Copy</button>
                <button class="btn btn-ghost btn-sm" onclick="Admin.copyInviteMessage('${esc(inv.code)}','${esc(team.name)}')" title="Copy onboarding message">Copy Msg</button>
                <button class="btn btn-ghost btn-sm" style="color:var(--fail)" onclick="Admin.revokeInvite(${inv.id})">Revoke</button>
              ` : '—'}</td>
            </tr>`;
          }).join('')}</tbody>
        </table></div>`;
      }
    } catch(e) {
      const el = $$('team-invites-detail');
      if (el) el.innerHTML = `<div style="color:var(--fail);font-size:var(--text-sm);">${esc(e.message)}</div>`;
    }
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
    App._alSubmitFn = async () => { await Admin.submitAddUser(); if(!$$('add-learner-overlay').classList.contains('hidden')) return; Admin.renderTeams(); };
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
      Admin.selectTeam(Admin._selectedTeamId);
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
  _selectedUsers: new Set(),

  updateBulkBar() {
    const sel = Admin._selectedUsers;
    const bar = $$('bulk-bar');
    const cb  = $$('select-all-cb');
    if (!bar) return;
    if (sel.size === 0) {
      bar.classList.add('hidden');
      if (cb) cb.checked = false;
      return;
    }
    bar.classList.remove('hidden');
    const countEl = $$('bulk-count');
    if (countEl) countEl.textContent = `${sel.size} selected`;
    // Sync select-all checkbox state
    const visibleIds = Array.from($$('learners-tbody')?.querySelectorAll('input[type=checkbox]') || []).map(c => c.dataset.id);
    if (cb) cb.checked = visibleIds.length > 0 && visibleIds.every(id => sel.has(id));
  },

  toggleSelectAll(checked) {
    const checkboxes = $$('learners-tbody')?.querySelectorAll('input[type=checkbox]') || [];
    checkboxes.forEach(cb => {
      cb.checked = checked;
      if (checked) Admin._selectedUsers.add(cb.dataset.id);
      else Admin._selectedUsers.delete(cb.dataset.id);
    });
    Admin.updateBulkBar();
  },

  toggleUserSelect(id, checked) {
    if (checked) Admin._selectedUsers.add(id);
    else Admin._selectedUsers.delete(id);
    Admin.updateBulkBar();
  },

  clearSelection() {
    Admin._selectedUsers.clear();
    $$('learners-tbody')?.querySelectorAll('input[type=checkbox]').forEach(cb => cb.checked = false);
    Admin.updateBulkBar();
  },

  async bulkDelete() {
    const ids = Array.from(Admin._selectedUsers);
    if (!ids.length) return;
    if (!confirm(`Permanently delete ${ids.length} user(s)? This cannot be undone.`)) return;
    try {
      await api('/api/learners/bulk/delete', { method: 'POST', body: JSON.stringify({ ids }) });
      Toast.ok(`${ids.length} user(s) deleted.`);
      Admin._selectedUsers.clear();
      Admin.renderLearners(Admin._learnersPage);
    } catch(e) { Toast.err(e.message); }
  },

  async bulkChangeTeam(teamId) {
    const ids = Array.from(Admin._selectedUsers);
    if (!ids.length || !teamId) return;
    const payload = { ids, team_id: teamId === '__unassign__' ? null : teamId };
    try {
      await api('/api/learners/bulk', { method: 'PATCH', body: JSON.stringify(payload) });
      const label = teamId === '__unassign__' ? 'Unassigned' : (teamsCache.find(t => String(t.id) === teamId)?.name || teamId);
      Toast.ok(`${ids.length} user(s) moved to ${label}.`);
      Admin._selectedUsers.clear();
      Admin.renderLearners(Admin._learnersPage);
    } catch(e) { Toast.err(e.message); }
    $$('bulk-team').value = '';
  },

  async bulkChangeRole(role) {
    const ids = Array.from(Admin._selectedUsers);
    if (!ids.length || !role) return;
    try {
      await api('/api/learners/bulk', { method: 'PATCH', body: JSON.stringify({ ids, role }) });
      Toast.ok(`${ids.length} user(s) updated to ${role === 'manager' ? 'Manager' : 'User'}.`);
      Admin._selectedUsers.clear();
      Admin.renderLearners(Admin._learnersPage);
    } catch(e) { Toast.err(e.message); }
    $$('bulk-role').value = '';
  },

  async renderLearners(page = 1) {
    const seq = Admin._navSeq;
    Admin._learnersPage = page;
    Admin._selectedUsers.clear();
    Admin.updateBulkBar();
    const tbody = $$('learners-tbody'); if(!tbody) return;
    try {
      const tid = $$('l-team-filter').value;
      const role = $$('l-role-filter')?.value || '';
      const params = new URLSearchParams();
      if (tid) params.set('team_id', tid === 'unassigned' ? 'null' : tid);
      if (role) params.set('role', role);
      params.set('page', page);
      let path = `/api/learners?${params.toString()}`;
      const [apiRes, teams] = await Promise.all([api(path), api('/api/admin/teams')]);
      if (Admin._navSeq !== seq) return;

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
      // Populate bulk-team dropdown with current teams
      const bulkTeamSel = $$('bulk-team');
      if (bulkTeamSel) {
        bulkTeamSel.innerHTML = '<option value="">Move to team…</option><option value="__unassign__">Unassign</option>' +
          teamsCache.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
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
        <span style="font-size:var(--text-sm);color:var(--ink-3);">${totalCount} users · Page ${page} of ${totalPages}</span>
        <button class="btn btn-outline btn-sm" ${page <= 1 ? 'disabled' : ''} onclick="Admin.renderLearners(${page - 1})">← Prev</button>
        <button class="btn btn-outline btn-sm" ${page >= totalPages ? 'disabled' : ''} onclick="Admin.renderLearners(${page + 1})">Next →</button>`;
    } catch(e) { tbody.innerHTML = `<tr><td colspan="5">${esc(e.message)}</td></tr>`; }
  },
  filterLearners(q) {
    const tbody = $$('learners-tbody'); if(!tbody) return;
    const query = (q || '').toLowerCase().trim();
    const filtered = _allLearners.filter(l => (l.name || '').toLowerCase().includes(query));
    if(!filtered.length) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:32px;">No matches.</td></tr>'; return; }
    tbody.innerHTML = filtered.map(l => {
      const team = (teamsCache||[]).find(t => t.id === l.team_id);
      const teamHtml = team ? esc(team.name) : '<span class="chip chip-amber" style="font-size:9px;">Unassigned</span>';
      const isManager = l.role === 'manager';
      const roleChip = isManager
        ? '<span class="chip chip-blue" style="font-size:9px;">Manager</span>'
        : '<span class="chip chip-green" style="font-size:9px;">User</span>';
      const isChecked = Admin._selectedUsers.has(l.id);
      return `<tr>
        <td style="width:36px;"><input type="checkbox" data-id="${l.id}" ${isChecked ? 'checked' : ''} onchange="Admin.toggleUserSelect('${l.id}', this.checked)"></td>
        <td>${esc(l.name || 'Unnamed')} ${l.overdue_count ? `<span class="chip chip-red" style="font-size:9px;">⚠️ ${l.overdue_count}</span>` : ''}</td>
        <td>${roleChip}</td>
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
  openAddUser() {
    App._editLearnerId = null;
    $$('al-modal-title').textContent = 'Add User';
    $$('al-modal-sub').textContent = 'Set credentials for login.';
    $$('al-name').value = ''; $$('al-pw1').value = ''; $$('al-pw2').value = '';
    $$('al-role').value = 'learner';
    const sel = $$('al-team');
    if(sel) sel.innerHTML = '<option value="">Unassigned</option>' + (teamsCache||[]).map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
    $$('al-pw-section').classList.remove('hidden');
    $$('al-submit-btn').textContent = 'Create Account';
    App._alSubmitFn = Admin.submitAddUser;
    $$('add-learner-overlay').classList.remove('hidden');
    setTimeout(() => $$('al-name').focus(), CONFIG.FOCUS_DELAY);
  },
  closeAddUser() { $$('add-learner-overlay').classList.add('hidden'); App._alSubmitFn = null; },
  async submitAddUser() {
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
      Admin.closeAddUser();
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
    if (!App._editLearnerId) return Toast.err('No user selected.');
    const name   = $$('al-name').value.trim();
    const role   = $$('al-role').value;
    const teamId = $$('al-team').value || null;
    if (!name) return Toast.err('Name is required.');
    try {
      await api(`/api/learners/${App._editLearnerId}`, { method:'PATCH', body:JSON.stringify({ name, role, team_id: teamId }) });
      Admin.closeAddUser();
      Toast.ok('User updated.');
      Admin.renderLearners();
    } catch(e) { Toast.err(e.message); }
  },
  openDeleteLearner(id, name, role) {
    const label = role === 'manager' ? 'Manager' : 'User';
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
  async renderComps() {
    const seq = Admin._navSeq;
    const tbody = $$('comp-tbody'); if(!tbody) return;
    try {
      const cid  = $$('comp-filter')?.value || '';
      const from = $$('comp-from')?.value || '';
      const to   = $$('comp-to')?.value || '';
      const params = new URLSearchParams();
      if (cid)  params.set('course_id', cid);
      if (from) params.set('from', from);
      if (to)   params.set('to', to);
      const res = await api(`/api/admin/completions?${params.toString()}`);
      if (Admin._navSeq !== seq) return;

      // Populate course filter on first load
      const filterEl = $$('comp-filter');
      if (filterEl && filterEl.options.length <= 1) {
        const courses = await api('/api/courses').catch(() => []);
        courses.forEach(c => {
          const o = document.createElement('option'); o.value = c.id; o.textContent = c.title; filterEl.appendChild(o);
        });
        if (cid) filterEl.value = cid;
      }

      if (!res || !res.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--ink-4);padding:32px;">No completions match these filters.</td></tr>';
        $$('comp-pass-rate').textContent = '';
        return;
      }

      const passed = res.filter(r => r.passed).length;
      const rate = Math.round((passed / res.length) * 100);
      $$('comp-pass-rate').textContent = `${rate}% pass rate · ${res.length} records`;

      tbody.innerHTML = res.map(r => `<tr>
        <td>${esc(r.user_name)}</td>
        <td>${esc(r.course_title)}</td>
        <td>${r.score}%</td>
        <td>${r.passed ? '<span class="chip chip-brand-accent">Passed</span>' : '<span class="chip chip-red">Failed</span>'}</td>
        <td>${new Date(r.completed_at * 1000).toLocaleDateString()}</td>
        <td style="font-family:monospace;font-size:11px;">${r.cert_id || '—'}</td>
      </tr>`).join('');
    } catch(e) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--fail);">${esc(e.message)}</td></tr>`; }
  },

  clearCompFilters() {
    const f = $$('comp-filter'); if (f) f.value = '';
    const fr = $$('comp-from'); if (fr) fr.value = '';
    const to = $$('comp-to'); if (to) to.value = '';
    Admin.renderComps();
  },

  async renderCourses() {
    const seq = Admin._navSeq;
    const grid = $$('a-courses-grid'); if(!grid) return;
    grid.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;grid-column:1/-1"><div class="spinner"></div></div>';
    try {
      const [courses, sections, assignments] = await Promise.all([
        api('/api/courses'),
        api('/api/sections').catch(() => []),
        api('/api/assignments').catch(() => [])
      ]);
      if (Admin._navSeq !== seq) return;
      sectionsCache = sections || [];
      Admin._renderSectionsBar(sections);

      // Count enrolled learners per course
      const enrolled = {};
      (assignments || []).forEach(a => { enrolled[a.course_id] = (enrolled[a.course_id] || 0) + 1; });

      if (!courses.length) {
        grid.innerHTML = '<div class="empty" style="grid-column:1/-1;"><div class="empty-icon">📚</div><div class="empty-title">No courses yet</div><div class="empty-hint">Create your first course with the AI Importer or build one from scratch.</div><div class="empty-action"><button class="btn btn-primary btn-sm" onclick="App.aNav(\'importer\')">+ New Course</button></div></div>';
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
          html += bySec[s.id].map(c => Admin._courseCard(c, sections, enrolled)).join('');
        }
      });
      if(unsec.length) {
        if(sections.length) html += `<div style="grid-column:1/-1;margin-top:var(--space-6);padding-bottom:var(--space-2);border-bottom:2px solid var(--rule);"><div style="font-weight:700;font-size:var(--text-lg);color:var(--ink-3);">Unsectioned</div></div>`;
        html += unsec.map(c => Admin._courseCard(c, sections, enrolled)).join('');
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

  _courseCard(c, sections, enrolled = {}) {
    const secOpts = sections.map(s => `<option value="${s.id}" ${c.section_id===s.id?'selected':''}>${esc(s.name)}</option>`).join('');
    const count = enrolled[c.id] || 0;
    const enrollBadge = count > 0
      ? `<span class="chip chip-green" style="font-size:9px;">${count} enrolled</span>`
      : `<span class="chip" style="font-size:9px;color:var(--ink-4);">No learners</span>`;
    return `<div class="card">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:4px;">
        <div style="font-weight:700;line-height:1.3;">${esc(c.title)}</div>
        ${enrollBadge}
      </div>
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
    if (!App._resetPwId) return Toast.err('No user selected.');
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
      const from = !isTeam ? ($$('comp-from')?.value || '') : '';
      const to   = !isTeam ? ($$('comp-to')?.value || '') : '';
      const params = new URLSearchParams();
      if (filterId) params.set('course_id', filterId);
      if (from) params.set('from', from);
      if (to)   params.set('to', to);
      const url = `/api/admin/completions?${params.toString()}`;
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

  // AI Importer methods live in js/importer.js (const Importer)
  // Legacy shims so existing HTML onclick="Admin.saveAiKeys()" etc. keep working
  saveAiKeys() { Importer.saveAiKeys(); },
  requestAiEdit() { Importer.requestAiEdit(); },
  toggleAiEdit(s) { Importer.toggleAiEdit(s); },
  autofillCourseDetails() { Importer.autofillCourseDetails(); },

};
