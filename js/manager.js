// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Manager Dashboard & Scoping
// ══════════════════════════════════════════════════════════

const Manager = {
  init() {
    App.show('screen-manager');
    $$('m-team-badge').textContent = curManager.team_name || 'My Team';
    Manager.nav('dashboard');
  },

  nav(p) {
    ['dashboard','courses','team','completions','account'].forEach(k => {
      if($$(`mn-${k}`)) $$(`mn-${k}`).classList.toggle('active', k===p);
      const mp = $$(`mp-${k}`);
      if(mp) { mp.classList.toggle('hidden', k!==p); mp.classList.toggle('active', k===p); }
    });
    if(p==='dashboard') Manager.renderDash();
    if(p==='courses')   Manager.renderCourses();
    if(p==='team')      Manager.renderTeam();
    if(p==='completions') Manager.renderComps();
  },

  // ─── DASHBOARD ───
  async renderDash() {
    const statsEl = $$('m-stats'); if(!statsEl) return;
    statsEl.innerHTML = '<div style="display:flex;justify-content:center;padding:40px;width:100%;"><div class="spinner"></div></div>';
    try {
      const [learners, comps] = await Promise.all([
        managerApi(`/api/learners?team_id=${curManager.team_id}`),
        managerApi('/api/admin/completions')
      ]);
      const overdue = learners.reduce((s,l) => s + (l.overdue_count || 0), 0);
      const passed = comps.filter(c => c.passed).length;
      const rate = comps.length ? Math.round(passed/comps.length*100) : 0;

      statsEl.innerHTML = [['Members', learners.length, '👥'],['Month', comps.length, '🏆'],['Pass Rate', rate + '%', '📈'],['Overdue', overdue, '⚠️']].map(([l,v,i])=>`<div class="stat-tile">
        <div style="font-size:24px;">${i}</div>
        <div class="stat-value">${v}</div>
        <div class="stat-label">${l}</div>
      </div>`).join('');

      if (!comps.length) {
        $$('m-recent').innerHTML = '<div class="card" style="color:var(--ink-4);text-align:center;">No team activity recorded yet.</div>';
      } else {
        $$('m-recent').innerHTML = `<h3>Recent Team Activity</h3><div class="table-wrap"><table><thead><tr><th>Learner</th><th>Course</th><th>Score</th><th>Date</th></tr></thead><tbody>${comps.slice(0,5).map(r=>`<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td></tr>`).join('')}</tbody></table></div>`;
      }
    } catch(e) { 
      statsEl.innerHTML = `<div class="card" style="color:var(--fail);width:100%;">${esc(e.message)}</div>`;
    }
  },

  // ─── COURSES ───
  async renderCourses() {
    try {
      const apiCourses = await managerApi('/api/courses');
      $$('m-courses-grid').innerHTML = apiCourses.map(normCourse).map(c => `<div class="card">
        <div style="font-weight:700;">${esc(c.title)}</div>
        <button class="btn btn-primary btn-sm w-full" style="margin-top:12px;" onclick="Manager.openTeamAssign('${c.id}', '${esc(c.title)}')">Assign to Team</button>
      </div>`).join('');
    } catch(e) { }
  },

  // ─── TEAM ───
  async renderTeam() {
    try {
      const learners = await managerApi(`/api/learners?team_id=${curManager.team_id}`);
      $$('m-team-tbody').innerHTML = learners.map(l => `<tr>
        <td>${esc(l.name)} ${l.overdue_count?`<span class="chip chip-red">⚠️ ${l.overdue_count} overdue</span>`:''}</td>
        <td>${l.completion_count}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="Admin.openResetPw('${l.id}','${esc(l.name)}')">Reset PW</button></td>
      </tr>`).join('');
    } catch(e) { }
  },

  // ─── TEAM ASSIGN ───
  async openTeamAssign(cid, title) {
    App._assignCourseId = cid;
    $$('assign-subtitle').textContent = `Assign ${title} to your team`;
    $$('assign-overlay').classList.remove('hidden');
    $$('assign-list').innerHTML = 'Loading team...';
    try {
      const [learners, assigns] = await Promise.all([
        managerApi(`/api/learners?team_id=${curManager.team_id}`),
        managerApi('/api/assignments')
      ]);
      const cidAssigns = assigns.filter(a => a.course_id === cid).map(a => a.learner_id);
      $$('assign-list').innerHTML = `<div class="field"><label>Due Date (Optional)</label><input type="date" id="team-due-date"></div>` + learners.map(l => {
        const exists = cidAssigns.includes(l.id);
        return `<div style="display:flex;align-items:center;gap:12px;padding:8px 0;">
          <input type="checkbox" id="chk-${l.id}" ${exists?'disabled checked':'checked'}>
          <label style="margin:0;">${esc(l.name)} ${exists?'(Already assigned)':''}</label>
        </div>`;
      }).join('') + `<button class="btn btn-primary w-full" style="margin-top:12px;" onclick="Manager.submitTeamAssign()">Assign Now</button>`;
    } catch(e) { }
  },
  async submitTeamAssign() {
    const due_at = $$('team-due-date').value || null;
    const checks = $$('assign-list').querySelectorAll('input[type=checkbox]:not(:disabled):checked');
    for(const chk of checks) {
      const lid = chk.id.replace('chk-','');
      await managerApi('/api/assignments', { method:'POST', body:JSON.stringify({ course_id:App._assignCourseId, learner_id:lid, due_at }) });
    }
    Toast.ok('Team assigned.');
    $$('assign-overlay').classList.add('hidden');
  },

  // ─── COMPLETIONS ───
  async renderComps() {
    const res = await managerApi('/api/admin/completions');
    $$('m-comp-tbody').innerHTML = res.map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td></tr>`).join('');
  }
};
