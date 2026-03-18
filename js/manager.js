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
      const [apiCourses, sections] = await Promise.all([managerApi('/api/courses'), api('/api/sections').catch(() => [])]);
      const courseCard = c => {
        const nc = normCourse(c);
        return `<div class="card">
          <div style="font-weight:700;">${esc(nc.title)}</div>
          <button class="btn btn-primary btn-sm w-full" style="margin-top:12px;" onclick="Manager.openTeamAssign('${nc.id}', '${esc(nc.title)}')">Assign to Team</button>
        </div>`;
      };
      let html = '';
      if(sections.length) {
        const bySec = {}, unsec = [];
        sections.forEach(s => { bySec[s.id] = []; });
        apiCourses.forEach(c => { if(c.section_id && bySec[c.section_id]) bySec[c.section_id].push(c); else unsec.push(c); });
        sections.forEach(s => {
          if(!bySec[s.id].length) return;
          html += `<div class="section-header" style="grid-column:1/-1;">${esc(s.name)}</div>` + bySec[s.id].map(courseCard).join('');
        });
        if(unsec.length) html += `<div class="section-header" style="grid-column:1/-1;">Other</div>` + unsec.map(courseCard).join('');
      } else {
        html = apiCourses.map(courseCard).join('');
      }
      $$('m-courses-grid').innerHTML = html;
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

  // ─── CSV IMPORT ───
  _csvRows: null,

  openCsvImport() {
    Manager._csvRows = null;
    $$('lcsv-preview').classList.add('hidden');
    $$('lcsv-preview').innerHTML = '';
    $$('lcsv-import-btn').disabled = true;
    $$('lcsv-import-btn').textContent = 'Import Learners';
    $$('lcsv-sub').textContent = 'Upload a CSV file to add multiple learners at once.';
    $$('lcsv-file-input').value = '';
    $$('learner-csv-overlay').classList.remove('hidden');
  },

  closeCsvImport() {
    $$('learner-csv-overlay').classList.add('hidden');
  },

  downloadLearnerTemplate() {
    const csv = 'name,password\nJane Smith,welcome123\nJohn Doe,securepass';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'trainflow-learners-template.csv';
    a.click();
  },

  lCsvDrop(e) {
    e.preventDefault();
    $$('lcsv-drop-zone').classList.remove('drag-active');
    const f = e.dataTransfer.files[0];
    if(f) Manager._handleCsvFile(f);
  },

  lCsvSelected(e) {
    const f = e.target.files[0];
    if(f) Manager._handleCsvFile(f);
    e.target.value = '';
  },

  _parseCsv(text) {
    const lines = text.trim().split('\n').filter(l => l.trim());
    if(lines.length < 2) return [];
    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, '').toLowerCase());
    return lines.slice(1).map(line => {
      const vals = [];
      let cur = '', inQ = false;
      for(const ch of line + ',') {
        if(ch === '"') { inQ = !inQ; }
        else if(ch === ',' && !inQ) { vals.push(cur.trim().replace(/^"|"$/g, '')); cur = ''; }
        else { cur += ch; }
      }
      return Object.fromEntries(headers.map((h, i) => [h, (vals[i] || '').trim()]));
    }).filter(r => r.name || r.password);
  },

  _handleCsvFile(file) {
    const reader = new FileReader();
    reader.onload = ev => {
      const rows = Manager._parseCsv(ev.target.result);
      if(!rows.length) { Toast.err('No data rows found. Check the file format.'); return; }
      Manager._csvRows = rows;

      // Validate and build preview
      const valid = [], invalid = [];
      rows.forEach(r => {
        if(!r.name) invalid.push({ ...r, _err: 'Missing name' });
        else if(!r.password || r.password.length < 8) invalid.push({ ...r, _err: 'Password missing or < 8 chars' });
        else valid.push(r);
      });

      const previewEl = $$('lcsv-preview');
      previewEl.classList.remove('hidden');
      previewEl.innerHTML = `
        <div style="margin-bottom:var(--space-3);font-size:var(--text-sm);">
          <span class="chip chip-green">${valid.length} valid</span>
          ${invalid.length ? `<span class="chip chip-red" style="margin-left:4px;">${invalid.length} error${invalid.length > 1 ? 's' : ''}</span>` : ''}
        </div>
        <div class="table-wrap" style="max-height:260px;overflow-y:auto;">
          <table>
            <thead><tr><th>Name</th><th>Password</th><th>Status</th></tr></thead>
            <tbody>
              ${rows.map(r => {
                const err = !r.name ? 'Missing name' : (!r.password || r.password.length < 8) ? 'Password < 8 chars' : null;
                return `<tr>
                  <td>${esc(r.name || '—')}</td>
                  <td style="color:var(--ink-4);">${r.password ? '••••••••' : '—'}</td>
                  <td>${err ? `<span class="chip chip-red" style="font-size:9px;">${esc(err)}</span>` : '<span class="chip chip-green" style="font-size:9px;">✓ OK</span>'}</td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>`;

      $$('lcsv-import-btn').disabled = valid.length === 0;
      $$('lcsv-import-btn').textContent = valid.length ? `Import ${valid.length} Learner${valid.length > 1 ? 's' : ''}` : 'Import Learners';
      $$('lcsv-sub').textContent = `${rows.length} row${rows.length > 1 ? 's' : ''} parsed from "${file.name}"`;
    };
    reader.readAsText(file);
  },

  async submitCsvImport() {
    const validRows = (Manager._csvRows || []).filter(r => r.name && r.password && r.password.length >= 8);
    if(!validRows.length) return;
    const btn = $$('lcsv-import-btn');
    btn.disabled = true; btn.textContent = 'Importing…';
    try {
      const res = await managerApi('/api/learners/bulk', {
        method: 'POST',
        body: JSON.stringify({ learners: validRows, team_id: curManager.team_id })
      });
      Manager.closeCsvImport();
      Toast.ok(`${res.created} learner${res.created !== 1 ? 's' : ''} imported${res.errors.length ? `, ${res.errors.length} skipped` : ''}.`);
      Manager.renderTeam();
    } catch(e) {
      Toast.err(e.message);
      btn.disabled = false;
      btn.textContent = `Import ${validRows.length} Learners`;
    }
  },

  // ─── COMPLETIONS ───
  async renderComps() {
    const res = await managerApi('/api/admin/completions');
    $$('m-comp-tbody').innerHTML = res.map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td></tr>`).join('');
  }
};
