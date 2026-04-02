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
    if(p==='account' && curManager) { const n = $$('mcp-name'); if(n) n.value = curManager.name || ''; }
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
    const tbody = $$('m-team-tbody'); if (!tbody) return;
    try {
      const learners = await managerApi(`/api/learners?team_id=${curManager.team_id}`);
      const rows = Array.isArray(learners) ? learners : (learners.rows || []);
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--ink-4);">No learners yet. Use "+ Add Learner" to get started.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(l => `<tr>
        <td>${esc(l.name)} ${l.overdue_count ? `<span class="chip chip-red" style="font-size:9px;">⚠️ ${l.overdue_count} overdue</span>` : ''}</td>
        <td>${l.assignment_count || 0}</td>
        <td>${l.completion_count || 0}</td>
        <td>${l.pass_rate != null ? l.pass_rate + '%' : '—'}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="Manager.openResetPw('${l.id}','${esc(l.name)}')">Reset PW</button></td>
      </tr>`).join('');
    } catch(e) { tbody.innerHTML = `<tr><td colspan="5" style="color:var(--fail);padding:16px;">${esc(e.message)}</td></tr>`; }
  },

  // ─── RESET PASSWORD ───
  openResetPw(id, name) {
    $$('reset-pw-subtitle').textContent = name;
    App._resetPwId = id;
    $$('rp-pw1').value = '';
    $$('rp-pw2').value = '';
    $$('reset-pw-overlay').classList.remove('hidden');
  },
  async submitResetPw() {
    const pw = $$('rp-pw1').value;
    if (!pw || pw.length < 8) return Toast.err('Password must be at least 8 characters.');
    const btn = $$('reset-pw-overlay')?.querySelector('.btn-primary');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      await managerApi(`/api/learners/${App._resetPwId}/password`, { method:'PUT', body:JSON.stringify({ password:pw }) });
      Admin.closeResetPw();
      Toast.ok('Password reset.');
    } catch(e) { Toast.err(e.message); }
    finally { if (btn) { btn.disabled = false; btn.textContent = orig; } }
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
      }).join('') + `<button class="btn btn-primary w-full" id="team-assign-btn" style="margin-top:12px;" onclick="Manager.submitTeamAssign()">Assign Now</button>`;
    } catch(e) { }
  },
  async submitTeamAssign() {
    const btn = $$('team-assign-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Assigning…'; }
    try {
      const due_at = $$('team-due-date').value || null;
      const checks = $$('assign-list').querySelectorAll('input[type=checkbox]:not(:disabled):checked');
      for(const chk of checks) {
        const lid = chk.id.replace('chk-','');
        await managerApi('/api/assignments', { method:'POST', body:JSON.stringify({ course_id:App._assignCourseId, learner_id:lid, due_at }) });
      }
      Toast.ok('Team assigned.');
      $$('assign-overlay').classList.add('hidden');
    } catch(e) { Toast.err(e.message); }
    finally { if (btn) { btn.disabled = false; btn.textContent = orig; } }
  },

  // ─── CSV IMPORT ───
  _csvRows: null,

  _csvRows: null,
  _credsRows: null,   // [{name, password}] for the credentials sheet
  _importedIds: null, // [{id, name}] returned from the API after bulk import

  _generatePassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const arr = new Uint8Array(10);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(n => chars[n % chars.length]).join('');
  },

  openCsvImport() {
    Manager._csvRows = null;
    Manager._credsRows = null;
    Manager._importedIds = null;
    $$('lcsv-preview').classList.add('hidden');
    $$('lcsv-preview').innerHTML = '';
    $$('lcsv-import-btn').disabled = true;
    $$('lcsv-import-btn').textContent = 'Import Learners';
    $$('lcsv-sub').textContent = 'Upload a CSV file to add multiple learners at once.';
    $$('lcsv-file-input').value = '';
    const cb = $$('lcsv-autogen');
    if (cb) { cb.checked = false; Manager.lCsvToggleAutogen(); }
    $$('learner-csv-overlay').classList.remove('hidden');
  },

  closeCsvImport() {
    $$('learner-csv-overlay').classList.add('hidden');
  },

  lCsvToggleAutogen() {
    const on = $$('lcsv-autogen')?.checked;
    const track = $$('lcsv-autogen-track');
    const thumb = $$('lcsv-autogen-thumb');
    if (track) track.style.background = on ? 'var(--brand)' : 'var(--border-2)';
    if (thumb) thumb.style.transform = on ? 'translateX(20px)' : 'translateX(0)';
    const hint = $$('lcsv-col-hint');
    if (hint) hint.innerHTML = on ? 'Column needed: <code>name</code> only' : 'Columns: <code>name, password</code>';
    // Re-parse if a file is already loaded
    if (Manager._csvRows !== null) {
      const fi = $$('lcsv-file-input');
      if (fi && fi.files[0]) Manager._handleCsvFile(fi.files[0]);
    }
  },

  downloadLearnerTemplate() {
    const autogen = $$('lcsv-autogen')?.checked;
    const csv = autogen
      ? 'name\nJane Smith\nJohn Doe\nAlex Johnson'
      : 'name,password\nJane Smith,welcome123\nJohn Doe,securepass';
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
      const autogen = $$('lcsv-autogen')?.checked;
      const parsed = Manager._parseCsv(ev.target.result);
      if (!parsed.length) { Toast.err('No data rows found. Check the file format.'); return; }

      // In auto-gen mode generate passwords now so the preview is accurate
      const rows = parsed.map(r => ({
        ...r,
        password: autogen ? Manager._generatePassword() : (r.password || '')
      }));
      Manager._csvRows = rows;

      const valid = [], invalid = [];
      rows.forEach(r => {
        if (!r.name) invalid.push({ ...r, _err: 'Missing name' });
        else if (!r.password || r.password.length < 8) invalid.push({ ...r, _err: 'Password too short' });
        else valid.push(r);
      });

      const previewEl = $$('lcsv-preview');
      previewEl.classList.remove('hidden');
      previewEl.innerHTML = `
        <div style="margin-bottom:var(--space-3);font-size:var(--text-sm);">
          <span class="chip chip-green">${valid.length} ready</span>
          ${invalid.length ? `<span class="chip chip-red" style="margin-left:4px;">${invalid.length} error${invalid.length > 1 ? 's' : ''}</span>` : ''}
        </div>
        <div class="table-wrap" style="max-height:240px;overflow-y:auto;">
          <table>
            <thead><tr><th>Name</th><th>Password</th><th>Status</th></tr></thead>
            <tbody>
              ${rows.map(r => {
                const err = !r.name ? 'Missing name' : (!r.password || r.password.length < 8) ? 'Password < 8 chars' : null;
                return `<tr>
                  <td>${esc(r.name || '—')}</td>
                  <td style="font-family:monospace;font-size:12px;color:${autogen ? 'var(--brand)' : 'var(--ink-4)'};">${r.password || '—'}</td>
                  <td>${err ? `<span class="chip chip-red" style="font-size:9px;">${esc(err)}</span>` : '<span class="chip chip-green" style="font-size:9px;">✓ OK</span>'}</td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
        ${autogen ? `<div style="font-size:var(--text-xs);color:var(--ink-4);margin-top:var(--space-3);">⚠ Save or print the credentials sheet shown after import — passwords cannot be recovered later.</div>` : ''}`;

      $$('lcsv-import-btn').disabled = valid.length === 0;
      $$('lcsv-import-btn').textContent = valid.length ? `Import ${valid.length} Learner${valid.length > 1 ? 's' : ''}` : 'Import Learners';
      $$('lcsv-sub').textContent = `${rows.length} row${rows.length > 1 ? 's' : ''} parsed from "${file.name}"`;
    };
    reader.readAsText(file);
  },

  async submitCsvImport() {
    const autogen = $$('lcsv-autogen')?.checked;
    const validRows = (Manager._csvRows || []).filter(r => r.name && r.password && r.password.length >= 8);
    if (!validRows.length) return;
    const btn = $$('lcsv-import-btn');
    btn.disabled = true; btn.textContent = 'Importing…';
    try {
      const res = await managerApi('/api/learners/bulk', {
        method: 'POST',
        body: JSON.stringify({ learners: validRows, team_id: curManager.team_id })
      });
      Manager.closeCsvImport();
      Manager.renderTeam();
      Manager._importedIds = res.created_learners || [];

      if (autogen && res.created_learners && res.created_learners.length) {
        // Map IDs back to the plaintext passwords used
        const idMap = Object.fromEntries(res.created_learners.map(l => [l.name, l]));
        Manager._credsRows = validRows
          .filter(r => idMap[r.name])
          .map(r => ({ id: idMap[r.name].id, name: r.name, password: r.password }));
        Manager.showCredentialsSheet(res.created, res.errors.length);
      } else {
        Toast.ok(`${res.created} learner${res.created !== 1 ? 's' : ''} imported${res.errors.length ? `, ${res.errors.length} skipped` : ''}.`);
        if (Manager._importedIds.length) Manager.proceedToAssign();
      }
    } catch(e) {
      Toast.err(e.message);
      btn.disabled = false;
      btn.textContent = `Import ${validRows.length} Learners`;
    }
  },

  showCredentialsSheet(createdCount, skippedCount) {
    const rows = Manager._credsRows || [];
    $$('creds-sub').textContent = `${createdCount} learner${createdCount !== 1 ? 's' : ''} imported${skippedCount ? `, ${skippedCount} skipped` : ''}. Share these temporary passwords — learners can update them in Account settings.`;
    $$('creds-tbody').innerHTML = rows.map((r, i) => `<tr>
      <td style="color:var(--ink-4);">${i + 1}</td>
      <td style="font-weight:600;">${esc(r.name)}</td>
      <td style="font-family:monospace;font-size:13px;letter-spacing:0.04em;">${esc(r.password)}</td>
    </tr>`).join('');
    $$('creds-overlay').classList.remove('hidden');
  },

  downloadCredsCSV() {
    const rows = Manager._credsRows || [];
    if (!rows.length) return;
    const orgName = brandCache.name || 'TrainFlow';
    const csv = [
      [`${orgName} — Team Credentials`, '', ''],
      ['Generated', new Date().toLocaleDateString(), ''],
      ['', '', ''],
      ['#', 'Name', 'Temporary Password'],
      ...rows.map((r, i) => [i + 1, r.name, r.password])
    ].map(row => row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `team-credentials-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  },

  async proceedToAssign() {
    $$('creds-overlay').classList.add('hidden');
    const ids = Manager._importedIds || [];
    if (!ids.length) return;
    const overlay = $$('post-import-assign-overlay');
    if (!overlay) return;
    $$('pia-sub').textContent = `Assign mandatory training to the ${ids.length} learner${ids.length !== 1 ? 's' : ''} you just imported.`;
    $$('pia-due').value = '';
    // Populate course dropdown
    const sel = $$('pia-course');
    sel.innerHTML = '<option value="">Loading…</option>';
    try {
      const courses = await managerApi('/api/courses');
      sel.innerHTML = courses.length
        ? courses.map(c => `<option value="${c.id}">${esc(c.title)}</option>`).join('')
        : '<option value="">No courses available</option>';
    } catch { sel.innerHTML = '<option value="">Could not load courses</option>'; }
    overlay.classList.remove('hidden');
  },

  skipPostImportAssign() {
    $$('creds-overlay')?.classList.add('hidden');
    $$('post-import-assign-overlay')?.classList.add('hidden');
    const count = (Manager._importedIds || []).length;
    if (count) Toast.ok(`${count} learner${count !== 1 ? 's' : ''} imported successfully.`);
    Manager._importedIds = null;
    Manager._credsRows = null;
  },

  async submitPostImportAssign() {
    const courseId = $$('pia-course')?.value;
    if (!courseId) return Toast.err('Please select a course.');
    const dueRaw = $$('pia-due')?.value;
    const dueAt = dueRaw ? Math.floor(new Date(dueRaw).getTime() / 1000) : null;
    const ids = Manager._importedIds || [];
    if (!ids.length) return;
    const btn = $$('pia-submit-btn');
    const orig = btn.textContent;
    btn.disabled = true; btn.textContent = 'Assigning…';
    try {
      await Promise.all(ids.map(l =>
        managerApi('/api/assignments', {
          method: 'POST',
          body: JSON.stringify({ course_id: courseId, learner_id: l.id, due_at: dueAt })
        }).catch(() => null) // skip already-assigned
      ));
      $$('post-import-assign-overlay').classList.add('hidden');
      Toast.ok(`Course assigned to ${ids.length} learner${ids.length !== 1 ? 's' : ''}.`);
      Manager._importedIds = null;
      Manager._credsRows = null;
    } catch(e) {
      Toast.err(e.message);
    } finally {
      btn.disabled = false; btn.textContent = orig;
    }
  },

  // ─── COMPLETIONS ───
  async renderComps() {
    const res = await managerApi('/api/admin/completions');
    $$('m-comp-tbody').innerHTML = res.map(r => `<tr><td>${esc(r.user_name)}</td><td>${esc(r.course_title)}</td><td>${r.score}%</td><td>${r.passed?'Passed':'Failed'}</td><td>${new Date(r.completed_at*1000).toLocaleDateString()}</td></tr>`).join('');
  }
};
