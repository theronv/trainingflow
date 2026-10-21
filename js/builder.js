// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Content Builder & AI Importer
// ══════════════════════════════════════════════════════════

const Builder = {
  // ─── COURSE BUILDER ───
  // The icon is stored as an emoji; the picker shows the line icon each emoji maps to.
  setIcon(emoji) {
    $$('cb-icon').value = emoji;
    const selected = courseIconName(emoji);
    $$('cb-icon-grid').innerHTML = COURSE_ICON_GROUPS.map((g) => `<div class="icon-group-label" aria-hidden="true">${g.label}</div>` +
      COURSE_ICON_CHOICES.filter((i) => i.group === g.label).map(({ name, emoji: e }) =>
        `<button type="button" class="icon-choice" role="radio" aria-checked="${name === selected}" aria-label="${name}" title="${name}" onclick="Builder.pickIcon('${e}')">${courseIcon(e)}</button>`).join('')).join('');
  },
  pickIcon(emoji) {
    Builder.setIcon(emoji);
    Builder._dirty = true;
  },
  openBuilder(editId = null) {
    cbState = { editId, mods: [] };
    $$('cb-title').value = '';
    Builder.setIcon(COURSE_ICON_CHOICES.find(i => i.name === 'cap').emoji);
    $$('cb-desc').value = '';
    $$('cb-ref-url').value = '';
    $$('mods-builder').innerHTML = '';
    $$('builder-title').textContent = editId ? 'Edit Course' : 'New Course';
    $$('builder-overlay').classList.remove('hidden');
    Builder._dirty = false;
    if (!Builder._dirtyArmed) {
      Builder._dirtyArmed = true;
      $$('builder-overlay').addEventListener('input', () => { Builder._dirty = true; });
    }
    if(editId) {
      api(`/api/courses/${editId}`).then(c => {
        const nc = normCourse(c);
        $$('cb-title').value = nc.title;
        Builder.setIcon(nc.icon);
        $$('cb-desc').value = nc.desc;
        $$('cb-ref-url').value = nc.refUrl;
        cbState.mods = nc.mods.map(m => ({ id: m.id, title: m.title, content: m.content, summary: m.summary || '', reference_url: m.refUrl || '', learning_objectives: m.objectives || [], questions: m.questions }));
        Builder.renderBuilderMods();
      }).catch(() => {});
    }
  },
  async closeBuilder(force) {
    if (!force && Builder._dirty && !await Confirm.ask({ title: 'Discard changes?', body: 'Your unsaved changes to this course will be lost.', confirmLabel: 'Discard changes', cancelLabel: 'Keep editing', danger: true })) return;
    Builder._dirty = false;
    $$('builder-overlay').classList.add('hidden');
  },
  addMod() {
    const mi = cbState.mods.length;
    cbState.mods.push({ id: uid(), title: '', content: '', summary: '', reference_url: '', learning_objectives: [], questions: [] });
    Builder.renderBuilderMods();
  },
  renderBuilderMods() {
    $$('mods-builder').innerHTML = cbState.mods.map((m, i) => `
      <div class="card" style="margin-bottom:var(--space-4);">
        <div style="display:flex;justify-content:space-between;margin-bottom:var(--space-3);">
          <div style="font-weight:700;">Module ${i+1}</div>
          <button class="btn btn-ghost btn-sm btn-danger-ghost" onclick="Builder.delMod(${i})">Remove</button>
        </div>
        <div class="field"><label>Title</label><input type="text" value="${esc(m.title)}" oninput="cbState.mods[${i}].title=this.value" placeholder="e.g. Introduction"></div>
        <div class="field"><label>Content (Markdown)</label><textarea style="min-height:120px;" oninput="cbState.mods[${i}].content=this.value" placeholder="Module text here...">${esc(m.content)}</textarea></div>
        <details style="margin-bottom:var(--space-3);">
          <summary style="cursor:pointer;font-size:var(--text-sm);font-weight:600;color:var(--ink-3);padding:var(--space-2) 0;user-select:none;">Module Metadata (summary, source URL, objectives)</summary>
          <div style="padding-top:var(--space-3);border-top:1px solid var(--border);margin-top:var(--space-2);">
            <div class="field">
              <label>Summary <span style="font-weight:400;color:var(--ink-4);">(shown to learners before content)</span></label>
              <textarea style="min-height:60px;" oninput="cbState.mods[${i}].summary=this.value" placeholder="Brief overview of what this module covers...">${esc(m.summary || '')}</textarea>
            </div>
            <div class="field">
              <label>Source URL <span style="font-weight:400;color:var(--ink-4);">(shown as "Read This First" banner)</span></label>
              <input type="url" value="${esc(m.reference_url || '')}" oninput="cbState.mods[${i}].reference_url=this.value" placeholder="https://docs.example.com/page">
            </div>
            <div class="field">
              <label>Learning Objectives <span style="font-weight:400;color:var(--ink-4);">(one per line)</span></label>
              <textarea style="min-height:80px;" oninput="cbState.mods[${i}].learning_objectives=this.value.split('\n').filter(l=>l.trim())" placeholder="Understand how authentication works&#10;Apply token-based access patterns&#10;Identify common API errors">${esc((m.learning_objectives || []).join('\n'))}</textarea>
            </div>
          </div>
        </details>
        <div style="margin-top:var(--space-4);">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-3);">
            <div style="font-weight:600;font-size:var(--text-sm);">Questions (${m.questions.length})</div>
            <button class="btn btn-outline btn-sm" onclick="Builder.addQuestion(${i})">+ Question</button>
          </div>
          ${m.questions.map((q, j) => `
            <div style="border:1px solid var(--rule);border-radius:var(--radius);padding:var(--space-3);margin-bottom:var(--space-3);">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-2);">
                <div style="font-weight:600;font-size:var(--text-sm);color:var(--ink-3);">Q${j+1}</div>
                <button class="btn btn-ghost btn-sm" style="color:var(--fail);" onclick="Builder.delQuestion(${i},${j})">✕ Remove</button>
              </div>
              <div class="field"><label>Question</label><input type="text" value="${esc(q.question||'')}" oninput="cbState.mods[${i}].questions[${j}].question=this.value" placeholder="Question text"></div>
              <label style="font-size:var(--text-sm);font-weight:500;color:var(--ink-2);margin-bottom:var(--space-2);display:block;">Options <span style="font-weight:400;color:var(--ink-4);">(select the correct answer)</span></label>
              ${['A','B','C','D'].map((letter, k) => `
                <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-2);">
                  <input type="radio" name="q-correct-${i}-${j}" value="${k}" ${q.correct_index===k?'checked':''} onchange="cbState.mods[${i}].questions[${j}].correct_index=${k}" title="Mark as correct answer">
                  <span style="font-size:var(--text-sm);font-weight:600;min-width:16px;">${letter}</span>
                  <input type="text" value="${esc((q.options||[])[k]||'')}" oninput="cbState.mods[${i}].questions[${j}].options[${k}]=this.value" placeholder="Option ${letter}" style="flex:1;">
                </div>`).join('')}
              <div class="field" style="margin-top:var(--space-2);margin-bottom:0;"><label>Explanation</label><input type="text" value="${esc(q.explanation||'')}" oninput="cbState.mods[${i}].questions[${j}].explanation=this.value" placeholder="Why this answer is correct (shown after attempt)"></div>
            </div>`).join('')}
        </div>
      </div>`).join('');
  },
  delMod(i) { cbState.mods.splice(i, 1); Builder.renderBuilderMods(); },
  addQuestion(i) {
    cbState.mods[i].questions.push({ id: uid(), question: '', options: ['', '', '', ''], correct_index: 0, explanation: '' });
    Builder.renderBuilderMods();
  },
  delQuestion(i, j) { cbState.mods[i].questions.splice(j, 1); Builder.renderBuilderMods(); },
  async saveCourse(btn) {
    const title = $$('cb-title').value.trim();
    if(!title) return Toast.err('Title required.');
    for (let mi = 0; mi < cbState.mods.length; mi++) {
      const m = cbState.mods[mi];
      for (let qi = 0; qi < m.questions.length; qi++) {
        const q = m.questions[qi];
        const filled = (q.options || []).filter(o => o && o.trim());
        if (!q.question?.trim()) return Toast.err(`Module ${mi+1}, Q${qi+1}: question text is required.`);
        if (filled.length < 2) return Toast.err(`Module ${mi+1}, Q${qi+1}: at least 2 options are required.`);
        if (q.correct_index == null || q.correct_index < 0 || q.correct_index >= (q.options||[]).length || !(q.options[q.correct_index]||'').trim()) {
          return Toast.err(`Module ${mi+1}, Q${qi+1}: correct answer must point to a filled option.`);
        }
      }
    }
    const body = {
      title,
      icon: $$('cb-icon').value || '📋',
      description: $$('cb-desc').value,
      reference_url: $$('cb-ref-url').value.trim() || null,
      modules: cbState.mods
    };
    const origText = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      if(cbState.editId) await api(`/api/courses/${cbState.editId}`, { method: 'PUT', body: JSON.stringify(body) });
      else await api('/api/courses', { method: 'POST', body: JSON.stringify(body) });
      Builder.closeBuilder(true);
      if (curManager) Manager.init(); else Admin.init();
      Toast.ok('Course saved.');
    } catch(e) { Toast.err(e.message); }
    finally { if (btn) { btn.disabled = false; if (origText) btn.textContent = origText; } }
  },

  // ─── ASSIGN COURSES (ADMIN + MANAGER) ───
  // Pick one or more courses (card checkboxes), then whole teams and/or individual learners, an
  // optional due date, one batch submit.
  _sel: new Set(),
  _assign: null,
  _assignApi: () => (curManager ? managerApi : api),

  _selPrefix: () => (curManager ? 'm' : 'a'),
  _selAllIds: () => (curManager ? (Manager._courseIds || []) : (Admin._cv?.courses || []).map(c => c.id)),

  toggleCourseSel(id, on) {
    on ? Builder._sel.add(id) : Builder._sel.delete(id);
    Builder._selBarUpdate();
  },
  selectAllCourses() {
    const all = Builder._selAllIds();
    const everySelected = all.length > 0 && all.every(id => Builder._sel.has(id));
    Builder._sel = new Set(everySelected ? [] : all);
    Builder._selSyncBoxes();
    Builder._selBarUpdate();
  },
  clearCourseSel() { Builder._sel = new Set(); Builder._selSyncBoxes(); Builder._selBarUpdate(); },
  _selSyncBoxes() {
    document.querySelectorAll('#a-courses-grid .cc-check input, #m-courses-grid .cc-check input')
      .forEach(el => { el.checked = Builder._sel.has(el.dataset.id); });
  },
  // Called after the course list is fetched: forget selections for courses that no longer exist.
  selPrune(ids) {
    const live = new Set(ids);
    Builder._sel = new Set([...Builder._sel].filter(id => live.has(id)));
    Builder._selBarUpdate();
  },
  _selBarUpdate() {
    const p = Builder._selPrefix(), n = Builder._sel.size;
    const bar = $$(`${p}-sel-bar`); if (!bar) return;
    bar.classList.toggle('hidden', n === 0);
    $$(`${p}-sel-count`).textContent = `${n} course${n === 1 ? '' : 's'} selected`;
    const all = Builder._selAllIds();
    const btn = $$(`${p}-sel-all`);
    if (btn) btn.textContent = all.length && all.every(id => Builder._sel.has(id)) ? 'Deselect all' : 'Select all';
  },
  courseCheckbox(id, title) {
    return `<label class="cc-check"><input type="checkbox" data-id="${id}" aria-label="Select ${esc(title)}" ${Builder._sel.has(id) ? 'checked' : ''} onchange="Builder.toggleCourseSel('${id}', this.checked)"></label>`;
  },
  openAssignSelected() {
    const ids = [...Builder._sel];
    if (!ids.length) return;
    Builder.openAssign(ids);
  },

  // Learners (or teams) that still lack at least one of the chosen courses.
  _assignPending(st, learnerId) {
    return st.courseIds.filter(cid => !st.assigned[cid].has(learnerId)).length;
  },

  async openAssign(courseIds, title) {
    const ids = [].concat(courseIds);
    App._assignCourseIds = ids;
    $$('assign-subtitle').textContent = ids.length === 1 ? title : `${ids.length} courses`;
    $$('assign-search').value = '';
    $$('assign-due').value = '';
    $$('assign-overlay').classList.remove('hidden');
    $$('assign-list').innerHTML = 'Loading...';
    Builder._assign = { courseIds: ids, teams: new Set(), learners: new Set(), assigned: {}, people: [], managers: [], teams_: [] };
    ids.forEach(cid => { Builder._assign.assigned[cid] = new Set(); });
    Builder._assignUpdateBtn();
    try {
      const call = Builder._assignApi();
      const [people, managers, teams, assigns] = await Promise.all([
        call('/api/learners?role=learner'),
        // Admins can also assign training to managers (individually, never via a team selection).
        curManager ? Promise.resolve([]) : call('/api/learners?role=manager').catch(() => []),
        call('/api/admin/teams').catch(() => []),
        call('/api/assignments')
      ]);
      const st = Builder._assign;
      st.people = (people || []).filter(l => !l.role || l.role === 'learner');
      st.managers = (managers || []).filter(l => l.role === 'manager');
      st.teams_ = (teams || []).filter(t => st.people.some(l => l.team_id === t.id));
      assigns.filter(a => st.assigned[a.course_id]).forEach(a => st.assigned[a.course_id].add(a.learner_id));
      Builder._assignRender();
    } catch(e) { $$('assign-list').innerHTML = `<p style="color:var(--fail);">${esc(e.message)}</p>`; }
  },

  _assignRender() {
    const st = Builder._assign;
    const pending = id => Builder._assignPending(st, id);
    const row = (id, label, meta, checked, disabled, data) => `
      <label data-name="${esc(data)}" style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);cursor:${disabled ? 'default' : 'pointer'};">
        <input type="checkbox" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''} onchange="${id}">
        <span style="flex:1;margin:0;">${label}</span>${meta}
      </label>`;
    const chip = t => `<span class="chip">${t}</span>`;
    let html = '';
    if (st.teams_.length) {
      html += '<div class="modal-sub" style="margin:4px 0;font-weight:600;">Teams</div>';
      html += st.teams_.map(t => {
        const members = st.people.filter(l => l.team_id === t.id);
        const open = members.filter(l => pending(l.id) > 0).length;
        const all = open === 0;
        return row(`Builder._assignToggleTeam(${t.id}, this.checked)`, esc(t.name),
          chip(all ? 'All assigned' : `${open} of ${members.length} to add`),
          st.teams.has(t.id) || all, all, `${t.name} team`);
      }).join('');
    }
    html += '<div class="modal-sub" style="margin:12px 0 4px;font-weight:600;">Learners</div>';
    html += st.people.map(l => {
      const done = pending(l.id) === 0;
      const team = st.teams_.find(t => t.id === l.team_id);
      return row(`Builder._assignToggleLearner('${l.id}', this.checked)`, esc(l.name),
        done ? `<span class="chip chip-green">Assigned</span>`
             : chip(team ? esc(team.name) : 'No team'),
        done || st.learners.has(l.id) || st.teams.has(l.team_id), done, l.name);
    }).join('') || '<p style="color:var(--ink-3);">No learners yet.</p>';
    if (st.managers.length) {
      html += '<div class="modal-sub" style="margin:12px 0 4px;font-weight:600;">Managers</div>';
      html += st.managers.map(l => {
        const done = pending(l.id) === 0;
        const team = st.teams_.find(t => t.id === l.team_id);
        return row(`Builder._assignToggleLearner('${l.id}', this.checked)`, esc(l.name),
          done ? `<span class="chip chip-green">Assigned</span>` : chip(team ? esc(team.name) : 'Manager'),
          done || st.learners.has(l.id), done, l.name);
      }).join('');
    }
    $$('assign-list').innerHTML = html;
    App.filterAssignList($$('assign-search').value);
  },

  _assignToggleTeam(id, on) {
    const st = Builder._assign;
    on ? st.teams.add(id) : st.teams.delete(id);
    Builder._assignRender(); Builder._assignUpdateBtn();
  },
  _assignToggleLearner(id, on) {
    const st = Builder._assign;
    on ? st.learners.add(id) : st.learners.delete(id);
    Builder._assignUpdateBtn();
  },
  // People who would receive at least one new assignment.
  _assignCount() {
    const st = Builder._assign;
    const ids = new Set(st.learners);
    st.people.filter(l => st.teams.has(l.team_id)).forEach(l => ids.add(l.id));
    return [...ids].filter(id => Builder._assignPending(st, id) > 0).length;
  },
  _assignUpdateBtn() {
    const btn = $$('assign-submit-btn');
    const st = Builder._assign;
    const n = st ? Builder._assignCount() : 0;
    btn.disabled = n === 0;
    const what = st && st.courseIds.length > 1 ? `${st.courseIds.length} courses` : '';
    btn.textContent = n ? `Assign ${what ? what + ' ' : ''}to ${n} learner${n === 1 ? '' : 's'}` : 'Assign';
  },

  async submitAssign() {
    const st = Builder._assign;
    if (!st || !st.courseIds.length) return Toast.err('No course selected.');
    const btn = $$('assign-submit-btn');
    btn.disabled = true; btn.textContent = 'Assigning…';
    try {
      const res = await Builder._assignApi()('/api/assignments/bulk', {
        method: 'POST',
        body: JSON.stringify({
          course_ids: st.courseIds,
          team_ids: [...st.teams],
          learner_ids: [...st.learners],
          due_at: $$('assign-due').value || null
        })
      });
      const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
      Toast.ok(st.courseIds.length > 1
        ? `Created ${plural(res.added, 'assignment')} across ${plural(st.courseIds.length, 'course')}.`
        : `Assigned to ${plural(res.added, 'learner')}.`);
      $$('assign-overlay').classList.add('hidden');
      Builder._sel = new Set();
      if (curManager) Manager.init(); else Admin.renderCourses?.();
    } catch(e) { Toast.err(e.message); Builder._assignUpdateBtn(); }
  }
};
