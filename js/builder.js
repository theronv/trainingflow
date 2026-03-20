// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Content Builder & AI Importer
// ══════════════════════════════════════════════════════════

const Builder = {
  // ─── COURSE BUILDER ───
  openBuilder(editId = null) {
    cbState = { editId, mods: [] };
    $$('cb-title').value = '';
    $$('cb-icon').value = '';
    $$('cb-desc').value = '';
    $$('cb-ref-url').value = '';
    $$('mods-builder').innerHTML = '';
    $$('builder-title').textContent = editId ? 'Edit Course' : 'New Course';
    $$('builder-overlay').classList.remove('hidden');
    if(editId) {
      api(`/api/courses/${editId}`).then(c => {
        const nc = normCourse(c);
        $$('cb-title').value = nc.title;
        $$('cb-icon').value = nc.icon;
        $$('cb-desc').value = nc.desc;
        $$('cb-ref-url').value = nc.refUrl;
        cbState.mods = nc.mods.map(m => ({ id: m.id, title: m.title, content: m.content, summary: m.summary || '', reference_url: m.refUrl || '', learning_objectives: m.objectives || [], questions: m.questions }));
        Builder.renderBuilderMods();
      }).catch(() => {});
    }
  },
  closeBuilder() { $$('builder-overlay').classList.add('hidden'); },
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
          <button class="btn btn-ghost btn-sm" style="color:var(--fail);" onclick="Builder.delMod(${i})">Remove</button>
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
  async saveCourse() {
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
    try {
      if(cbState.editId) await api(`/api/courses/${cbState.editId}`, { method: 'PUT', body: JSON.stringify(body) });
      else await api('/api/courses', { method: 'POST', body: JSON.stringify(body) });
      Builder.closeBuilder();
      if (curManager) Manager.init(); else Admin.init();
      Toast.ok('Course saved.');
    } catch(e) { Toast.err(e.message); }
  },

  // ─── ASSIGN INDIVIDUAL (ADMIN) ───
  async openAssign(cid, title) {
    App._assignCourseId = cid;
    $$('assign-subtitle').textContent = title;
    $$('assign-overlay').classList.remove('hidden');
    $$('assign-list').innerHTML = 'Loading...';
    try {
      const [learners, assigns] = await Promise.all([api('/api/learners'), api('/api/assignments')]);
      const cidAssigns = assigns.filter(a => a.course_id === cid).map(a => a.learner_id);
      $$('assign-list').innerHTML = learners.map(l => `
        <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--rule);">
          <input type="checkbox" id="chk-ind-${l.id}" ${cidAssigns.includes(l.id)?'checked':''} onchange="Builder.toggleAssign('${l.id}', this.checked)">
          <label for="chk-ind-${l.id}" style="margin:0;">${esc(l.name)}</label>
        </div>`).join('');
    } catch(e) { }
  },
  async toggleAssign(lid, checked) {
    try {
      const method = checked ? 'POST' : 'DELETE';
      await api('/api/assignments', { method, body: JSON.stringify({ course_id: App._assignCourseId, learner_id: lid }) });
      Toast.ok(checked ? 'Course assigned.' : 'Assignment removed.');
    } catch(e) { Toast.err(e.message); }
  }
};
