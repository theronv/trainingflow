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
    $$('mods-builder').innerHTML = '';
    $$('builder-overlay').classList.remove('hidden');
    if(editId) { 
      // Load existing logic to be implemented
    }
  },
  closeBuilder() { $$('builder-overlay').classList.add('hidden'); },
  addMod() {
    const mi = cbState.mods.length;
    cbState.mods.push({ id: uid(), title: '', content: '', questions: [] });
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
        <div class="field"><label>Content (Markdown)</label><textarea style="min-height:120px;" oninput="cbState.mods[${i}].content=this.value" placeholder="Module text here...">${m.content}</textarea></div>
      </div>`).join('');
  },
  delMod(i) { cbState.mods.splice(i, 1); Builder.renderBuilderMods(); },
  async saveCourse() {
    const title = $$('cb-title').value.trim();
    if(!title) return Toast.err('Title required.');
    const body = { 
      title, 
      icon: $$('cb-icon').value || '📋',
      description: $$('cb-desc').value,
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
    } catch(e) { Toast.err(e.message); }
  }
};
