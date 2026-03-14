// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Content Builder & AI Importer
// ══════════════════════════════════════════════════════════

const Builder = {
  // ─── COURSE BUILDER ───
  openBuilder(editId = null) {
    cbState = { editId, mods: [] };
    $$('cb-overlay').classList.remove('hidden');
    if(editId) { /* Load existing */ }
    Builder.renderBuilderMods();
  },
  addMod() {
    cbState.mods.push({ id: uid(), title: 'New Module', content: '', questions: [] });
    Builder.renderBuilderMods();
  },
  renderBuilderMods() {
    $$('cb-mods').innerHTML = cbState.mods.map((m, i) => `<div class="card" style="margin-bottom:12px;">
      <input type="text" value="${esc(m.title)}" oninput="cbState.mods[${i}].title=this.value" placeholder="Module Title">
      <textarea oninput="cbState.mods[${i}].content=this.value" placeholder="Markdown content...">${m.content}</textarea>
      <button class="btn btn-ghost btn-sm" onclick="Builder.delMod(${i})">Remove Module</button>
    </div>`).join('');
  },
  delMod(i) { cbState.mods.splice(i, 1); Builder.renderBuilderMods(); },
  async saveCourse() {
    const title = $$('cb-title').value.trim();
    const body = { title, mods: cbState.mods };
    try {
      await api('/api/courses', { method: 'POST', body: JSON.stringify(body) });
      $$('cb-overlay').classList.add('hidden');
      if (curManager) Manager.nav('courses'); else Admin.nav('courses');
      Toast.ok('Course saved.');
    } catch(e) { Toast.err(e.message); }
  },

  // ─── ASSIGN OVERLAY ───
  async openAssign(cid, title) {
    App._assignCourseId = cid;
    $$('assign-subtitle').textContent = title;
    $$('assign-overlay').classList.remove('hidden');
    Builder.renderAssignList();
  },
  async renderAssignList() {
    const [learners, assigns] = await Promise.all([api('/api/learners'), api('/api/assignments')]);
    const cidAssigns = assigns.filter(a => a.course_id === App._assignCourseId).map(a => a.learner_id);
    $$('assign-list').innerHTML = learners.map(l => `<div style="padding:8px 0; border-bottom:1px solid var(--rule);">
      <input type="checkbox" id="chk-${l.id}" ${cidAssigns.includes(l.id)?'checked':''}>
      <label for="chk-${l.id}">${esc(l.name)}</label>
    </div>`).join('');
  },

  // ─── AI IMPORTER ───
  handleDrop(e) {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files).filter(f => f.name.endsWith('.md'));
    files.forEach(f => {
      const r = new FileReader();
      r.onload = ev => {
        cbState.mods.push({ id: uid(), title: f.name.replace('.md',''), content: ev.target.result, questions: [] });
        Toast.ok('Added ' + f.name);
      };
      r.readAsText(f);
    });
  }
};
