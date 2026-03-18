// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Unified Application Proxy
// ══════════════════════════════════════════════════════════

const AppProxy = {
  // Navigation
  aNav: (p) => Admin.nav(p),
  mNav: (p) => Manager.nav(p),
  lNav: (p) => Learner.nav(p),
  
  // Auth
  doLogin: () => Auth.doLogin(),
  doManagerLogin: () => Auth.doManagerLogin(),
  doManagerRegister: () => Auth.doManagerRegister(),
  adminLogout: () => Auth.adminLogout(),
  managerLogout: () => Auth.managerLogout(),
  learnerLogout: () => Auth.learnerLogout(),
  toggleManagerReg: (s) => Auth.toggleManagerReg(s),
  doLearnerLogin: () => Auth.doLearnerLogin(),

  // Builder & Courses
  openBuilder: (id) => Builder.openBuilder(id),
  closeBuilder: () => Builder.closeBuilder(),
  addMod: () => Builder.addMod(),
  saveCourse: () => Builder.saveCourse(),
  openAssign: (id, t) => Builder.openAssign(id, t),
  closeAssign: () => $$('assign-overlay').classList.add('hidden'),
  
  // Importer
  handleDrop: (e) => Admin.handleDrop(e),
  handleFileSelect: (e) => Admin.handleFileSelect(e),
  proceedFromUpload: () => Admin.proceedFromUpload(),
  startGeneration: () => Admin.startGeneration(),
  saveAiCourse: () => Admin.saveAiCourse(),
  goPhase: (n) => Admin.goPhase(n),

  // Admin Extra
  renderLearners: () => Admin.renderLearners(),
  filterLearners: (q) => Admin.filterLearners(q),
  openAddLearner: () => Admin.openAddLearner(),
  closeAddLearner: () => Admin.closeAddLearner(),
  submitAddLearner: () => Admin.submitAddLearner(),
  openEditLearner: (id, name, teamId, role) => Admin.openEditLearner(id, name, teamId, role),
  submitEditLearner: () => Admin.submitEditLearner(),
  openDeleteLearner: (id, name, role) => Admin.openDeleteLearner(id, name, role),
  submitDeleteLearner: (id) => Admin.submitDeleteLearner(id),
  openCreateTeam: () => Admin.openCreateTeam(),
  renderComps: (cid) => Admin.renderComps(cid),
  saveBrand: () => Admin.saveBrand(),
  clearRecords: () => Admin.clearRecords(),
  openResetPw: (id, n) => Admin.openResetPw(id, n),
  closeResetPw: () => Admin.closeResetPw(),
  submitResetPw: () => Admin.submitResetPw(),
  exportCSV: (s) => Admin.exportCSV(s),

  // Manager Extra
  toggleInvites: () => {
    const s = $$('invites-section'); if(!s) return;
    s.classList.toggle('hidden');
    $$('invites-toggle-icon').textContent = s.classList.contains('hidden') ? '▾' : '▴';
  },

  // Learner Extra
  closeCert: () => $$('cert-overlay').classList.add('hidden'),
  downloadCertPDF: () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF('l', 'mm', 'a4');
    html2canvas($$('cert-sheet'), { scale: 2 }).then(canvas => {
      const img = canvas.toDataURL('image/png');
      doc.addImage(img, 'PNG', 0, 0, 297, 210);
      doc.save('certificate.pdf');
    });
  },

  // Missing Mappings
  changePw: async () => {
    const cur = $$('np0')?.value || '';
    const p1  = $$('np1')?.value || '';
    const p2  = $$('np2')?.value || '';
    if (!cur) return Toast.err('Enter your current password.');
    if (p1.length < 8) return Toast.err('New password must be at least 8 characters.');
    if (p1 !== p2) return Toast.err('Passwords do not match.');
    try {
      await api('/api/admin/password', { method: 'PUT', body: JSON.stringify({ current_password: cur, new_password: p1 }) });
      $$('np0').value = ''; $$('np1').value = ''; $$('np2').value = '';
      Toast.ok('Admin password updated.');
    } catch(e) { Toast.err(e.message); }
  },
  previewBrand: () => applyBrand(),
  resetBrand: () => { brandCache = { name: CONFIG.DEFAULT_BRAND_NAME, c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, pass: CONFIG.DEFAULT_PASS }; applyBrand(); Admin.renderBranding(); },
  openTagsModal: () => { $$('tags-modal').classList.remove('hidden'); },
  closeTagsModal: () => $$('tags-modal').classList.add('hidden'),
  closeLearnerTagsModal: () => $$('learner-tags-modal').classList.add('hidden'),
  createTag: () => Toast.info('Tags coming soon'),
  closeConfirmDelete: () => $$('confirm-delete-overlay').classList.add('hidden'),
  copyInviteCode: () => {
    const code = $$('generated-code').textContent;
    navigator.clipboard.writeText(code).then(() => Toast.ok('Code copied!')).catch(() => Toast.info(code));
  },
  submitGenerateInvite: async () => {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    try {
      await api('/api/admin/invites', { method: 'POST', body: JSON.stringify({ code, team_id: App._inviteTeamId }) });
      $$('generated-code').textContent = code;
      $$('invite-form').classList.add('hidden');
      $$('invite-result').classList.remove('hidden');
    } catch (e) { Toast.err(e.message); }
  },

  // Navigation & screen switching
  exitCourse: () => { App.show('screen-learner'); if(curLearner) Learner.nav('courses'); },
  showLearner: () => { if(curLearner) { App.show('screen-learner'); Learner.nav('courses'); } else Toast.info('No active learner session.'); },
  moveLearner: (id) => Admin.moveLearner(id),

  // Manager
  renderMComps: () => Manager.renderComps(),
  updateManagerName: () => Toast.info('Coming soon'),
  changeManagerPw: () => Toast.info('Coming soon'),

  // Learner account
  updateLearnerName: () => Toast.info('Coming soon'),
  changeLearnerPw: () => Toast.info('Coming soon'),

  // Assign overlay tabs & search
  setAssignTab: (tab) => {
    ['learners','tags'].forEach(t => {
      const btn = $$(`assign-tab-${t}`), pane = $$(`assign-pane-${t}`);
      if(btn) btn.classList.toggle('active', t===tab);
      if(pane) pane.classList.toggle('hidden', t!==tab);
    });
  },
  filterAssignList: (q) => {
    $$('assign-list').querySelectorAll('[data-name]').forEach(el => {
      el.style.display = !q || el.dataset.name.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
    });
  },

  // Completions pagination
  compPage: (dir) => {
    compOffset = Math.max(0, compOffset + dir * COMP_LIMIT);
    Admin.renderComps();
  },

  // Branding
  uploadLogo: (e) => {
    const file = e.target.files[0]; if(!file) return;
    const reader = new FileReader();
    reader.onload = ev => { brandCache.logo = ev.target.result; applyBrand(); };
    reader.readAsDataURL(file);
  },
  syncHex: (colorId, hexId) => {
    const hex = $$(hexId).value;
    if(/^#[0-9a-fA-F]{6}$/.test(hex)) { $$(colorId).value = hex; applyBrand(); }
  },

  // Settings backup
  exportBackup: async () => {
    try {
      const [courses, learners, comps] = await Promise.all([api('/api/courses'), api('/api/learners'), api('/api/admin/completions')]);
      const blob = new Blob([JSON.stringify({ courses, learners, completions: comps }, null, 2)], { type: 'application/json' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'trainflow-backup.json'; a.click();
    } catch(e) { Toast.err(e.message); }
  },
  importBackup: () => Toast.info('Import feature coming soon'),

  // CSV import (for course builder)
  csvImportOpen: () => { csvParsed = null; $$('csv-preview').classList.add('hidden'); $$('csv-confirm').disabled = true; $$('csv-overlay').classList.remove('hidden'); },
  csvDrop: (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if(f) App._handleCsvFile(f); },
  csvFileSelected: (e) => { const f = e.target.files[0]; if(f) App._handleCsvFile(f); e.target.value = ''; },
  csvClose: () => $$('csv-overlay').classList.add('hidden'),
  csvConfirm: () => Toast.info('CSV import into builder coming soon'),
  _handleCsvFile: (file) => {
    const reader = new FileReader();
    reader.onload = ev => {
      try {
        csvParsed = JSON.parse(ev.target.result);
        $$('csv-preview').innerHTML = `<div class="card">${Array.isArray(csvParsed) ? csvParsed.length : 1} module(s) ready to import</div>`;
        $$('csv-preview').classList.remove('hidden');
        $$('csv-confirm').disabled = false;
      } catch { Toast.err('Invalid JSON file.'); }
    };
    reader.readAsText(file);
  },

  // Global
  init: async () => {
    await App.baseInit();
    if (getToken()) Admin.init();
    else if (getManagerToken()) Manager.init();
    else if (getLearnerToken()) Learner.init();
  }
};

// Merge proxy into the core App object
Object.assign(App, AppProxy);

// Auto-init on load
document.addEventListener('DOMContentLoaded', () => App.init());
