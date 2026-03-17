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
  csvImportOpen: () => Builder.csvImportOpen(),
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
