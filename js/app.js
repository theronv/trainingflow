// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Unified Application Proxy (Exhaustive)
// ══════════════════════════════════════════════════════════

/**
 * The App object is the global interface for the HTML.
 * This file maps all UI events to their respective modules.
 */

const AppProxy = {
  // ─── Navigation ───
  aNav: (p) => Admin.nav(p),
  mNav: (p) => Manager.nav(p),
  lNav: (p) => Learner.nav(p),
  showPage: (id) => showPage(id),
  exitCourse: () => Learner.nav('courses'),

  // ─── Authentication ───
  doLogin: () => Auth.doLogin(),
  doManagerLogin: () => Auth.doManagerLogin(),
  doManagerRegister: () => Auth.doManagerRegister(),
  adminLogout: () => Auth.adminLogout(),
  managerLogout: () => Auth.managerLogout(),
  learnerLogout: () => Auth.learnerLogout(),
  toggleManagerReg: (s) => Auth.toggleManagerReg(s),
  doLearnerLogin: () => Auth.doLearnerLogin(),

  // ─── Admin: Teams & Invites ───
  openCreateTeam: () => Admin.openCreateTeam(),
  submitCreateTeam: () => Admin.submitCreateTeam(),
  deleteTeam: (id) => Admin.deleteTeam(id),
  openRenameTeam: (id, n) => Admin.openRenameTeam(id, n),
  toggleTeamMembers: (id) => Admin.toggleTeamMembers(id),
  openGenerateInvite: (id, n) => Admin.openGenerateInvite(id, n),
  submitGenerateInvite: () => Admin.submitGenerateInvite(),
  copyInviteCode: () => Admin.copyInviteCode(),
  toggleInvites: () => Admin.toggleInvites(),
  revokeInvite: (id) => Admin.revokeInvite(id),

  // ─── Admin: Learners ───
  renderLearners: () => Admin.renderLearners(),
  filterLearners: (q) => Admin.filterLearners(q),
  learnerPage: (d) => Admin.learnerPage(d),
  moveLearner: (id) => Admin.moveLearner(id),
  openAddLearner: () => Admin.openAddLearner(),
  closeAddLearner: () => Admin.closeAddLearner(),
  submitAddLearner: () => Admin.submitAddLearner(),
  openResetPw: (id, n) => Admin.openResetPw(id, n),
  closeResetPw: () => Admin.closeResetPw(),
  submitResetPw: () => Admin.submitResetPw(),
  openLearnerTags: (id, n) => Admin.openLearnerTags(id, n),
  closeLearnerTagsModal: () => Admin.closeLearnerTagsModal(),

  // ─── Admin: Settings & Branding ───
  saveBrand: () => Admin.saveBrand(),
  resetBrand: () => Admin.resetBrand(),
  previewBrand: () => Admin.previewBrand(),
  syncHex: (a, b) => Admin.syncHex(a, b),
  uploadLogo: (e) => Admin.uploadLogo(e),
  changePw: () => Admin.changePw(),
  exportBackup: () => Admin.exportBackup(),
  importBackup: (e) => Admin.importBackup(e),
  clearRecords: () => Admin.clearRecords(),

  // ─── Manager: Team Management ───
  renderMComps: (id) => Manager.renderComps(id),
  openTeamAssign: (id, t) => Manager.openTeamAssign(id, t),
  submitTeamAssign: () => Manager.submitTeamAssign(),
  updateManagerName: () => Manager.updateName(),
  changeManagerPw: () => Manager.changePw(),

  // ─── Learner: Profile ───
  updateLearnerName: () => Learner.updateName(),
  changeLearnerPw: () => Learner.changePw(),

  // ─── Builder & Assignments ───
  openBuilder: (id) => Builder.openBuilder(id),
  addMod: () => Builder.addMod(),
  delMod: (i) => Builder.delMod(i),
  saveCourse: () => Builder.saveCourse(),
  csvImportOpen: () => Builder.csvImportOpen(),
  csvClose: () => Builder.csvClose(),
  csvDrop: (e) => Builder.csvDrop(e),
  csvFileSelected: (e) => Builder.csvFileSelected(e),
  csvConfirm: () => Builder.csvConfirm(),
  openAssign: (id, t) => Builder.openAssign(id, t),
  setAssignTab: (t) => Builder.setAssignTab(t),
  filterAssignList: (q) => Builder.filterAssignList(q),
  closeAssign: () => $$('assign-overlay').classList.add('hidden'),

  // ─── Global ───
  init: async () => {
    await App.baseInit();
    if (getToken()) Admin.init();
    else if (getManagerToken()) Manager.init();
    else if (getLearnerToken()) Learner.init();
  },
  downloadCertPDF: () => window.print(),
  closeCert: () => $$('cert-overlay').classList.add('hidden'),
  exportCSV: (s) => Admin.exportCSV(s)
};

// Merge proxy into the core App object
Object.assign(App, AppProxy);

// Auto-init on load
document.addEventListener('DOMContentLoaded', () => App.init());
