// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Unified Application Proxy
// ══════════════════════════════════════════════════════════

/**
 * The App object is the global interface for the HTML.
 * It proxies calls to the modular JS files (auth.js, admin.js, etc.)
 */

// Core setup already exists in js/core.js (App object)

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

  // Builder
  openBuilder: (id) => Builder.openBuilder(id),
  addMod: () => Builder.addMod(),
  saveCourse: () => Builder.saveCourse(),
  csvImportOpen: () => Builder.csvImportOpen(),
  
  // Global
  init: async () => {
    await App.init();
    if (getToken()) Admin.init();
    else if (getManagerToken()) Manager.init();
    else if (getLearnerToken()) Learner.init();
  }
};

// Merge proxy into the core App object
Object.assign(App, AppProxy);

// Auto-init on load
document.addEventListener('DOMContentLoaded', () => App.init());
