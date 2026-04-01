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
  saveCourse: (btn) => Builder.saveCourse(btn),
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
  openCreateSection: () => Admin.openCreateSection(),
  openAddManager: (teamId, teamName) => Admin.openAddManager(teamId, teamName),
  openCreateTeam: () => Admin.openCreateTeam(),
  renderComps: (cid) => Admin.renderComps(cid),
  saveBrand: (btn) => Admin.saveBrand(btn),
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
    const jspdf = window.jspdf;
    if (!jspdf) { Toast.err('PDF library not loaded.'); return; }
    if (typeof html2canvas !== 'function') { Toast.err('Canvas library not loaded.'); return; }
    const { jsPDF } = jspdf;
    const doc = new jsPDF('l', 'mm', 'a4');
    const sheet = $$('cert-sheet');
    if (!sheet) { Toast.err('Certificate sheet not found.'); return; }

    Toast.info('Generating PDF...');
    html2canvas(sheet, { scale: 2, useCORS: true, logging: false }).then(canvas => {
      const img = canvas.toDataURL('image/png');
      doc.addImage(img, 'PNG', 0, 0, 297, 210);

      // Official Filename: Certificate_CourseName_LearnerName.pdf
      const slug = s => s.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '');
      const cName = slug($$('c-course')?.textContent || 'Course');
      const lName = slug($$('c-name')?.textContent || 'Learner');
      const filename = `Certificate_${cName}_${lName}.pdf`;

      doc.save(filename);
      Toast.ok('Certificate downloaded.');
    }).catch(e => {
      console.error('PDF Error:', e);
      Toast.err('Failed to generate PDF.');
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
  previewBrand: () => {
    const hex  = $$('br-c1')?.value; if (hex  && /^#[0-9a-fA-F]{6}$/.test(hex))  brandCache.c1 = hex;
    const hex2 = $$('br-c2')?.value; if (hex2 && /^#[0-9a-fA-F]{6}$/.test(hex2)) brandCache.c2 = hex2;
    const hex3 = $$('br-c3')?.value; if (hex3 && /^#[0-9a-fA-F]{6}$/.test(hex3)) brandCache.c3 = hex3;
    const name = $$('br-name')?.value; if (name !== undefined) brandCache.name = name;
    const tagline = $$('br-tag')?.value; if (tagline !== undefined) brandCache.tagline = tagline;
    const logoUrl = $$('br-logo-url')?.value; if (logoUrl) brandCache.logo = logoUrl;
    applyBrand();
    // Update live branding panel preview
    const pn = $$('br-prev-name'); if (pn) pn.textContent = brandCache.name;
    const pl = $$('br-prev-logo'); if (pl) { pl.src = brandCache.logo || ''; pl.style.display = brandCache.logo ? 'block' : 'none'; }
    const ptag = $$('br-prev-tagline'); if (ptag) ptag.textContent = brandCache.tagline || CONFIG.DEFAULT_TAGLINE;
    const pcorg = $$('br-prev-cert-org'); if (pcorg) { pcorg.textContent = brandCache.name; pcorg.style.color = brandCache.c1 || CONFIG.DEFAULT_C1; }
    const lpb = $$('br-prev-logo-box'); const lph = $$('br-prev-logo-placeholder');
    if (lpb) { lpb.src = brandCache.logo || ''; lpb.style.display = brandCache.logo ? 'block' : 'none'; }
    if (lph) lph.style.display = brandCache.logo ? 'none' : '';
  },
  resetBrand: () => { brandCache = { name: CONFIG.DEFAULT_BRAND_NAME, tagline: CONFIG.DEFAULT_TAGLINE, logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, c3: CONFIG.DEFAULT_C3, pass: CONFIG.DEFAULT_PASS, font: CONFIG.DEFAULT_FONT, fontUrl: '' }; applyBrand(); Admin.renderBranding(); },
  changeFontPreset: (val) => {
    if (val !== 'Custom') {
      brandCache.font = val;
      brandCache.fontUrl = '';
      applyBrand();
    }
    Admin._toggleCustomFont(val === 'Custom');
    const cfName = $$('br-font-custom-name');
    if (cfName && val !== 'Custom') cfName.textContent = '';
  },
  uploadFont: (e) => {
    const file = e.target.files[0]; if (!file) return;
    const allowed = ['font/woff2','font/woff','font/ttf','font/otf','application/font-woff','application/font-woff2','application/x-font-ttf','application/x-font-opentype','application/octet-stream'];
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['woff','woff2','ttf','otf'].includes(ext)) { Toast.err('Upload a .woff2, .woff, .ttf, or .otf file.'); return; }
    if (file.size > 2 * 1024 * 1024) { Toast.err('Font file must be under 2MB.'); return; }
    const reader = new FileReader();
    reader.onload = ev => {
      brandCache.fontUrl = ev.target.result;
      brandCache.font = 'Custom';
      const sel = $$('br-font'); if (sel) sel.value = 'Custom';
      Admin._toggleCustomFont(true);
      const cfName = $$('br-font-custom-name');
      if (cfName) cfName.textContent = `${file.name} loaded ✓`;
      applyBrand();
    };
    reader.readAsDataURL(file);
  },
  applyPalette: (c1, c2, c3) => {
    brandCache.c1 = c1; brandCache.c2 = c2; brandCache.c3 = c3;
    const set = (id, val) => { const el = $$(id); if(el) el.value = val; };
    set('br-c1', c1); set('br-c1-hex', c1); set('br-c2', c2); set('br-c2-hex', c2); set('br-c3', c3); set('br-c3-hex', c3);
    App.previewBrand();
  },
  openTagsModal: () => { $$('tags-modal').classList.remove('hidden'); Admin.loadTagsList(); },
  closeTagsModal: () => $$('tags-modal').classList.add('hidden'),
  closeLearnerTagsModal: () => $$('learner-tags-modal').classList.add('hidden'),
  createTag: () => Admin.createTag(),
  closeConfirmDelete: () => $$('confirm-delete-overlay').classList.add('hidden'),
  copyInviteCode: (code) => {
    const c = code || $$('generated-code').textContent;
    navigator.clipboard.writeText(c).then(() => Toast.ok('Code copied!')).catch(() => Toast.info(c));
  },
  copyInviteMessage: (code, teamName) => Admin.copyInviteMessage(code, teamName),
  submitGenerateInvite: async () => {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    try {
      await api('/api/admin/invites', { method: 'POST', body: JSON.stringify({ code, team_id: App._inviteTeamId }) });
      $$('generated-code').textContent = code;
      $$('invite-form').classList.add('hidden');
      $$('invite-result').classList.remove('hidden');
    } catch (e) { Toast.err(e.message); }
  },

  // Learner CSV import
  openCsvImport: () => Manager.openCsvImport(),
  closeCsvImport: () => Manager.closeCsvImport(),
  downloadLearnerTemplate: () => Manager.downloadLearnerTemplate(),
  lCsvDrop: (e) => Manager.lCsvDrop(e),
  lCsvSelected: (e) => Manager.lCsvSelected(e),
  lCsvToggleAutogen: () => Manager.lCsvToggleAutogen(),
  submitCsvImport: () => Manager.submitCsvImport(),
  downloadCredsCSV: () => Manager.downloadCredsCSV(),
  proceedToAssign: () => Manager.proceedToAssign(),
  skipPostImportAssign: () => Manager.skipPostImportAssign(),
  submitPostImportAssign: () => Manager.submitPostImportAssign(),

  // Navigation & screen switching
  exitCourse: () => {
    if (window._adminPreview) { window._adminPreview = false; App.show('screen-admin'); }
    else { App.show('screen-learner'); if(curLearner) Learner.nav('courses'); }
  },
  showLearner: () => { if(curLearner) { App.show('screen-learner'); Learner.nav('courses'); } else Toast.info('No active learner session.'); },
  moveLearner: (id) => Admin.moveLearner(id),

  // Manager
  renderMComps: () => Manager.renderComps(),
  updateManagerName: async () => {
    const name = $$('mcp-name').value.trim();
    if (!name) return Toast.err('Name is required.');
    try {
      await managerApi('/api/managers/me', { method: 'PATCH', body: JSON.stringify({ name }) });
      curManager = { ...curManager, name };
      const u = getManagerUser(); if (u) setManagerUser({ ...u, user: { ...(u.user || {}), name } });
      $$('m-team-badge').textContent = curManager.team_name || 'My Team';
      Toast.ok('Name updated.');
    } catch(e) { Toast.err(e.message); }
  },
  changeManagerPw: async () => {
    const cur = $$('mcp-cur').value;
    const pw = $$('mcp-new').value;
    const conf = $$('mcp-confirm').value;
    if (!cur) return Toast.err('Enter your current password.');
    if (pw.length < 8) return Toast.err('New password must be at least 8 characters.');
    if (pw !== conf) return Toast.err('Passwords do not match.');
    try {
      await managerApi('/api/managers/me', { method: 'PATCH', body: JSON.stringify({ current_password: cur, password: pw }) });
      $$('mcp-cur').value = ''; $$('mcp-new').value = ''; $$('mcp-confirm').value = '';
      Toast.ok('Password updated.');
    } catch(e) { Toast.err(e.message); }
  },

  // Learner account
  updateLearnerName: async () => {
    const name = $$('lcp-name').value.trim();
    if (!name) return Toast.err('Name is required.');
    try {
      await learnerApi('/api/learners/me', { method: 'PATCH', body: JSON.stringify({ name }) });
      curLearner = { ...curLearner, name };
      $$('l-name-display').textContent = name;
      $$('l-avatar').textContent = name[0];
      Toast.ok('Name updated.');
    } catch(e) { Toast.err(e.message); }
  },
  changeLearnerPw: async () => {
    const cur = $$('lcp-cur').value;
    const pw = $$('lcp-new').value;
    const conf = $$('lcp-confirm').value;
    if (!cur) return Toast.err('Enter your current password.');
    if (pw.length < 8) return Toast.err('New password must be at least 8 characters.');
    if (pw !== conf) return Toast.err('Passwords do not match.');
    try {
      await learnerApi('/api/learners/me', { method: 'PATCH', body: JSON.stringify({ current_password: cur, password: pw }) });
      $$('lcp-cur').value = ''; $$('lcp-new').value = ''; $$('lcp-confirm').value = '';
      Toast.ok('Password updated.');
    } catch(e) { Toast.err(e.message); }
  },

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
    reader.onload = ev => {
      brandCache.logo = ev.target.result;
      const urlInput = $$('br-logo-url'); if (urlInput) urlInput.value = '';
      applyBrand();
      const pl = $$('br-prev-logo'); if (pl) { pl.src = brandCache.logo; pl.style.display = 'block'; }
      const lpb = $$('br-prev-logo-box'); const lph = $$('br-prev-logo-placeholder');
      if (lpb) { lpb.src = brandCache.logo; lpb.style.display = 'block'; }
      if (lph) lph.style.display = 'none';
    };
    reader.readAsDataURL(file);
  },
  syncHex: (colorId, hexId) => {
    const el = $$(hexId);
    const hex = el.value;
    if (/^#[0-9a-fA-F]{6}$/.test(hex)) {
      el.style.borderColor = '';
      el.title = '';
      $$(colorId).value = hex;
      App.previewBrand();
    } else {
      el.style.borderColor = 'var(--fail)';
      el.title = 'Enter a valid hex color, e.g. #2563eb';
    }
  },

  // Settings backup
  exportBackup: async () => {
    try {
      const [summaries, learners, comps] = await Promise.all([api('/api/courses'), api('/api/learners'), api('/api/admin/completions')]);
      const courses = await Promise.all(summaries.map(c => api(`/api/courses/${c.id}`)));
      const blob = new Blob([JSON.stringify({ courses, learners, completions: comps }, null, 2)], { type: 'application/json' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'trainflow-backup.json'; a.click();
    } catch(e) { Toast.err(e.message); }
  },
  importBackup: () => {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = '.json,application/json';
    inp.onchange = async e => {
      const file = e.target.files[0]; if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!data.courses || !Array.isArray(data.courses)) return Toast.err('Invalid backup file — no courses array found.');
        // Enrich backup with full course details if modules are missing
        const courses = data.courses;
        const res = await api('/api/admin/backup/restore', { method: 'POST', body: JSON.stringify({ courses }) });
        Toast.ok(`Restored ${res.imported} course(s). ${res.skipped} already existed and were skipped.`);
        Admin.renderCourses();
      } catch(e) { Toast.err('Restore failed: ' + e.message); }
    };
    inp.click();
  },

  // CSV import (for course builder)
  csvImportOpen: () => { csvParsed = null; $$('csv-preview').classList.add('hidden'); $$('csv-confirm').disabled = true; $$('csv-overlay').classList.remove('hidden'); },
  csvDrop: (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if(f) App._handleCsvFile(f); },
  csvFileSelected: (e) => { const f = e.target.files[0]; if(f) App._handleCsvFile(f); e.target.value = ''; },
  csvClose: () => $$('csv-overlay').classList.add('hidden'),
  csvConfirm: () => {
    if (!csvParsed || !csvParsed.length) return;
    csvParsed.forEach(m => cbState.mods.push(m));
    Builder.renderBuilderMods();
    App.csvClose();
    Toast.ok(`Added ${csvParsed.length} module(s) to the builder.`);
    csvParsed = null;
  },
  _handleCsvFile: (file) => {
    const reader = new FileReader();
    reader.onload = ev => {
      try {
        const text = ev.target.result;
        if (file.name.toLowerCase().endsWith('.json')) {
          const raw = JSON.parse(text);
          csvParsed = App._normImportData(raw);
        } else {
          csvParsed = App._parseCsvImport(text);
        }
        const qCount = csvParsed.reduce((s, m) => s + m.questions.length, 0);
        $$('csv-preview').innerHTML = `<div class="card" style="color:var(--pass);">✓ ${csvParsed.length} module(s) · ${qCount} question(s) ready to import</div>`;
        $$('csv-preview').classList.remove('hidden');
        $$('csv-confirm').disabled = false;
      } catch(e) { Toast.err('Could not parse file: ' + e.message); }
    };
    reader.readAsText(file);
  },
  _parseCsvImport: (text) => {
    const parseRow = line => {
      const vals = []; let cur = '', inQ = false;
      for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === '"') { inQ = !inQ; }
        else if (c === ',' && !inQ) { vals.push(cur); cur = ''; }
        else cur += c;
      }
      vals.push(cur);
      return vals.map(v => v.replace(/^"|"$/g, '').trim());
    };
    const lines = text.trim().split('\n').filter(l => l.trim());
    if (!lines.length) throw new Error('File is empty');
    const header = parseRow(lines[0]).map(h => h.toLowerCase().replace(/\s+/g,''));
    const rows = lines.slice(1).map(l => {
      const vals = parseRow(l);
      return Object.fromEntries(header.map((h, i) => [h, vals[i] || '']));
    });
    // Group by module name
    const modMap = new Map();
    const modOrder = [];
    rows.forEach(r => {
      const modName = r.module || r.title || 'Imported Module';
      if (!modMap.has(modName)) { modMap.set(modName, []); modOrder.push(modName); }
      const correctLetter = (r.correct || 'a').toUpperCase();
      const correctIdx = ['A','B','C','D'].includes(correctLetter)
        ? ['A','B','C','D'].indexOf(correctLetter)
        : (parseInt(r.correct) || 0);
      modMap.get(modName).push({
        id: uid(), question: r.question || '',
        options: [r.optiona||r.opta||'', r.optionb||r.optb||'', r.optionc||r.optc||'', r.optiond||r.optd||''],
        correct_index: correctIdx, explanation: r.explanation || ''
      });
    });
    return modOrder.map(name => ({ id: uid(), title: name, content: '', summary: '', reference_url: '', learning_objectives: [], questions: modMap.get(name) }));
  },
  _normImportData: (raw) => {
    const arr = Array.isArray(raw) ? raw : [raw];
    return arr.map(m => ({
      id: uid(),
      title: m.module || m.title || 'Imported Module',
      content: m.content || '',
      summary: m.summary || '',
      reference_url: m.reference_url || '',
      learning_objectives: Array.isArray(m.learning_objectives) ? m.learning_objectives : [],
      questions: (m.questions || []).map(q => ({
        id: uid(),
        question: q.question || '',
        options: Array.isArray(q.options) ? q.options : [q.optionA||q.optiona||'', q.optionB||q.optionb||'', q.optionC||q.optionc||'', q.optionD||q.optiond||''],
        correct_index: typeof q.correct_index === 'number' ? q.correct_index : (['A','B','C','D'].indexOf((q.correct||'A').toUpperCase()) >= 0 ? ['A','B','C','D'].indexOf((q.correct||'A').toUpperCase()) : 0),
        explanation: q.explanation || ''
      }))
    }));
  },

  // Theme toggle
  toggleTheme: () => {
    const html = document.documentElement;
    const isLight = html.getAttribute('data-theme') === 'light';
    const next = isLight ? 'dark' : 'light';
    if (next === 'dark') html.removeAttribute('data-theme');
    else html.setAttribute('data-theme', 'light');
    localStorage.setItem('trainflow_theme', next);
    const icon = next === 'light' ? '☾' : '☀';
    document.querySelectorAll('.theme-toggle').forEach(btn => {
      btn.textContent = icon;
      btn.title = next === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
    });
  },

  // Global
  init: async () => {
    const savedTheme = localStorage.getItem('trainflow_theme');
    if (savedTheme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
      document.querySelectorAll('.theme-toggle').forEach(btn => {
        btn.textContent = '☾';
        btn.title = 'Switch to dark mode';
      });
    }
    // Pre-apply saved brand color before API loads to prevent flash
    const savedBrand = localStorage.getItem('trainflow_brand_color');
    if (savedBrand && /^#[0-9a-fA-F]{6}$/.test(savedBrand)) {
      brandCache.c1 = savedBrand;
      applyBrand();
    }
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
