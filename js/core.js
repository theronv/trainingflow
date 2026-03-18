// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Core Utilities & State
// ══════════════════════════════════════════════════════════

const CONFIG = {
  WORKER_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8787'
    : 'https://trainflow-worker.theronv.workers.dev',
  DEFAULT_BRAND_NAME: 'TrainFlow',
  DEFAULT_TAGLINE: 'Training & Certification Platform',
  DEFAULT_C1: '#2563eb',
  DEFAULT_C2: '#1d4ed8',
  DEFAULT_PASS: 80,
  DEFAULT_ICON: '📋',
  MIN_PW_LEN: 8,
  TOAST_MS: 3200,
  FOCUS_DELAY: 80,
};

const WORKER_URL = CONFIG.WORKER_URL;

const StorageUtils = {
  get(key) { try { return sessionStorage.getItem(key); } catch (e) { return null; } },
  set(key, val) { try { sessionStorage.setItem(key, val); } catch (e) { } },
  remove(key) { try { sessionStorage.removeItem(key); } catch (e) { } }
};

function getToken()          { return StorageUtils.get('tf_token'); }
function setToken(t)         { StorageUtils.set('tf_token', t); }
function clearToken()        { StorageUtils.remove('tf_token'); }
function getManagerToken()   { return StorageUtils.get('tf_manager_token'); }
function setManagerToken(t)  { StorageUtils.set('tf_manager_token', t); }
function clearManagerToken() { StorageUtils.remove('tf_manager_token'); }
function getManagerUser()    { try { return JSON.parse(StorageUtils.get('tf_manager_user')); } catch(e){ return null; } }
function setManagerUser(u)   { StorageUtils.set('tf_manager_user', JSON.stringify(u)); }
function clearManagerUser()  { StorageUtils.remove('tf_manager_user'); }
function getLearnerToken()   { return StorageUtils.get('tf_learner_token'); }
function setLearnerToken(t)  { StorageUtils.set('tf_learner_token', t); }
function clearLearnerToken() { StorageUtils.remove('tf_learner_token'); }

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(WORKER_URL + path, { ...opts, headers });
  if (res.status === 401 && token) { clearToken(); App.show('screen-landing'); throw new Error('Session expired'); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw Object.assign(new Error(body.error || res.statusText), { status: res.status, detail: body.detail });
  }
  return res.json();
}

async function managerApi(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const token = getManagerToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(WORKER_URL + path, { ...opts, headers });
  if (res.status === 401 && token) { clearManagerToken(); clearManagerUser(); App.show('screen-landing'); throw new Error('Session expired'); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw Object.assign(new Error(body.error || res.statusText), { status: res.status, detail: body.detail });
  }
  return res.json();
}

async function learnerApi(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const token = getLearnerToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(WORKER_URL + path, { ...opts, headers });
  if (res.status === 401 && token) { clearLearnerToken(); App.show('screen-landing'); throw new Error('Session expired'); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw Object.assign(new Error(body.error || res.statusText), { status: res.status, detail: body.detail });
  }
  return res.json();
}

let curLearner   = null;
let curManager   = null;
let curCourse    = null;
let curModIdx    = 0;
let quizSt       = {};
let cbState      = { editId: null, mods: [] };
let csvParsed    = null;
let compOffset   = 0;
const COMP_LIMIT = 50;
let _allLearners = [];
let teamsCache   = [];
let coursesCache = [];
let assignCache  = [];
let isDemo       = false;
let brandCache   = { name: CONFIG.DEFAULT_BRAND_NAME, tagline: CONFIG.DEFAULT_TAGLINE, logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, pass: CONFIG.DEFAULT_PASS };

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2,6); }
function $$(id) { return document.getElementById(id); }

const Toast = {
  show(msg, type='info') {
    const el = document.createElement('div');
    el.className = `toast t-${type}`;
    el.textContent = msg;
    document.getElementById('toast-root').appendChild(el);
    setTimeout(() => { el.style.transition='opacity 0.3s'; el.style.opacity='0'; setTimeout(()=>el.remove(),300); }, CONFIG.TOAST_MS);
  },
  ok(m)   { Toast.show(m,'success'); },
  err(m)  { Toast.show(m,'error'); },
  info(m) { Toast.show(m,'info'); }
};

function normCourse(c) {
  return {
    id: c.id, icon: c.icon || CONFIG.DEFAULT_ICON, title: c.title, desc: c.description || '', refUrl: c.reference_url || '',
    mods: (c.modules || []).map(m => ({
      id: m.id, title: m.title, content: m.content || '',
      questions: (m.questions || []).map(q => ({
        id: q.id,
        question: q.question,
        options: [q.option_a, q.option_b, q.option_c, q.option_d],
        correct_index: q.correct_index,
        explanation: q.explanation || '',
      }))
    }))
  };
}
function normRecord(r) { return { cid: r.course_id, learner: r.learner_name, score: r.score, passed: Boolean(r.passed), date: (r.completed_at || 0) * 1000, cid2: r.cert_id || '', }; }
function normBrand(b) { return { name: b.org_name || CONFIG.DEFAULT_BRAND_NAME, tagline: b.tagline || CONFIG.DEFAULT_TAGLINE, logo: b.logo_url || '', c1: b.primary_color || CONFIG.DEFAULT_C1, c2: b.secondary_color || CONFIG.DEFAULT_C2, pass: b.pass_threshold ?? CONFIG.DEFAULT_PASS, }; }

function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${alpha})`;
}
function darken(hex, percent) {
  let r = parseInt(hex.slice(1,3),16);
  let g = parseInt(hex.slice(3,5),16);
  let b = parseInt(hex.slice(5,7),16);
  r = Math.max(0, Math.floor(r * (1 - percent/100)));
  g = Math.max(0, Math.floor(g * (1 - percent/100)));
  b = Math.max(0, Math.floor(b * (1 - percent/100)));
  return `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`;
}

function applyBrand() {
  const b = brandCache;
  const hex = (b.c1 && /^#[0-9a-fA-F]{6}$/.test(b.c1)) ? b.c1 : CONFIG.DEFAULT_C1;

  // Apply all brand CSS tokens
  document.documentElement.style.setProperty('--brand',        hex);
  document.documentElement.style.setProperty('--brand-dark',   darken(hex, 15));
  document.documentElement.style.setProperty('--brand-glow',   hexToRgba(hex, 0.15));
  document.documentElement.style.setProperty('--shadow-brand', `0 0 0 3px ${hexToRgba(hex, 0.2)}`);
  // Legacy aliases
  document.documentElement.style.setProperty('--brand-1', hex);
  document.documentElement.style.setProperty('--brand-2', b.c2 || CONFIG.DEFAULT_C2);

  // Org name across all surfaces
  ['ldg-brand', 'l-brand', 'a-brand', 'm-brand'].forEach(id => { const el = $$(id); if(el) el.textContent = b.name; });
  const certSig = $$('c-sig-dept');
  if(certSig) certSig.textContent = b.name + ' Training Department';

  // Logo across all surfaces (topbars + landing)
  const logoSrc = b.logo || '';
  ['l-logo', 'a-logo', 'm-logo', 'ldg-logo'].forEach(id => {
    const img = $$(id); if(!img) return;
    if(logoSrc) { img.src = logoSrc; img.classList.remove('hidden'); }
    else { img.src = ''; img.classList.add('hidden'); }
  });

  // Hide/show the diamond accent on topbar brand when logo is present
  document.querySelectorAll('.brand').forEach(el => el.classList.toggle('has-logo', !!logoSrc));

  // Landing: show logo image + name together, or just name
  const ldgWrap = $$('ldg-logo-wrap');
  if (ldgWrap) ldgWrap.classList.toggle('hidden', !logoSrc);
  const ldgBrand = $$('ldg-brand');
  if (ldgBrand) ldgBrand.style.display = ''; // always show name
}

function showPage(id) { 
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  const el = $$(id); if(el) el.classList.remove('hidden');
}

const App = {
  async baseInit() {
    const lt = getLearnerToken();
    if (lt) { try { const me = await learnerApi('/api/learners/me'); curLearner = { id: me.id, name: me.name }; } catch { clearLearnerToken(); } }
    const mt = getManagerToken();
    if (mt) { curManager = getManagerUser(); }
    try { const b = await api('/api/brand'); brandCache = normBrand(b); } catch { }
    applyBrand();
  },

  show(id) {
    // 🔐 RBAC / Access Control
    if (id === 'screen-admin' && !getToken()) {
      Toast.err('Unauthorized: Admin access required.');
      return App.show('screen-login');
    }
    if (id === 'screen-manager' && !getManagerToken()) {
      Toast.err('Unauthorized: Manager access required.');
      return App.show('screen-manager-login');
    }
    if (id === 'screen-course' && !getLearnerToken() && !isDemo && !window._adminPreview) {
      Toast.err('Please sign in to view courses.');
      return App.show('screen-landing');
    }

    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const el = $$(id); if(el) el.classList.add('active');
  },

  startDemo() {
    isDemo = true;
    curLearner = { id: 'demo-id', name: 'Demo Learner' };
    brandCache = { name: 'TrainFlow Demo', tagline: 'Experience the new UI/UX', logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, pass: CONFIG.DEFAULT_PASS };
    applyBrand();
    Toast.ok('Demo Mode Activated ✨');
    Learner.init();
  },

  goLearner() { App.show('screen-learner'); applyBrand(); if(curLearner) Learner.init(); else showPage('lp-name'); },
  goManager() { App.show('screen-manager-login'); Auth.toggleManagerReg(false); setTimeout(()=>$$('m-login-name').focus(),CONFIG.FOCUS_DELAY); },
  goAdmin()   { App.show('screen-login'); setTimeout(()=>$$('pw-input').focus(),CONFIG.FOCUS_DELAY); },
};
