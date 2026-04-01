// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Authentication Logic
// ══════════════════════════════════════════════════════════

function scheduleExpiryWarning(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (!payload.exp) return;
    const msUntilWarn = (payload.exp * 1000) - Date.now() - 5 * 60 * 1000;
    if (msUntilWarn > 0) {
      setTimeout(() => Toast.info('Your session expires in 5 minutes. Save your work and sign in again to continue.'), msUntilWarn);
    }
  } catch(e) { /* ignore */ }
}

const Auth = {
  // ─── ADMIN ───
  async doLogin() {
    const password = $$('pw-input').value;
    try {
      const { token } = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) });
      setToken(token);
      scheduleExpiryWarning(token);
      $$('pw-input').value = '';
      applyBrand();
      App.show('screen-admin');
      Admin.init();
    } catch (e) {
      if (e.status === 503) $$('first-run-overlay').classList.remove('hidden');
      else Toast.err(e.message);
    }
  },
  adminLogout() { clearToken(); curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); },

  // ─── MANAGER ───
  toggleManagerReg(show) {
    $$('m-login-form').classList.toggle('hidden', show);
    $$('m-reg-form').classList.toggle('hidden', !show);
    $$('m-login-sub').textContent = show ? 'Create your manager account.' : 'Sign in to manage your team.';
  },
  async doManagerLogin() {
    const name = $$('m-login-name').value.trim(), password = $$('m-login-pw').value;
    if(!name || !password) return Toast.err('Enter name and password.');
    try {
      const data = await api('/api/auth/manager/login', { method: 'POST', body: JSON.stringify({ name, password }) });
      setManagerToken(data.token); scheduleExpiryWarning(data.token); setManagerUser(data); curManager = data;
      Manager.init();
    } catch(e) { Toast.err(e.message); }
  },
  async doManagerRegister() {
    const name = $$('m-reg-name').value.trim(), pw1 = $$('m-reg-pw1').value, pw2 = $$('m-reg-pw2').value, code = $$('m-reg-code').value.trim();
    if (!name) return Toast.err('Please enter your full name.');
    if (pw1.length < 8) return Toast.err('Password must be at least 8 characters.');
    if (pw1 !== pw2) return Toast.err('Passwords do not match.');
    if (!code) return Toast.err('Please enter your invite code.');
    try {
      const data = await api('/api/auth/manager/register', { method: 'POST', body: JSON.stringify({ name, password: pw1, code }) });
      setManagerToken(data.token); scheduleExpiryWarning(data.token); setManagerUser(data); curManager = data;
      Manager.init();
    } catch(e) { Toast.err(e.message); }
  },
  managerLogout() { clearManagerToken(); clearManagerUser(); curManager = null; curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); },

  // ─── LEARNER ───
  async doLearnerLogin() {
    const name = $$('learner-name-input').value.trim(), password = $$('learner-pw-input').value;
    try {
      const data = await api('/api/learners/login', { method: 'POST', body: JSON.stringify({ name, password }) });
      setLearnerToken(data.token); curLearner = { id: data.user.id, name: data.user.name };
      Learner.init();
    } catch(e) { $$('l-login-error').textContent = e.message; $$('l-login-error').style.display='block'; }
  },
  learnerLogout() { clearLearnerToken(); curLearner = null; curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); }
};
