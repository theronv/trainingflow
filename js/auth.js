// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Authentication Logic
// ══════════════════════════════════════════════════════════

const Auth = {
  // ─── ADMIN ───
  async doLogin() {
    const password = $$('pw-input').value;
    try {
      const { token } = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) });
      setToken(token);
      $$('pw-input').value = '';
      applyBrand();
      App.show('screen-admin');
      Admin.init();
    } catch (e) {
      if (e.status === 503) $$('first-run-overlay').classList.remove('hidden');
      else Toast.err(e.message);
    }
  },
  adminLogout() { clearToken(); App.show('screen-landing'); },

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
      setManagerToken(data.token); setManagerUser(data); curManager = data;
      Manager.init();
    } catch(e) { Toast.err(e.message); }
  },
  async doManagerRegister() {
    const name = $$('m-reg-name').value.trim(), pw1 = $$('m-reg-pw1').value, pw2 = $$('m-reg-pw2').value, invite_code = $$('m-reg-code').value.trim();
    if(!name || pw1.length < 8 || pw1 !== pw2 || !invite_code) return Toast.err('Please check all fields.');
    try {
      const data = await api('/api/auth/manager/register', { method: 'POST', body: JSON.stringify({ name, password: pw1, invite_code }) });
      setManagerToken(data.token); setManagerUser(data); curManager = data;
      Manager.init();
    } catch(e) { Toast.err(e.message); }
  },
  managerLogout() { clearManagerToken(); clearManagerUser(); curManager = null; App.show('screen-landing'); },

  // ─── LEARNER ───
  async doLearnerLogin() {
    const name = $$('learner-name-input').value.trim(), password = $$('learner-pw-input').value;
    try {
      const data = await api('/api/learners/login', { method: 'POST', body: JSON.stringify({ name, password }) });
      setLearnerToken(data.token); curLearner = { id: data.id, name: data.name };
      Learner.init();
    } catch(e) { $$('l-login-error').textContent = e.message; $$('l-login-error').style.display='block'; }
  },
  learnerLogout() { clearLearnerToken(); curLearner = null; App.show('screen-landing'); }
};
