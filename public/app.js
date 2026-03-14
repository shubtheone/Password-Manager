const $ = (id) => document.getElementById(id);
const $$ = (sel, root = document) => root.querySelectorAll(sel);

const screens = {
  profile: $('profile-screen'),
  auth: $('auth-screen'),
  createUser: $('create-user-screen'),
  vault: $('vault-screen'),
};

const showScreen = (name) => {
  Object.values(screens).forEach((el) => el && el.classList.add('hidden'));
  const s = screens[name];
  if (s) s.classList.remove('hidden');
};

const AUTO_LOCK_STORAGE_KEY = 'familyVault_autoLock';
const AUTO_LOCK_MINUTES_KEY = 'familyVault_autoLockMinutes';

let state = {
  users: [],
  selectedUserId: null,
  userId: null,
  vault: { passwords: [], notes: [] },
  passwordFilter: '',
  noteFilter: '',
  locked: false,
  autoLockEnabled: false,
  autoLockMinutes: 5,
  inactivityTimerId: null,
  pendingImportFile: null,
};

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const data = res.ok ? (res.status === 204 ? null : await res.json().catch(() => null)) : null;
  if (!res.ok) {
    const err = (data && data.error) || res.statusText || 'Request failed';
    throw new Error(err);
  }
  return data;
}

function toast(msg, isSuccess = false) {
  const el = document.createElement('div');
  el.className = isSuccess ? 'error-toast success-toast' : 'error-toast';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function renderProfiles() {
  const list = $('profile-list');
  if (!list) return;
  list.innerHTML = state.users
    .map(
      (u) =>
        `<button type="button" class="profile-card" data-user-id="${u.id}" data-user-name="${escapeAttr(u.name)}" data-has-recovery="${u.hasRecovery ? '1' : '0'}">${escapeHtml(u.name)}</button>`
    )
    .join('');
  list.querySelectorAll('.profile-card').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedUserId = btn.dataset.userId;
      state.selectedUserHasRecovery = btn.dataset.hasRecovery === '1';
      $('auth-user-name').textContent = btn.dataset.userName || '';
      $('login-keyword').value = '';
      const forgotBtn = $('forgot-keyword-btn');
      if (forgotBtn) forgotBtn.classList.toggle('hidden', !state.selectedUserHasRecovery);
      $('recover-keyword-form').classList.add('hidden');
      $('login-form').classList.remove('hidden');
      showScreen('auth');
      setTimeout(() => $('login-keyword').focus(), 100);
    });
  });
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function escapeAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function loadUsers() {
  const data = await api('/api/users');
  state.users = data.users || [];
  renderProfiles();
}

$('add-profile-btn')?.addEventListener('click', () => {
  $('create-name').value = '';
  $('create-keyword').value = '';
  if ($('create-recovery-keyword')) $('create-recovery-keyword').value = '';
  updateKeywordRequirements('');
  showScreen('createUser');
  setTimeout(() => $('create-name').focus(), 100);
});

$('create-back')?.addEventListener('click', () => showScreen('profile'));

function validateKeywordClient(keyword) {
  const len = keyword.length >= 8;
  const upper = /[A-Z]/.test(keyword);
  const lower = /[a-z]/.test(keyword);
  const num = /\d/.test(keyword);
  const sym = /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(keyword);
  return { len, upper, lower, num, sym, all: len && upper && lower && num && sym };
}

function updateKeywordRequirements(keyword) {
  const v = validateKeywordClient(keyword);
  const ids = ['kw-len', 'kw-upper', 'kw-lower', 'kw-num', 'kw-sym'];
  const keys = ['len', 'upper', 'lower', 'num', 'sym'];
  keys.forEach((k, i) => {
    const el = $(ids[i]);
    if (el) el.classList.toggle('met', v[k]);
  });
  const submitBtn = $('create-submit-btn');
  if (submitBtn) submitBtn.disabled = !v.all;
}

$('create-keyword')?.addEventListener('input', () => {
  updateKeywordRequirements($('create-keyword').value);
});

$('create-keyword')?.addEventListener('focus', () => {
  updateKeywordRequirements($('create-keyword').value);
});

$('create-user-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('create-name').value.trim();
  const keyword = $('create-keyword').value;
  const recoveryKeyword = $('create-recovery-keyword')?.value?.trim() || undefined;
  if (!name || !keyword) return;
  if (!validateKeywordClient(keyword).all) {
    toast('Keyword does not meet all requirements');
    return;
  }
  if (recoveryKeyword && !validateKeywordClient(recoveryKeyword).all) {
    toast('Recovery keyword must meet the same requirements');
    return;
  }
  try {
    await api('/api/users', { method: 'POST', body: { name, keyword, recoveryKeyword } });
    await loadUsers();
    showScreen('profile');
  } catch (err) {
    toast(err.message);
  }
});

$('auth-back')?.addEventListener('click', () => {
  state.selectedUserId = null;
  showScreen('profile');
});

$('forgot-keyword-btn')?.addEventListener('click', () => {
  $('login-form').classList.add('hidden');
  $('recover-keyword-form').classList.remove('hidden');
  $('recover-recovery-keyword').value = '';
  $('recover-new-keyword').value = '';
});

$('recover-cancel-btn')?.addEventListener('click', () => {
  $('recover-keyword-form').classList.add('hidden');
  $('login-form').classList.remove('hidden');
});

$('recover-submit-btn')?.addEventListener('click', async () => {
  const recoveryKeyword = $('recover-recovery-keyword').value;
  const newKeyword = $('recover-new-keyword').value;
  if (!recoveryKeyword || !newKeyword) {
    toast('Enter both recovery keyword and new keyword');
    return;
  }
  if (!validateKeywordClient(newKeyword).all) {
    toast('New keyword must meet the same requirements (8+ chars, upper, lower, number, symbol)');
    return;
  }
  try {
    await api('/api/auth/recover-keyword', {
      method: 'POST',
      body: { userId: state.selectedUserId, recoveryKeyword, newKeyword },
    });
    toast('Keyword updated. You can now log in with your new keyword.', true);
    $('recover-keyword-form').classList.add('hidden');
    $('login-form').classList.remove('hidden');
    $('login-keyword').value = newKeyword;
  } catch (err) {
    toast(err.message);
  }
});

$('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const keyword = $('login-keyword').value;
  if (!state.selectedUserId || !keyword) return;
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: { userId: state.selectedUserId, keyword } });
    state.userName = data.userName || '';
    state.userId = state.selectedUserId;
    await loadVault();
    $('vault-user-name').textContent = state.userName || '';
    state.locked = false;
    loadAutoLockSettings();
    startInactivityTimer();
    showScreen('vault');
    $('password-search').value = '';
    $('note-search').value = '';
    state.passwordFilter = '';
    state.noteFilter = '';
    renderPasswords();
    renderNotes();
  } catch (err) {
    toast(err.message);
  }
});

async function loadVault() {
  const data = await api('/api/vault');
  state.vault = data;
  const check = await api('/api/auth/check');
  state.userName = check.userName;
  if (check.userId) state.userId = check.userId;
}

function loadAutoLockSettings() {
  try {
    const stored = localStorage.getItem(AUTO_LOCK_STORAGE_KEY);
    const minutes = localStorage.getItem(AUTO_LOCK_MINUTES_KEY);
    state.autoLockEnabled = stored === 'true';
    state.autoLockMinutes = minutes ? parseInt(minutes, 10) : 5;
    const toggle = $('auto-lock-toggle');
    const select = $('auto-lock-minutes');
    if (toggle) toggle.checked = state.autoLockEnabled;
    if (select) select.value = String(state.autoLockMinutes);
  } catch (_) {}
}

function startInactivityTimer() {
  stopInactivityTimer();
  if (!state.autoLockEnabled) return;
  const ms = state.autoLockMinutes * 60 * 1000;
  state.inactivityTimerId = setTimeout(() => {
    state.locked = true;
    state.vault = { passwords: [], notes: [] };
    $('lock-user-name').textContent = state.userName || '';
    $('unlock-keyword').value = '';
    $('lock-overlay').classList.remove('hidden');
    stopInactivityTimer();
  }, ms);
}

function stopInactivityTimer() {
  if (state.inactivityTimerId) {
    clearTimeout(state.inactivityTimerId);
    state.inactivityTimerId = null;
  }
}

function resetInactivityTimer() {
  if (state.autoLockEnabled && !state.locked) {
    startInactivityTimer();
  }
}

$('auto-lock-toggle')?.addEventListener('change', (e) => {
  state.autoLockEnabled = e.target.checked;
  localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(state.autoLockEnabled));
  if (state.autoLockEnabled) startInactivityTimer();
  else stopInactivityTimer();
});

$('auto-lock-minutes')?.addEventListener('change', (e) => {
  state.autoLockMinutes = parseInt(e.target.value, 10);
  localStorage.setItem(AUTO_LOCK_MINUTES_KEY, String(state.autoLockMinutes));
  if (state.autoLockEnabled) startInactivityTimer();
});

$('settings-btn')?.addEventListener('click', () => {
  const panel = $('settings-panel');
  if (panel.classList.contains('hidden')) {
    panel.classList.remove('hidden');
    loadAutoLockSettings();
  } else {
    panel.classList.add('hidden');
  }
});

$('lock-btn')?.addEventListener('click', () => {
  state.locked = true;
  state.vault = { passwords: [], notes: [] };
  $('lock-user-name').textContent = state.userName || '';
  $('unlock-keyword').value = '';
  $('lock-overlay').classList.remove('hidden');
  stopInactivityTimer();
});

document.addEventListener('click', (e) => {
  const panel = $('settings-panel');
  if (panel && !panel.classList.contains('hidden') && !panel.contains(e.target) && !$('settings-btn')?.contains(e.target)) {
    panel.classList.add('hidden');
  }
});

$('unlock-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const keyword = $('unlock-keyword').value;
  const userId = state.userId;
  if (!userId || !keyword) return;
  try {
    await api('/api/auth/login', { method: 'POST', body: { userId, keyword } });
    await loadVault();
    state.locked = false;
    $('lock-overlay').classList.add('hidden');
    startInactivityTimer();
    renderPasswords();
    renderNotes();
  } catch (err) {
    toast(err.message);
  }
});

$('unlock-logout')?.addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  state.selectedUserId = null;
  state.userId = null;
  state.vault = { passwords: [], notes: [] };
  state.locked = false;
  $('lock-overlay').classList.add('hidden');
  showScreen('profile');
  loadUsers();
});

$('logout-btn')?.addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  state.selectedUserId = null;
  state.userId = null;
  state.vault = { passwords: [], notes: [] };
  state.locked = false;
  showScreen('profile');
  loadUsers();
});

function setupVaultActivityListeners() {
  const vault = $('vault-screen');
  if (!vault) return;
  const reset = () => resetInactivityTimer();
  vault.addEventListener('click', reset);
  vault.addEventListener('keydown', reset);
  vault.addEventListener('input', reset);
}

$$('.vault-tabs .tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    $$('.vault-tabs .tab').forEach((t) => t.classList.remove('active'));
    $$('#vault-screen .panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    const panel = $(`${tab.dataset.tab}-panel`);
    if (panel) panel.classList.add('active');
  });
});

function filteredPasswords() {
  const q = state.passwordFilter.trim().toLowerCase();
  if (!q) return state.vault.passwords;
  return state.vault.passwords.filter(
    (p) =>
      (p.url && p.url.toLowerCase().includes(q)) ||
      (p.extraInfo && p.extraInfo.toLowerCase().includes(q)) ||
      (p.username && p.username.toLowerCase().includes(q)) ||
      (p.email && p.email.toLowerCase().includes(q))
  );
}

function filteredNotes() {
  const q = state.noteFilter.trim().toLowerCase();
  if (!q) return state.vault.notes;
  return state.vault.notes.filter((n) => (n.title && n.title.toLowerCase().includes(q)) || (n.description && n.description.toLowerCase().includes(q)));
}

function renderPasswords() {
  const list = $('password-list');
  if (!list) return;
  const items = filteredPasswords();
  if (items.length === 0) {
    list.innerHTML = '<div class="empty-state">No passwords yet. Add one or adjust search.</div>';
    return;
  }
  list.innerHTML = items
    .map(
      (p) => `
    <div class="list-item" data-id="${escapeAttr(p.id)}">
      <div class="main">
        <div class="title-row">${p.url ? escapeHtml(p.url) : '(No URL)'}</div>
        <div class="meta">${escapeHtml(p.username || '')} ${p.email ? '· ' + escapeHtml(p.email) : ''}</div>
        ${p.extraInfo ? `<div class="meta">${escapeHtml(p.extraInfo)}</div>` : ''}
        <div class="password-row-inline"><span class="password-display" data-visible="0">••••••••</span></div>
      </div>
      <div class="actions">
        <button type="button" class="small-btn eye-password-btn" title="Show password">👁</button>
        <button type="button" class="small-btn edit-password">Edit</button>
        <button type="button" class="small-btn danger delete-password">Delete</button>
      </div>
    </div>`
    )
    .join('');
  list.querySelectorAll('.eye-password-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.list-item');
      if (!item) return;
      const id = item.dataset.id;
      const p = state.vault.passwords.find((x) => x.id === id);
      const span = item.querySelector('.password-display');
      if (!p || !span) return;
      const visible = span.dataset.visible === '1';
      if (visible) {
        span.textContent = '••••••••';
        span.dataset.visible = '0';
        btn.textContent = '👁';
        btn.title = 'Show password';
      } else {
        span.textContent = p.password || '(none)';
        span.dataset.visible = '1';
        btn.textContent = '🙈';
        btn.title = 'Hide password';
      }
    });
  });
  list.querySelectorAll('.edit-password').forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.list-item');
      if (!item) return;
      const id = item.dataset.id;
      const p = state.vault.passwords.find((x) => x.id === id);
      if (p) openPasswordModal(p);
    });
  });
  list.querySelectorAll('.delete-password').forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.list-item');
      if (!item) return;
      deletePassword(item.dataset.id);
    });
  });
}

function renderNotes() {
  const list = $('note-list');
  if (!list) return;
  const items = filteredNotes();
  if (items.length === 0) {
    list.innerHTML = '<div class="empty-state">No notes yet. Add one or adjust search.</div>';
    return;
  }
  list.innerHTML = items
    .map(
      (n) => `
    <div class="list-item" data-id="${escapeAttr(n.id)}">
      <div class="main">
        <div class="title-row">${escapeHtml(n.title || '(No title)')}</div>
        ${n.description ? `<div class="meta">${escapeHtml(n.description.slice(0, 120))}${n.description.length > 120 ? '…' : ''}</div>` : ''}
      </div>
      <div class="actions">
        <button type="button" class="small-btn edit-note">Edit</button>
        <button type="button" class="small-btn danger delete-note">Delete</button>
      </div>
    </div>`
    )
    .join('');
  list.querySelectorAll('.edit-note').forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.list-item');
      if (!item) return;
      const id = item.dataset.id;
      const n = state.vault.notes.find((x) => x.id === id);
      if (n) openNoteModal(n);
    });
  });
  list.querySelectorAll('.delete-note').forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.list-item');
      if (!item) return;
      deleteNote(item.dataset.id);
    });
  });
}

$('password-search')?.addEventListener('input', () => {
  state.passwordFilter = $('password-search').value;
  renderPasswords();
});

$('note-search')?.addEventListener('input', () => {
  state.noteFilter = $('note-search').value;
  renderNotes();
});

function openPasswordModal(entry = null) {
  const isNew = !entry;
  $('password-modal-title').textContent = isNew ? 'Add password' : 'Edit password';
  $('password-id').value = entry ? entry.id : '';
  $('password-url').value = entry ? entry.url : '';
  $('password-username').value = entry ? entry.username : '';
  $('password-value').value = entry ? entry.password : '';
  $('password-email').value = entry ? entry.email : '';
  $('password-extra').value = entry ? entry.extraInfo : '';
  $('modal-overlay').classList.remove('hidden');
  $$('.modal').forEach((m) => m.classList.add('hidden'));
  $('password-modal').classList.remove('hidden');
}

function openNoteModal(entry = null) {
  const isNew = !entry;
  $('note-modal-title').textContent = isNew ? 'Add note' : 'Edit note';
  $('note-id').value = entry ? entry.id : '';
  $('note-title').value = entry ? entry.title : '';
  $('note-description').value = entry ? entry.description : '';
  $('modal-overlay').classList.remove('hidden');
  $$('.modal').forEach((m) => m.classList.add('hidden'));
  $('note-modal').classList.remove('hidden');
}

$('add-password-btn')?.addEventListener('click', () => openPasswordModal());
$('add-note-btn')?.addEventListener('click', () => openNoteModal());

$('password-cancel')?.addEventListener('click', () => $('modal-overlay').classList.add('hidden'));
$('note-cancel')?.addEventListener('click', () => $('modal-overlay').classList.add('hidden'));

/* Modal only closes via Cancel/Save buttons, not by clicking outside */

document.querySelectorAll('.eye-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const target = $(btn.dataset.target);
    if (!target) return;
    const showing = target.type === 'text';
    target.type = showing ? 'password' : 'text';
    btn.textContent = showing ? '👁' : '🙈';
  });
});

$('generate-password-btn')?.addEventListener('click', async () => {
  try {
    const data = await api('/api/vault/generate-password?length=20');
    $('password-value').value = data.password;
    $('password-value').type = 'text';
    setTimeout(() => { $('password-value').type = 'password'; }, 2000);
  } catch (err) {
    toast(err.message);
  }
});

$('export-backup-btn')?.addEventListener('click', async () => {
  try {
    const res = await fetch('/api/vault/export', { credentials: 'include', method: 'GET' });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d.error || 'Export failed');
    }
    const blob = await res.blob();
    const filename = res.headers.get('Content-Disposition')?.match(/filename="?([^";]+)"?/)?.[1] || `family-vault-backup-${new Date().toISOString().slice(0, 10)}.enc`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Backup downloaded', true);
  } catch (err) {
    toast(err.message);
  }
});

$('import-backup-btn')?.addEventListener('click', () => {
  $('import-backup-file').click();
});

$('import-backup-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  state.pendingImportFile = file;
  $('import-mode-hint').classList.remove('hidden');
  e.target.value = '';
});

function doImport(mode) {
  const file = state.pendingImportFile;
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async () => {
    let dataBase64 = reader.result;
    if (dataBase64.startsWith('data:')) dataBase64 = dataBase64.split(',')[1];
    try {
      await api('/api/vault/import', { method: 'POST', body: { data: dataBase64, mode } });
      state.pendingImportFile = null;
      $('import-mode-hint').classList.add('hidden');
      await loadVault();
      renderPasswords();
      renderNotes();
      toast('Backup imported', true);
    } catch (err) {
      toast(err.message);
    }
  };
  reader.readAsDataURL(file);
}

$('import-mode-replace')?.addEventListener('click', () => doImport('replace'));
$('import-mode-merge')?.addEventListener('click', () => doImport('merge'));

$('import-csv-btn')?.addEventListener('click', () => $('import-csv-file').click());

$('import-csv-file')?.addEventListener('change', async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  e.target.value = '';
  const reader = new FileReader();
  reader.onload = async () => {
    const csv = typeof reader.result === 'string' ? reader.result : '';
    try {
      const data = await api('/api/vault/import-csv', { method: 'POST', body: { csv } });
      await loadVault();
      renderPasswords();
      toast(data.imported ? `Imported ${data.imported} password(s)` : 'No rows imported', true);
    } catch (err) {
      toast(err.message);
    }
  };
  reader.readAsText(file, 'UTF-8');
});

$('password-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = $('password-id').value;
  const body = {
    url: $('password-url').value,
    username: $('password-username').value,
    password: $('password-value').value,
    email: $('password-email').value,
    extraInfo: $('password-extra').value,
  };
  try {
    if (id) {
      await api(`/api/vault/passwords/${id}`, { method: 'PUT', body });
    } else {
      await api('/api/vault/passwords', { method: 'POST', body });
    }
    await loadVault();
    renderPasswords();
    $('modal-overlay').classList.add('hidden');
  } catch (err) {
    toast(err.message);
  }
});

$('note-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = $('note-id').value;
  const body = {
    title: $('note-title').value,
    description: $('note-description').value,
  };
  try {
    if (id) {
      await api(`/api/vault/notes/${id}`, { method: 'PUT', body });
    } else {
      await api('/api/vault/notes', { method: 'POST', body });
    }
    await loadVault();
    renderNotes();
    $('modal-overlay').classList.add('hidden');
  } catch (err) {
    toast(err.message);
  }
});

async function deletePassword(id) {
  if (!confirm('Delete this password entry?')) return;
  try {
    await api(`/api/vault/passwords/${id}`, { method: 'DELETE' });
    await loadVault();
    renderPasswords();
  } catch (err) {
    toast(err.message);
  }
}

async function deleteNote(id) {
  if (!confirm('Delete this note?')) return;
  try {
    await api(`/api/vault/notes/${id}`, { method: 'DELETE' });
    await loadVault();
    renderNotes();
  } catch (err) {
    toast(err.message);
  }
}

const THEME_KEY = 'familyVault_theme';

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem(THEME_KEY, theme);
  const icon = theme === 'light' ? '🌙' : '☀';
  const profileBtn = $('theme-toggle-profile');
  const vaultBtn = $('theme-toggle-vault');
  if (profileBtn) profileBtn.textContent = icon;
  if (vaultBtn) vaultBtn.textContent = icon;
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

(function initTheme() {
  const saved = localStorage.getItem(THEME_KEY) || 'dark';
  applyTheme(saved);
})();

$('theme-toggle-profile')?.addEventListener('click', toggleTheme);
$('theme-toggle-vault')?.addEventListener('click', toggleTheme);

async function init() {
  const check = await api('/api/auth/check');
  if (check.authenticated) {
    state.userName = check.userName;
    state.userId = check.userId;
    await loadVault();
    $('vault-user-name').textContent = state.userName || '';
    loadAutoLockSettings();
    startInactivityTimer();
    setupVaultActivityListeners();
    showScreen('vault');
    renderPasswords();
    renderNotes();
  } else {
    await loadUsers();
    showScreen('profile');
  }
  updateKeywordRequirements($('create-keyword')?.value || '');
}

init().catch(() => {
  loadUsers().then(() => showScreen('profile'));
});
