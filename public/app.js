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

let state = {
  users: [],
  selectedUserId: null,
  vault: { passwords: [], notes: [] },
  passwordFilter: '',
  noteFilter: '',
};

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
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

function toast(msg) {
  const el = document.createElement('div');
  el.className = 'error-toast';
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
        `<button type="button" class="profile-card" data-user-id="${u.id}" data-user-name="${escapeAttr(u.name)}">${escapeHtml(u.name)}</button>`
    )
    .join('');
  list.querySelectorAll('.profile-card').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedUserId = btn.dataset.userId;
      $('auth-user-name').textContent = btn.dataset.userName || '';
      $('login-keyword').value = '';
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
  showScreen('createUser');
  setTimeout(() => $('create-name').focus(), 100);
});

$('create-back')?.addEventListener('click', () => showScreen('profile'));

$('create-user-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('create-name').value.trim();
  const keyword = $('create-keyword').value;
  if (!name || !keyword) return;
  try {
    await api('/api/users', { method: 'POST', body: { name, keyword } });
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

$('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const keyword = $('login-keyword').value;
  if (!state.selectedUserId || !keyword) return;
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: { userId: state.selectedUserId, keyword } });
    state.userName = data.userName || '';
    await loadVault();
    $('vault-user-name').textContent = state.userName || '';
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
}

$('logout-btn')?.addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  state.selectedUserId = null;
  state.vault = { passwords: [], notes: [] };
  showScreen('profile');
  loadUsers();
});

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
      </div>
      <div class="actions">
        <button type="button" class="small-btn edit-password">Edit</button>
        <button type="button" class="small-btn danger delete-password">Delete</button>
      </div>
    </div>`
    )
    .join('');
  list.querySelectorAll('.edit-password').forEach((btn) => {
    const item = btn.closest('.list-item');
    if (!item) return;
    const id = item.dataset.id;
    const p = state.vault.passwords.find((x) => x.id === id);
    if (p) openPasswordModal(p);
  });
  list.querySelectorAll('.delete-password').forEach((btn) => {
    const item = btn.closest('.list-item');
    if (!item) return;
    deletePassword(item.dataset.id);
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
    const item = btn.closest('.list-item');
    if (!item) return;
    const id = item.dataset.id;
    const n = state.vault.notes.find((x) => x.id === id);
    if (n) openNoteModal(n);
  });
  list.querySelectorAll('.delete-note').forEach((btn) => {
    const item = btn.closest('.list-item');
    if (!item) return;
    deleteNote(item.dataset.id);
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

$('modal-overlay')?.addEventListener('click', (e) => {
  if (e.target === $('modal-overlay')) $('modal-overlay').classList.add('hidden');
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

async function init() {
  const check = await api('/api/auth/check');
  if (check.authenticated) {
    state.userName = check.userName;
    await loadVault();
    $('vault-user-name').textContent = state.userName || '';
    showScreen('vault');
    renderPasswords();
    renderNotes();
  } else {
    await loadUsers();
    showScreen('profile');
  }
}

init().catch(() => {
  loadUsers().then(() => showScreen('profile'));
});
