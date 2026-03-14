const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const {
  ensureDataDir,
  getUsers,
  saveUsers,
  hashKeyword,
  verifyKeyword,
  getVault,
  saveVault,
  generateStrongPassword,
} = require('./crypto-utils');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_LOCK_MS = 10 * 60 * 1000;
const loginAttempts = new Map();

ensureDataDir();

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId || !req.session.keyword) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

function loginKey(req, userId) {
  return `${req.ip || 'unknown'}:${userId || 'unknown'}`;
}

function getLoginState(req, userId) {
  const key = loginKey(req, userId);
  const state = loginAttempts.get(key);
  if (!state) return { key, count: 0, firstFailAt: 0, lockUntil: 0 };
  return { key, ...state };
}

function recordFailedLogin(req, userId) {
  const now = Date.now();
  const { key, count, firstFailAt } = getLoginState(req, userId);
  const withinWindow = firstFailAt && now - firstFailAt <= LOGIN_WINDOW_MS;
  const nextCount = withinWindow ? count + 1 : 1;
  const nextFirst = withinWindow ? firstFailAt : now;
  const nextState = {
    count: nextCount,
    firstFailAt: nextFirst,
    lockUntil: nextCount >= MAX_LOGIN_ATTEMPTS ? now + LOGIN_LOCK_MS : 0,
  };
  loginAttempts.set(key, nextState);
  return nextState;
}

function clearFailedLogins(req, userId) {
  loginAttempts.delete(loginKey(req, userId));
}

app.get('/api/users', (req, res) => {
  const users = getUsers().map((u) => ({ id: u.id, name: u.name }));
  res.json({ users });
});

app.post('/api/users', (req, res) => {
  const { name, keyword } = req.body;
  if (!name || typeof name !== 'string' || !keyword || typeof keyword !== 'string') {
    return res.status(400).json({ error: 'Name and keyword are required' });
  }
  const trimmedName = name.trim();
  if (!trimmedName) return res.status(400).json({ error: 'Name cannot be empty' });
  if (keyword.length < 4) return res.status(400).json({ error: 'Keyword must be at least 4 characters' });

  const users = getUsers();
  if (users.some((u) => u.name.toLowerCase() === trimmedName.toLowerCase())) {
    return res.status(409).json({ error: 'A profile with this name already exists' });
  }

  const id = crypto.randomUUID();
  const { salt, hash } = hashKeyword(keyword);
  users.push({ id, name: trimmedName, salt, hash });
  saveUsers(users);

  const vault = { passwords: [], notes: [] };
  saveVault(id, keyword, vault);

  res.status(201).json({ user: { id, name: trimmedName } });
});

app.post('/api/auth/login', (req, res) => {
  const { userId, keyword } = req.body;
  if (!userId || !keyword) return res.status(400).json({ error: 'userId and keyword are required' });
  const now = Date.now();
  const { lockUntil } = getLoginState(req, userId);
  if (lockUntil && now < lockUntil) {
    const waitSec = Math.ceil((lockUntil - now) / 1000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${waitSec} seconds.` });
  }

  const users = getUsers();
  const user = users.find((u) => u.id === userId);
  if (!user) return res.status(404).json({ error: 'Profile not found' });
  if (!verifyKeyword(keyword, user.salt, user.hash)) {
    recordFailedLogin(req, userId);
    return res.status(401).json({ error: 'Wrong keyword' });
  }
  clearFailedLogins(req, userId);

  req.session.userId = userId;
  req.session.userName = user.name;
  req.session.keyword = keyword;
  res.json({ success: true, userName: user.name });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {});
  res.json({ success: true });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session && req.session.userId && req.session.keyword) {
    return res.json({ authenticated: true, userName: req.session.userName });
  }
  res.json({ authenticated: false });
});

app.get('/api/vault', requireAuth, (req, res) => {
  try {
    const vault = getVault(req.session.userId, req.session.keyword);
    res.json(vault);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to load vault' });
  }
});

app.post('/api/vault/passwords', requireAuth, (req, res) => {
  const { url, username, password, email, extraInfo } = req.body || {};
  const entry = {
    id: crypto.randomUUID(),
    url: String(url ?? '').trim(),
    username: String(username ?? '').trim(),
    password: String(password ?? ''),
    email: String(email ?? '').trim(),
    extraInfo: String(extraInfo ?? '').trim(),
  };
  let vault = getVault(req.session.userId, req.session.keyword);
  vault.passwords.push(entry);
  saveVault(req.session.userId, req.session.keyword, vault);
  res.status(201).json(entry);
});

app.put('/api/vault/passwords/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { url, username, password, email, extraInfo } = req.body || {};
  let vault = getVault(req.session.userId, req.session.keyword);
  const idx = vault.passwords.findIndex((p) => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Password entry not found' });
  vault.passwords[idx] = {
    ...vault.passwords[idx],
    url: String(url ?? vault.passwords[idx].url).trim(),
    username: String(username ?? vault.passwords[idx].username).trim(),
    password: String(password ?? vault.passwords[idx].password),
    email: String(email ?? vault.passwords[idx].email).trim(),
    extraInfo: String(extraInfo ?? vault.passwords[idx].extraInfo).trim(),
  };
  saveVault(req.session.userId, req.session.keyword, vault);
  res.json(vault.passwords[idx]);
});

app.delete('/api/vault/passwords/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  let vault = getVault(req.session.userId, req.session.keyword);
  const before = vault.passwords.length;
  vault.passwords = vault.passwords.filter((p) => p.id !== id);
  if (vault.passwords.length === before) return res.status(404).json({ error: 'Password entry not found' });
  saveVault(req.session.userId, req.session.keyword, vault);
  res.json({ success: true });
});

app.post('/api/vault/notes', requireAuth, (req, res) => {
  const { title, description } = req.body || {};
  const entry = {
    id: crypto.randomUUID(),
    title: String(title ?? '').trim(),
    description: String(description ?? ''),
  };
  let vault = getVault(req.session.userId, req.session.keyword);
  vault.notes.push(entry);
  saveVault(req.session.userId, req.session.keyword, vault);
  res.status(201).json(entry);
});

app.put('/api/vault/notes/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body || {};
  let vault = getVault(req.session.userId, req.session.keyword);
  const idx = vault.notes.findIndex((n) => n.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Note not found' });
  vault.notes[idx] = {
    ...vault.notes[idx],
    title: String(title ?? vault.notes[idx].title).trim(),
    description: String(description ?? vault.notes[idx].description),
  };
  saveVault(req.session.userId, req.session.keyword, vault);
  res.json(vault.notes[idx]);
});

app.delete('/api/vault/notes/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  let vault = getVault(req.session.userId, req.session.keyword);
  const before = vault.notes.length;
  vault.notes = vault.notes.filter((n) => n.id !== id);
  if (vault.notes.length === before) return res.status(404).json({ error: 'Note not found' });
  saveVault(req.session.userId, req.session.keyword, vault);
  res.json({ success: true });
});

app.get('/api/vault/generate-password', requireAuth, (req, res) => {
  const length = Math.min(64, Math.max(12, parseInt(req.query.length, 10) || 20));
  res.json({ password: generateStrongPassword(length) });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Family Vault running at http://0.0.0.0:${PORT}`);
  console.log(`On Tailscale/LAN use your device IP and port ${PORT}`);
});
