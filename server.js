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
  encryptVaultToBackup,
  decryptBackupToVault,
  resetUserKeyword,
} = require('./crypto-utils');

const KEYWORD_MIN_LENGTH = 8;
const KEYWORD_RULES = {
  minLength: KEYWORD_MIN_LENGTH,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSymbol: true,
};
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

function validateKeywordStrong(keyword) {
  if (typeof keyword !== 'string') return { valid: false, error: 'Keyword is required' };
  if (keyword.length < KEYWORD_MIN_LENGTH) {
    return { valid: false, error: `Keyword must be at least ${KEYWORD_MIN_LENGTH} characters` };
  }
  if (KEYWORD_RULES.requireUppercase && !/[A-Z]/.test(keyword)) {
    return { valid: false, error: 'Keyword must contain at least one uppercase letter' };
  }
  if (KEYWORD_RULES.requireLowercase && !/[a-z]/.test(keyword)) {
    return { valid: false, error: 'Keyword must contain at least one lowercase letter' };
  }
  if (KEYWORD_RULES.requireNumber && !/\d/.test(keyword)) {
    return { valid: false, error: 'Keyword must contain at least one number' };
  }
  if (KEYWORD_RULES.requireSymbol) {
    const hasSymbol = [...SYMBOLS].some((s) => keyword.includes(s));
    if (!hasSymbol) return { valid: false, error: 'Keyword must contain at least one symbol (!@#$%^&* etc.)' };
  }
  return { valid: true, error: null };
}

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_LOCK_MS = 10 * 60 * 1000;
const loginAttempts = new Map();

ensureDataDir();

app.use(express.json({ limit: '15mb' }));
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
  const kwValidation = validateKeywordStrong(keyword);
  if (!kwValidation.valid) return res.status(400).json({ error: kwValidation.error });

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
    return res.json({ authenticated: true, userName: req.session.userName, userId: req.session.userId });
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

app.post('/api/keyword/validate', (req, res) => {
  const { keyword } = req.body || {};
  const result = validateKeywordStrong(keyword);
  res.json({ valid: result.valid, error: result.error, rules: KEYWORD_RULES });
});

app.get('/api/vault/export', requireAuth, (req, res) => {
  try {
    const vault = getVault(req.session.userId, req.session.keyword);
    const encrypted = encryptVaultToBackup(vault, req.session.keyword);
    const filename = `family-vault-backup-${new Date().toISOString().slice(0, 10)}.enc`;
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(encrypted);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Export failed' });
  }
});

app.post('/api/vault/import', requireAuth, (req, res) => {
  const { data: dataBase64, mode } = req.body || {};
  if (!dataBase64 || typeof dataBase64 !== 'string') {
    return res.status(400).json({ error: 'Backup file data is required' });
  }
  const modeOk = mode === 'replace' || mode === 'merge';
  if (!modeOk) return res.status(400).json({ error: 'Mode must be "replace" or "merge"' });
  try {
    const raw = Buffer.from(dataBase64, 'base64').toString('utf8');
    const imported = decryptBackupToVault(raw, req.session.keyword);
    let vault = getVault(req.session.userId, req.session.keyword);
    if (mode === 'replace') {
      vault = { passwords: imported.passwords, notes: imported.notes };
    } else {
      const existingIds = new Set([
        ...vault.passwords.map((p) => p.id),
        ...vault.notes.map((n) => n.id),
      ]);
      const newPasswords = imported.passwords.filter((p) => !existingIds.has(p.id));
      const newNotes = imported.notes.filter((n) => !existingIds.has(n.id));
      vault = {
        passwords: [...vault.passwords, ...newPasswords],
        notes: [...vault.notes, ...newNotes],
      };
    }
    saveVault(req.session.userId, req.session.keyword, vault);
    res.json({ success: true, vault: { passwords: vault.passwords.length, notes: vault.notes.length } });
  } catch (e) {
    res.status(400).json({ error: 'Invalid or corrupted backup file, or wrong keyword' });
  }
});

/** Parse CSV line respecting quoted fields (e.g. "a,b",c) */
function parseCSVLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if ((c === ',' && !inQuotes) || (c === '\r' && !inQuotes)) {
      out.push(cur.trim());
      cur = '';
    } else if (c !== '\r') {
      cur += c;
    }
  }
  out.push(cur.trim());
  return out;
}

/** Import passwords from Brave/Chrome CSV export. Expects header: name,url,username,password or url,username,password */
app.post('/api/vault/import-csv', requireAuth, (req, res) => {
  const { csv } = req.body || {};
  if (!csv || typeof csv !== 'string') {
    return res.status(400).json({ error: 'CSV content is required' });
  }
  const lines = csv.split(/\n/).filter((l) => l.trim());
  if (lines.length < 2) {
    return res.status(400).json({ error: 'CSV must have a header row and at least one data row' });
  }
  const header = parseCSVLine(lines[0]).map((h) => h.toLowerCase().replace(/\s/g, '_'));
  const urlIdx = header.findIndex((h) => h === 'url' || h === 'login_uri' || h === 'origin' || h === 'website');
  const userIdx = header.findIndex((h) => h === 'username' || h === 'login' || h === 'user');
  const passIdx = header.findIndex((h) => h === 'password');
  const nameIdx = header.findIndex((h) => h === 'name' || h === 'title');
  if (passIdx === -1) {
    return res.status(400).json({ error: 'CSV must have a "password" column (Brave/Chrome export has name,url,username,password)' });
  }
  let vault = getVault(req.session.userId, req.session.keyword);
  let added = 0;
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCSVLine(lines[i]);
    if (cells.length < header.length) continue;
    const url = (urlIdx >= 0 ? cells[urlIdx] : '') || '';
    const username = (userIdx >= 0 ? cells[userIdx] : '') || '';
    const password = (passIdx >= 0 ? cells[passIdx] : '') || '';
    const extraInfo = (nameIdx >= 0 ? cells[nameIdx] : '') || '';
    vault.passwords.push({
      id: crypto.randomUUID(),
      url: String(url).trim(),
      username: String(username).trim(),
      password: String(password),
      email: '',
      extraInfo: String(extraInfo).trim(),
    });
    added++;
  }
  saveVault(req.session.userId, req.session.keyword, vault);
  res.json({ success: true, imported: added });
});

/* Dev-only: reset a profile's keyword (wipes vault; old data is unrecoverable). Only available when DEV_RECOVERY_SECRET is set. */
if (process.env.DEV_RECOVERY_SECRET) {
  app.post('/api/dev/reset-profile', (req, res) => {
    const { secret, userId, newKeyword } = req.body || {};
    if (secret !== process.env.DEV_RECOVERY_SECRET) {
      return res.status(403).json({ error: 'Invalid secret' });
    }
    if (!userId || !newKeyword) {
      return res.status(400).json({ error: 'userId and newKeyword are required' });
    }
    const kwValidation = validateKeywordStrong(newKeyword);
    if (!kwValidation.valid) {
      return res.status(400).json({ error: kwValidation.error });
    }
    try {
      resetUserKeyword(userId, newKeyword);
      res.json({ success: true, message: 'Profile reset. They can log in with the new keyword. Vault is empty.' });
    } catch (e) {
      res.status(400).json({ error: e.message || 'Reset failed' });
    }
  });
}

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Family Vault running at http://0.0.0.0:${PORT}`);
  console.log(`On Tailscale/LAN use your device IP and port ${PORT}`);
});
