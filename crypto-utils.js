const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const VAULTS_DIR = path.join(__dirname, 'data', 'vaults');
const SALT_LENGTH = 32;
const SCRYPT_KEYLEN = 64;
const VAULT_KEYLEN = 32;
const VAULT_SALT_LENGTH = 16;
const GCM_IV_LENGTH = 12;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1 };

function ensureDataDir() {
  if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  if (!fs.existsSync(VAULTS_DIR)) fs.mkdirSync(VAULTS_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
  }
}

function getUsers() {
  ensureDataDir();
  const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  return data.users || [];
}

function saveUsers(users) {
  ensureDataDir();
  fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2));
}

function hashKeyword(keyword) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const hash = crypto.scryptSync(keyword, salt, SCRYPT_KEYLEN, SCRYPT_OPTIONS);
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}

function verifyKeyword(keyword, saltB64, hashB64) {
  const salt = Buffer.from(saltB64, 'base64');
  const storedHash = Buffer.from(hashB64, 'base64');
  const computed = crypto.scryptSync(keyword, salt, SCRYPT_KEYLEN, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(storedHash, computed);
}

function deriveVaultKey(keyword, salt) {
  return crypto.scryptSync(keyword, salt, VAULT_KEYLEN, SCRYPT_OPTIONS);
}

function xorCrypt(data, keyword) {
  const dataBuf = Buffer.from(data, 'utf8');
  const keyBuf = Buffer.from(keyword, 'utf8');
  if (keyBuf.length === 0) throw new Error('Keyword cannot be empty');
  const out = Buffer.alloc(dataBuf.length);
  for (let i = 0; i < dataBuf.length; i++) {
    out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length];
  }
  return out.toString('base64');
}

function xorDecrypt(base64Data, keyword) {
  const dataBuf = Buffer.from(base64Data, 'base64');
  const keyBuf = Buffer.from(keyword, 'utf8');
  if (keyBuf.length === 0) throw new Error('Keyword cannot be empty');
  const out = Buffer.alloc(dataBuf.length);
  for (let i = 0; i < dataBuf.length; i++) {
    out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length];
  }
  return out.toString('utf8');
}

function encryptVaultData(plainText, keyword) {
  const salt = crypto.randomBytes(VAULT_SALT_LENGTH);
  const iv = crypto.randomBytes(GCM_IV_LENGTH);
  const key = deriveVaultKey(keyword, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 2,
    alg: 'aes-256-gcm',
    kdf: 'scrypt',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: encrypted.toString('base64'),
  });
}

function tryDecryptVaultData(raw, keyword) {
  const trimmed = raw.trim();
  if (!trimmed) return { plainText: '', legacyXor: false };

  if (trimmed.startsWith('{')) {
    const payload = JSON.parse(trimmed);
    if (payload && payload.v === 2 && payload.alg === 'aes-256-gcm' && payload.kdf === 'scrypt') {
      const salt = Buffer.from(payload.salt, 'base64');
      const iv = Buffer.from(payload.iv, 'base64');
      const tag = Buffer.from(payload.tag, 'base64');
      const data = Buffer.from(payload.data, 'base64');
      const key = deriveVaultKey(keyword, salt);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
      return { plainText: decrypted, legacyXor: false };
    }
  }

  return { plainText: xorDecrypt(trimmed, keyword), legacyXor: true };
}

function getVaultPath(userId) {
  const safe = userId.replace(/[^a-zA-Z0-9-_]/g, '');
  return path.join(VAULTS_DIR, `${safe}.json`);
}

function readVaultEncrypted(userId) {
  const vaultPath = getVaultPath(userId);
  if (!fs.existsSync(vaultPath)) return null;
  return fs.readFileSync(vaultPath, 'utf8');
}

function writeVaultEncrypted(userId, encryptedBase64) {
  ensureDataDir();
  fs.writeFileSync(getVaultPath(userId), encryptedBase64);
}

function getVault(userId, keyword) {
  const raw = readVaultEncrypted(userId);
  if (!raw || raw.trim() === '') {
    return { passwords: [], notes: [] };
  }
  try {
    const { plainText, legacyXor } = tryDecryptVaultData(raw, keyword);
    const json = plainText;
    const vault = JSON.parse(json);
    if (legacyXor) {
      writeVaultEncrypted(userId, encryptVaultData(json, keyword));
    }
    return {
      passwords: Array.isArray(vault.passwords) ? vault.passwords : [],
      notes: Array.isArray(vault.notes) ? vault.notes : [],
    };
  } catch (e) {
    throw new Error('Invalid keyword or corrupted vault');
  }
}

function saveVault(userId, keyword, vault) {
  const json = JSON.stringify({
    passwords: vault.passwords || [],
    notes: vault.notes || [],
  });
  writeVaultEncrypted(userId, encryptVaultData(json, keyword));
}

function generateStrongPassword(length = 20) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  const bytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

function encryptVaultToBackup(vault, keyword) {
  const json = JSON.stringify({
    passwords: vault.passwords || [],
    notes: vault.notes || [],
  });
  return encryptVaultData(json, keyword);
}

function decryptBackupToVault(raw, keyword) {
  const { plainText } = tryDecryptVaultData(raw, keyword);
  if (!plainText) return { passwords: [], notes: [] };
  const vault = JSON.parse(plainText);
  return {
    passwords: Array.isArray(vault.passwords) ? vault.passwords : [],
    notes: Array.isArray(vault.notes) ? vault.notes : [],
  };
}

/**
 * Dev recovery only: reset a user's keyword and wipe their vault.
 * Old vault data cannot be recovered. Use when someone forgets their keyword.
 */
function resetUserKeyword(userId, newKeyword) {
  const users = getUsers();
  const idx = users.findIndex((u) => u.id === userId);
  if (idx === -1) throw new Error('User not found');
  const { salt, hash } = hashKeyword(newKeyword);
  users[idx] = { ...users[idx], salt, hash };
  saveUsers(users);
  const vaultPath = getVaultPath(userId);
  if (fs.existsSync(vaultPath)) fs.unlinkSync(vaultPath);
  saveVault(userId, newKeyword, { passwords: [], notes: [] });
}

module.exports = {
  ensureDataDir,
  getUsers,
  saveUsers,
  hashKeyword,
  verifyKeyword,
  getVault,
  saveVault,
  readVaultEncrypted,
  writeVaultEncrypted,
  getVaultPath,
  generateStrongPassword,
  encryptVaultToBackup,
  decryptBackupToVault,
  resetUserKeyword,
};
