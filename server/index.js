const express = require('express');
const cors = require('cors');
const Redis = require('ioredis');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '15mb' }));
app.use(cors());

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(salt + ':' + derivedKey.toString('hex'));
    });
  });
}
function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    const parts = (storedHash || '').split(':');
    if (parts.length !== 2) return resolve(false);
    const [salt, key] = parts;
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      const keyBuf = Buffer.from(key, 'hex');
      if (keyBuf.length !== derivedKey.length) return resolve(false);
      resolve(crypto.timingSafeEqual(keyBuf, derivedKey));
    });
  });
}

const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_KEY_VALUE_URL;
if (!REDIS_URL) {
  console.error('FATAL: No REDIS_URL / RENDER_KEY_VALUE_URL environment variable set.');
  process.exit(1);
}
const redis = new Redis(REDIS_URL);
redis.on('error', (err) => { console.error('Redis connection error:', err.message); });

// ============ Data key whitelist (existing dashboard data) ============
const ALLOWED_KEYS = new Set([
  'labor-weeks',
  'ldEstimateClients',
  'labor-employee-rates',
  'labor-last-admin-gross',
  'fleet-trucks',
  'fleet-maintenance-logs',
  'paperwork-signed-records',
  'attendance-records',
  'paperwork-uploads',
  'paperwork-job-archive',
  'compliance-business-authorizations',
  'compliance-truck-dot-inspections',
  'compliance-truck-safety-incidents',
  'compliance-truck-violations',
  'compliance-drivers',
  'settings-config-files',
  'settings-handoff-guide'
]);
const ALLOWED_KEY_PREFIXES = ['fleet-invoice-', 'paperwork-job-link-', 'paperwork-upload-', 'compliance-doc-', 'settings-config-doc-'];

function isAllowedKey(key) {
  if (ALLOWED_KEYS.has(key)) return true;
  return ALLOWED_KEY_PREFIXES.some(prefix => key.startsWith(prefix));
}

// ============ Auth: user accounts (stored separately, never exposed via /api/data) ============
const USERS_KEY = 'auth:users';
const SESSION_PREFIX = 'auth:session:';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

const SEED_USERS = [
  { email: 'aaron.henson@chhj.com', role: 'admin' },
  { email: 'administrative.assistantaug@chhj.com', role: 'user' }
];
const TEMP_PASSWORD = 'Password123!';

async function ensureUsersSeeded() {
  try {
    const raw = await redis.get(USERS_KEY);
    let users = raw ? JSON.parse(raw) : {};
    let changed = false;
    for (const seed of SEED_USERS) {
      if (!users[seed.email]) {
        const passwordHash = await hashPassword(TEMP_PASSWORD);
        users[seed.email] = { passwordHash, mustReset: true, role: seed.role };
        changed = true;
      } else if (!users[seed.email].role) {
        // Migrate accounts created before roles existed.
        users[seed.email].role = seed.role;
        changed = true;
      }
    }
    if (changed) {
      await redis.set(USERS_KEY, JSON.stringify(users));
      console.log('Seeded/migrated default user accounts.');
    }
  } catch (err) {
    console.error('User seeding failed:', err.message);
  }
}

async function getUsers() {
  const raw = await redis.get(USERS_KEY);
  return raw ? JSON.parse(raw) : {};
}
async function saveUsers(users) {
  await redis.set(USERS_KEY, JSON.stringify(users));
}

// Simple in-memory rate limiting for login attempts (per IP).
const loginAttempts = new Map(); // ip -> [timestamps]
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
function isRateLimited(ip) {
  const now = Date.now();
  const attempts = (loginAttempts.get(ip) || []).filter(t => now - t < LOGIN_WINDOW_MS);
  loginAttempts.set(ip, attempts);
  return attempts.length >= LOGIN_MAX_ATTEMPTS;
}
function recordLoginAttempt(ip) {
  const attempts = loginAttempts.get(ip) || [];
  attempts.push(Date.now());
  loginAttempts.set(ip, attempts);
}

app.post('/api/login', async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many login attempts. Try again in a few minutes.' });
  }
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  try {
    const users = await getUsers();
    const user = users[email.toLowerCase().trim()];
    recordLoginAttempt(ip);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const match = await verifyPassword(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    await redis.set(SESSION_PREFIX + token, email.toLowerCase().trim(), 'EX', SESSION_TTL_SECONDS);
    res.json({ token, mustReset: !!user.mustReset, role: user.role || 'user' });
  } catch (err) {
    console.error('Login failed:', err.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/change-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  try {
    const email = await redis.get(SESSION_PREFIX + token);
    if (!email) return res.status(401).json({ error: 'Session expired \u2014 please log in again.' });
    const users = await getUsers();
    if (!users[email]) return res.status(401).json({ error: 'Account not found.' });
    users[email].passwordHash = await hashPassword(newPassword);
    users[email].mustReset = false;
    await saveUsers(users);
    res.json({ ok: true });
  } catch (err) {
    console.error('Password change failed:', err.message);
    res.status(500).json({ error: 'Password change failed.' });
  }
});

app.post('/api/logout', async (req, res) => {
  const { token } = req.body || {};
  if (token) {
    try { await redis.del(SESSION_PREFIX + token); } catch (err) { console.error('Logout failed:', err.message); }
  }
  res.json({ ok: true });
});

// ============ Auth middleware: require a valid session for all data routes ============
async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    const email = await redis.get(SESSION_PREFIX + token);
    if (!email) return res.status(401).json({ error: 'Session expired \u2014 please log in again.' });
    req.userEmail = email;
    next();
  } catch (err) {
    console.error('Auth check failed:', err.message);
    res.status(500).json({ error: 'Auth check failed.' });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const users = await getUsers();
    const user = users[req.userEmail];
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
  } catch (err) {
    console.error('Admin check failed:', err.message);
    res.status(500).json({ error: 'Admin check failed.' });
  }
}

// List users -- any logged-in user can see the roster (matches the existing
// "Manage Documents" style visibility elsewhere in the app), but only admins
// can add new ones.
app.get('/api/admin/users', requireAuth, async (req, res) => {
  try {
    const users = await getUsers();
    const list = Object.keys(users).map(email => ({
      email,
      role: users[email].role || 'user',
      mustReset: !!users[email].mustReset
    }));
    res.json({ users: list });
  } catch (err) {
    console.error('User list failed:', err.message);
    res.status(500).json({ error: 'Could not load users.' });
  }
});

app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { email, role } = req.body || {};
  const cleanEmail = (email || '').toLowerCase().trim();
  if (!cleanEmail || !cleanEmail.includes('@')) {
    return res.status(400).json({ error: 'A valid email is required.' });
  }
  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({ error: 'Role must be "admin" or "user".' });
  }
  try {
    const users = await getUsers();
    if (users[cleanEmail]) {
      return res.status(400).json({ error: 'That user already exists.' });
    }
    const passwordHash = await hashPassword(TEMP_PASSWORD);
    users[cleanEmail] = { passwordHash, mustReset: true, role };
    await saveUsers(users);
    res.json({ ok: true, email: cleanEmail, tempPassword: TEMP_PASSWORD });
  } catch (err) {
    console.error('Add user failed:', err.message);
    res.status(500).json({ error: 'Could not add user.' });
  }
});

app.get('/health', async (req, res) => {
  try {
    await redis.ping();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) return res.status(400).json({ error: 'Unknown key.' });
  try {
    const value = await redis.get(key);
    res.json({ key, value: value === null ? null : JSON.parse(value) });
  } catch (err) {
    console.error(`GET /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage read failed.' });
  }
});

app.put('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) return res.status(400).json({ error: 'Unknown key.' });
  try {
    await redis.set(key, JSON.stringify(req.body.value));
    res.json({ key, ok: true });
  } catch (err) {
    console.error(`PUT /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage write failed.' });
  }
});

app.delete('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) return res.status(400).json({ error: 'Unknown key.' });
  try {
    await redis.del(key);
    res.json({ key, ok: true });
  } catch (err) {
    console.error(`DELETE /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage delete failed.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`Henson dashboard backend listening on port ${PORT}`);
  await ensureUsersSeeded();
});
 
