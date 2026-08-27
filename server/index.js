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
  'settings-handoff-guide',
  'mail-marketing-list'
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

// Employee names (not the financial payroll details) are needed by
// Attendance Tracking and Regulatory Compliance's Drivers section, which
// aren't restricted to admins -- so this computes just the name list from
// the most recent payroll week, without exposing gross pay, taxes, or hours.
app.get('/api/roster', requireAuth, async (req, res) => {
  try {
    const raw = await redis.get('labor-weeks');
    const weeks = raw ? JSON.parse(raw) : [];
    if (!weeks.length) return res.json({ names: [] });
    const sorted = [...weeks].sort((a, b) => (b.weekStart || '').localeCompare(a.weekStart || ''));
    const mostRecent = sorted[0];
    const names = (mostRecent.employees || []).map(e => e.name).filter(Boolean);
    res.json({ names });
  } catch (err) {
    console.error('Roster fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load roster.' });
  }
});

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

// Payroll data is sensitive. The two vestigial rate/gross keys are fully
// admin-only (nothing currently reads or writes them, but they're locked
// down if that changes). labor-weeks is different: any logged-in user can
// see the aggregate weekly numbers (revenue, labor cost, gauge, trends), but
// only admins can upload/edit/delete a week, and non-admins never receive
// the per-employee ADP breakdown -- that's stripped out below before the
// response goes out, not just hidden in the UI.
const ADMIN_ONLY_KEYS = new Set(['labor-employee-rates', 'labor-last-admin-gross']);
const ADMIN_WRITE_ONLY_KEYS = new Set(['labor-weeks']);

async function isRequestingUserAdmin(req) {
  const users = await getUsers();
  const user = users[req.userEmail];
  return !!(user && user.role === 'admin');
}

async function checkAdminOnlyKey(req, res, key) {
  if (!ADMIN_ONLY_KEYS.has(key)) return true;
  try {
    if (!(await isRequestingUserAdmin(req))) {
      res.status(403).json({ error: 'Admin access required.' });
      return false;
    }
    return true;
  } catch (err) {
    console.error('Admin-only key check failed:', err.message);
    res.status(500).json({ error: 'Permission check failed.' });
    return false;
  }
}

async function checkAdminWriteOnlyKey(req, res, key) {
  if (!ADMIN_WRITE_ONLY_KEYS.has(key)) return true;
  try {
    if (!(await isRequestingUserAdmin(req))) {
      res.status(403).json({ error: 'Admin access required.' });
      return false;
    }
    return true;
  } catch (err) {
    console.error('Admin write-only key check failed:', err.message);
    res.status(500).json({ error: 'Permission check failed.' });
    return false;
  }
}

// Local market cities to try, in addition to whatever city is already
// stored, when looking up a zip. Lob's US Verification API requires either
// a zip_code or both city AND state -- state alone isn't enough -- so a
// wrong or missing stored city means we have to guess and check rather than
// ask Lob to resolve the city from the address alone.
const MAIL_CANDIDATE_CITIES = ['Augusta', 'Evans', 'Grovetown', 'Martinez'];

function mailTitleCase(str){
  return str ? str.replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()) : '';
}

// Looks up the correct city, state, and zip code for a given street address
// using Lob's US Address Verification API (CASS-certified), so the Mail
// Marketing List tile can fill in zips automatically -- and correct a wrong
// city -- for addresses pasted without one. Since Lob requires a city guess
// (when there's no zip to search with), this tries the given city first,
// then a short list of local candidate cities, stopping at the first
// deliverable match. Requires the LOB_API_KEY environment variable (a Lob
// "live" secret key) to be set; address verification only works with a live
// key, not a test key.
app.post('/api/lookup-zip', requireAuth, async (req, res) => {
  const { address, city, state } = req.body || {};
  if (!address || !state) {
    return res.status(400).json({ error: 'address and state are required.' });
  }
  const apiKey = process.env.LOB_API_KEY;
  if (!apiKey) {
    console.error('Zip lookup requested but LOB_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Zip lookup is not configured on the server yet (LOB_API_KEY is missing).' });
  }

  const candidates = [];
  if (city) candidates.push(city);
  for (const c of MAIL_CANDIDATE_CITIES) {
    if (!candidates.some(existing => existing.toLowerCase() === c.toLowerCase())) candidates.push(c);
  }

  let anySuccessfulCall = false;
  let lastHttpError = null;
  try {
    for (const cityGuess of candidates) {
      const params = new URLSearchParams({ primary_line: address, city: cityGuess, state: state });
      const lobRes = await fetch('https://api.lob.com/v1/us_verifications', {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(apiKey + ':').toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: params.toString()
      });
      if (!lobRes.ok) {
        const errBody = await lobRes.text().catch(() => '');
        console.error(`Lob verification request failed (tried city "${cityGuess}"):`, lobRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        lastHttpError = `Lob returned an error (HTTP ${lobRes.status})${detail ? ': ' + detail : ''}`;
        continue;
      }
      anySuccessfulCall = true;
      const data = await lobRes.json();
      const deliverability = data.deliverability || '';
      const isDeliverable = deliverability.indexOf('deliverable') === 0;
      if (isDeliverable) {
        const zip = data.components ? (data.components.zip_code || '') : '';
        const matchedCity = mailTitleCase(data.components ? (data.components.city || '') : '');
        console.log(`Zip lookup: "${address}, [tried "${cityGuess}"], ${state}" \u2192 MATCHED city="${matchedCity}" zip="${zip}"`);
        return res.json({ zip, city: matchedCity, deliverability });
      }
      console.log(`Zip lookup: "${address}, [tried "${cityGuess}"], ${state}" \u2192 deliverability="${deliverability}" last_line="${data.last_line || ''}"`);
    }
    // None of the candidate cities produced a deliverable match. If every
    // single attempt failed at the HTTP level (none of them even got a real
    // answer from Lob), surface that as a genuine error rather than a
    // normal "couldn't verify" result.
    if (!anySuccessfulCall && lastHttpError) {
      return res.status(502).json({ error: lastHttpError });
    }
    res.json({ zip: '', city: '', deliverability: 'undeliverable' });
  } catch (err) {
    console.error('Zip lookup failed:', err.message);
    res.status(500).json({ error: 'Zip lookup failed: ' + err.message });
  }
});

app.get('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) return res.status(400).json({ error: 'Unknown key.' });
  if (!(await checkAdminOnlyKey(req, res, key))) return;
  try {
    const value = await redis.get(key);
    let parsed = value === null ? null : JSON.parse(value);
    if (key === 'labor-weeks' && Array.isArray(parsed) && !(await isRequestingUserAdmin(req))) {
      parsed = parsed.map(week => {
        const { employees, ...rest } = week;
        return rest;
      });
    }
    res.json({ key, value: parsed });
  } catch (err) {
    console.error(`GET /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage read failed.' });
  }
});

app.put('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) return res.status(400).json({ error: 'Unknown key.' });
  if (!(await checkAdminOnlyKey(req, res, key))) return;
  if (!(await checkAdminWriteOnlyKey(req, res, key))) return;
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
  if (!(await checkAdminOnlyKey(req, res, key))) return;
  if (!(await checkAdminWriteOnlyKey(req, res, key))) return;
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
  console.log(process.env.LOB_API_KEY
    ? `LOB_API_KEY is set (starts with "${process.env.LOB_API_KEY.slice(0, 5)}...")`
    : 'LOB_API_KEY is NOT set \u2014 zip lookup will not work until it is added.');
  await ensureUsersSeeded();
});
