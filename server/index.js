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
  'compliance-pretrip-inspections',
  'settings-config-files',
  'settings-handoff-guide',
  'mail-marketing-list',
  'mail-apartment-outreach',
  'mail-storage-outreach',
  'mail-neighborhoods',
  'mail-neighborhood-visits',
  'mail-marketing-materials'
]);
const ALLOWED_KEY_PREFIXES = ['fleet-invoice-', 'paperwork-job-link-', 'paperwork-upload-', 'compliance-doc-', 'settings-config-doc-', 'marketing-material-doc-'];

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

// ============ Auth: shared driver access code for Pre-Trip Inspections ============
// A completely separate, narrowly-scoped credential path -- deliberately NOT
// part of the regular auth:users system. A driver session token only ever
// satisfies requireDriverAuth (below), never the regular requireAuth used by
// every other endpoint, so this shared code can never reach payroll, fleet
// financials, or anything else even if it's passed around loosely.
const DRIVER_CODE_KEY = 'auth:driver-code';
const DRIVER_SESSION_PREFIX = 'auth:driver-session:';
const DRIVER_SESSION_TTL_SECONDS = 60 * 60 * 16; // 16 hours -- a work shift
const DEFAULT_DRIVER_CODE = 'TruckCheck2026';

async function getDriverCode() {
  const raw = await redis.get(DRIVER_CODE_KEY);
  return raw || DEFAULT_DRIVER_CODE;
}

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

// ============ Driver access: shared-code login, deliberately isolated ============
app.post('/api/driver-login', async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  }
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'Access code is required.' });
  try {
    recordLoginAttempt(ip);
    const validCode = await getDriverCode();
    if (code !== validCode) {
      return res.status(401).json({ error: 'Incorrect access code.' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    await redis.set(DRIVER_SESSION_PREFIX + token, '1', 'EX', DRIVER_SESSION_TTL_SECONDS);
    res.json({ token });
  } catch (err) {
    console.error('Driver login failed:', err.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/driver-logout', async (req, res) => {
  const { token } = req.body || {};
  if (token) {
    try { await redis.del(DRIVER_SESSION_PREFIX + token); } catch (err) { console.error('Driver logout failed:', err.message); }
  }
  res.json({ ok: true });
});

// Only ever satisfied by a driver-session token -- a driver token never
// satisfies requireAuth above (different Redis key namespace entirely), so
// it cannot be used against any other endpoint in this file.
async function requireDriverAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    const valid = await redis.get(DRIVER_SESSION_PREFIX + token);
    if (!valid) return res.status(401).json({ error: 'Session expired \u2014 please log in again.' });
    next();
  } catch (err) {
    console.error('Driver auth check failed:', err.message);
    res.status(500).json({ error: 'Auth check failed.' });
  }
}

// Minimal truck list for the driver-facing form -- name only, nothing else
// from the fleet record (no VIN, purchase price, etc.).
app.get('/api/driver/trucks', requireDriverAuth, async (req, res) => {
  try {
    const raw = await redis.get('fleet-trucks');
    const trucks = raw ? JSON.parse(raw) : [];
    res.json({ trucks: trucks.map(t => ({ id: t.id, nickname: t.nickname })) });
  } catch (err) {
    console.error('Driver truck list failed:', err.message);
    res.status(500).json({ error: 'Could not load trucks.' });
  }
});

// Same name list as the staff /api/roster endpoint (most recent ADP payroll
// week), just reachable via the driver-scoped session instead of a regular
// staff login. Names only -- no pay, hours, or other payroll detail.
app.get('/api/driver/roster', requireDriverAuth, async (req, res) => {
  try {
    const raw = await redis.get('labor-weeks');
    const weeks = raw ? JSON.parse(raw) : [];
    if (!weeks.length) return res.json({ names: [] });
    const sorted = [...weeks].sort((a, b) => (b.weekStart || '').localeCompare(a.weekStart || ''));
    const mostRecent = sorted[0];
    const names = (mostRecent.employees || []).map(e => e.name).filter(Boolean);
    res.json({ names });
  } catch (err) {
    console.error('Driver roster fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load roster.' });
  }
});

// Full neighborhood catalog for the door-hanger route tool -- name, general
// area, and coordinates only (no addresses), nothing sensitive here so the
// full record is fine to expose.
app.get('/api/driver/neighborhoods', requireDriverAuth, async (req, res) => {
  try {
    const raw = await redis.get('mail-neighborhoods');
    const neighborhoods = raw ? JSON.parse(raw) : [];
    res.json({ neighborhoods });
  } catch (err) {
    console.error('Driver neighborhoods fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load neighborhoods.' });
  }
});

// Logs a door-hanger visit as a new entry in a growing history (mirrors the
// pre-trip inspection log pattern) rather than overwriting a single
// "last visited" field, so admins can see full coverage over time.
app.post('/api/driver/neighborhood-visit', requireDriverAuth, async (req, res) => {
  const { neighborhoodId, neighborhoodName, driverName } = req.body || {};
  if (!neighborhoodId || !driverName) {
    return res.status(400).json({ error: 'Neighborhood and driver name are required.' });
  }
  try {
    const raw = await redis.get('mail-neighborhood-visits');
    const visits = raw ? JSON.parse(raw) : [];
    visits.push({
      id: 'visit_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      neighborhoodId, neighborhoodName: neighborhoodName || '',
      driverName: String(driverName).slice(0, 100),
      date: new Date().toISOString().slice(0, 10),
      submittedAt: new Date().toISOString()
    });
    await redis.set('mail-neighborhood-visits', JSON.stringify(visits));
    res.json({ ok: true });
  } catch (err) {
    console.error('Neighborhood visit log failed:', err.message);
    res.status(500).json({ error: 'Could not log visit.' });
  }
});

app.post('/api/driver/pretrip', requireDriverAuth, async (req, res) => {
  const { truckId, truckNickname, driverName, date, odometer, checklist, additionalNotes } = req.body || {};
  if (!truckId || !driverName || !Array.isArray(checklist) || checklist.length === 0) {
    return res.status(400).json({ error: 'Truck, driver name, and checklist are required.' });
  }
  try {
    const raw = await redis.get('compliance-pretrip-inspections');
    const records = raw ? JSON.parse(raw) : [];
    const hasDefect = checklist.some(c => c.status === 'defect');
    records.push({
      id: 'pti_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      truckId, truckNickname: truckNickname || '',
      driverName: String(driverName).slice(0, 100),
      date: date || new Date().toISOString().slice(0, 10),
      odometer: odometer || '',
      checklist,
      overallStatus: hasDefect ? 'defects' : 'ok',
      additionalNotes: (additionalNotes || '').slice(0, 2000),
      submittedAt: new Date().toISOString()
    });
    await redis.set('compliance-pretrip-inspections', JSON.stringify(records));
    res.json({ ok: true });
  } catch (err) {
    console.error('Pre-trip submission failed:', err.message);
    res.status(500).json({ error: 'Could not submit inspection.' });
  }
});

// Admin-only viewing/management of the shared driver access code.
app.get('/api/admin/driver-code', requireAuth, requireAdmin, async (req, res) => {
  try {
    res.json({ code: await getDriverCode() });
  } catch (err) {
    console.error('Get driver code failed:', err.message);
    res.status(500).json({ error: 'Could not load access code.' });
  }
});

app.post('/api/admin/driver-code', requireAuth, requireAdmin, async (req, res) => {
  const { code } = req.body || {};
  const cleanCode = (code || '').trim();
  if (cleanCode.length < 5) {
    return res.status(400).json({ error: 'Access code must be at least 5 characters.' });
  }
  try {
    await redis.set(DRIVER_CODE_KEY, cleanCode);
    res.json({ ok: true, code: cleanCode });
  } catch (err) {
    console.error('Set driver code failed:', err.message);
    res.status(500).json({ error: 'Could not save access code.' });
  }
});

// ============ App Settings: admin-editable values used elsewhere in the app ============
// Grouped by which tile each setting belongs to. Defaults match whatever was
// previously hardcoded, so nothing changes in behavior until an admin edits
// something. Read is open to any logged-in staff (the Marketing and
// Paperwork tiles need these values regardless of who's using them); only
// admins can change them.
const APP_SETTINGS_KEY = 'settings-app-config';
const DEFAULT_APP_SETTINGS = {
  marketing: {
    redfinSouthCarolina: 'https://www.redfin.com/zipcode/29851/filter/sort=lo-days,property-type=house+townhouse+manufactured,min-price=250k,max-days-on-market=2wk,include=forsale+fsbo,status=active,mr=2:12302+2:12307+2:12308',
    redfinEvansMartinez: 'https://www.redfin.com/zipcode/30907/filter/sort=lo-days,property-type=house+townhouse+manufactured,min-price=250k,max-days-on-market=2wk,include=forsale+fsbo,status=active,mr=2:12903+2:12907+2:12922+2:12924',
    redfinAugusta: 'https://www.redfin.com/zipcode/30916/filter/sort=lo-days,property-type=house+townhouse+manufactured,min-price=250k,max-days-on-market=2wk,include=forsale+fsbo,status=active,mr=2:12928+2:12930'
  },
  paperwork: {
    completedPaperworkCc: 'administrative.assistantaug@chhj.com,aaron.henson@chhj.com',
    googleReviewLink: 'https://g.page/r/CTsnaSA6YbvlEBM/review'
  }
};

// Merges saved settings on top of the defaults, one group/field at a time,
// so a newly-added setting (in a future update) always has a sensible
// fallback even if the admin has never touched it.
function mergeAppSettings(saved){
  const merged = {};
  for (const group of Object.keys(DEFAULT_APP_SETTINGS)) {
    merged[group] = Object.assign({}, DEFAULT_APP_SETTINGS[group], (saved && saved[group]) || {});
  }
  return merged;
}

app.get('/api/app-settings', requireAuth, async (req, res) => {
  try {
    const raw = await redis.get(APP_SETTINGS_KEY);
    const saved = raw ? JSON.parse(raw) : null;
    res.json({ settings: mergeAppSettings(saved) });
  } catch (err) {
    console.error('Get app settings failed:', err.message);
    res.status(500).json({ error: 'Could not load settings.' });
  }
});

app.post('/api/admin/app-settings', requireAuth, requireAdmin, async (req, res) => {
  const { settings } = req.body || {};
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'Settings object is required.' });
  }
  try {
    const raw = await redis.get(APP_SETTINGS_KEY);
    const existing = raw ? JSON.parse(raw) : {};
    // Merge group-by-group so saving one group's fields never wipes another group's saved values.
    const updated = Object.assign({}, existing);
    for (const group of Object.keys(settings)) {
      if (!DEFAULT_APP_SETTINGS[group]) continue; // ignore unknown groups
      updated[group] = Object.assign({}, existing[group] || {}, settings[group]);
    }
    await redis.set(APP_SETTINGS_KEY, JSON.stringify(updated));
    res.json({ ok: true, settings: mergeAppSettings(updated) });
  } catch (err) {
    console.error('Save app settings failed:', err.message);
    res.status(500).json({ error: 'Could not save settings.' });
  }
});

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

// Generates a one-off temporary password for an admin-initiated reset. Random
// per use (unlike the fixed TEMP_PASSWORD used for brand-new accounts), and
// avoids ambiguous characters (0/O, 1/l/I) since an admin may read or text
// this to the affected user.
function generateTempPassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(10);
  let pw = '';
  for (let i = 0; i < bytes.length; i++) pw += chars[bytes[i] % chars.length];
  return pw + '!';
}

// Lets an admin force-reset another user's password (e.g. they're locked out
// and can't receive a self-service reset email). Sets a fresh random
// temporary password and flags the account so the user is required to set
// their own password on their very next login -- the same mustReset flow
// already used when a new account is first created.
app.post('/api/admin/users/:email/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const cleanEmail = (req.params.email || '').toLowerCase().trim();
  try {
    const users = await getUsers();
    if (!users[cleanEmail]) {
      return res.status(404).json({ error: 'No user found with that email.' });
    }
    const tempPassword = generateTempPassword();
    users[cleanEmail].passwordHash = await hashPassword(tempPassword);
    users[cleanEmail].mustReset = true;
    await saveUsers(users);
    res.json({ ok: true, email: cleanEmail, tempPassword });
  } catch (err) {
    console.error('Admin password reset failed:', err.message);
    res.status(500).json({ error: 'Could not reset password.' });
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

// Reads one or more uploaded real-estate listing screenshots and extracts a
// structured address/city/state/zip for every listing visible, using Claude's
// vision + tool-use (forcing structured output rather than parsing free
// text). Requires the ANTHROPIC_API_KEY environment variable (a standard
// Anthropic API key from console.anthropic.com, separate from any Claude.ai
// subscription).
const EXTRACT_LISTINGS_TOOL = {
  name: 'extract_listings',
  description: 'Extract structured address data for every distinct property listing visible across the provided screenshot(s).',
  input_schema: {
    type: 'object',
    properties: {
      listings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            address: { type: 'string', description: 'Street address only, e.g. "123 Main St" -- no city/state/zip, no unit numbers unless part of the street address.' },
            city: { type: 'string' },
            state: { type: 'string', description: 'Two-letter state abbreviation, e.g. "GA".' },
            zip: { type: 'string', description: '5-digit zip code if visible in the screenshot, otherwise an empty string.' }
          },
          required: ['address', 'city', 'state']
        }
      }
    },
    required: ['listings']
  }
};

app.post('/api/admin/extract-listings', requireAuth, async (req, res) => {
  const { images } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 20) {
    return res.status(400).json({ error: 'Please upload 20 images or fewer at a time.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Listing extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Screenshot extraction is not configured on the server yet (ANTHROPIC_API_KEY is missing).' });
  }

  try {
    const imageBlocks = images.map(dataUri => {
      const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(dataUri || '');
      if (!match) return null;
      return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
    }).filter(Boolean);
    if (imageBlocks.length === 0) {
      return res.status(400).json({ error: 'No valid images were provided.' });
    }

    // Send at most 5 images per Anthropic request -- a single large batch
    // (e.g. 20 images at once) appears to make extraction noticeably less
    // reliable, sometimes returning nothing at all. Smaller batches, run in
    // parallel, keep each individual request focused and fast without
    // increasing total wait time much.
    const BATCH_SIZE = 5;
    const batches = [];
    for (let i = 0; i < imageBlocks.length; i += BATCH_SIZE) {
      batches.push(imageBlocks.slice(i, i + BATCH_SIZE));
    }

    async function runBatch(batchImages, batchIndex){
      const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 4096,
          tools: [EXTRACT_LISTINGS_TOOL],
          tool_choice: { type: 'tool', name: 'extract_listings' },
          messages: [{
            role: 'user',
            content: [
              ...batchImages,
              { type: 'text', text: `These are ${batchImages.length} screenshot(s) of real estate listings (from Redfin, Zillow, or similar). Look carefully at each image individually and extract the street address, city, state, and zip code for every distinct property listing visible. Each screenshot generally shows at least one listing -- read the address text carefully even if it's small. Do not include agent names, prices, or MLS numbers -- only the address fields. If the same property appears in more than one screenshot, list it only once.` }
            ]
          }]
        })
      });

      if (!anthropicRes.ok) {
        const errBody = await anthropicRes.text().catch(() => '');
        console.error(`Anthropic API request failed (batch ${batchIndex}, ${batchImages.length} images):`, anthropicRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return { error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` };
      }

      const data = await anthropicRes.json();
      const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_listings');
      if (!toolUseBlock) {
        const textBlock = (data.content || []).find(b => b.type === 'text');
        console.error(`Anthropic response had no tool_use block (batch ${batchIndex}, ${batchImages.length} images). stop_reason=${data.stop_reason}. Text content: ${textBlock ? textBlock.text.slice(0, 300) : '(none)'}`);
        return { error: 'Could not read a structured response from the extraction service.' };
      }
      const listings = Array.isArray(toolUseBlock.input.listings) ? toolUseBlock.input.listings : [];
      console.log(`Extraction batch ${batchIndex}: ${batchImages.length} image(s) in, ${listings.length} listing(s) out. stop_reason=${data.stop_reason}`);
      return { listings };
    }

    const batchResults = await Promise.all(batches.map((b, i) => runBatch(b, i)));
    const allListings = [];
    const batchErrors = [];
    batchResults.forEach(r => {
      if (r.error) batchErrors.push(r.error);
      else allListings.push(...r.listings);
    });

    if (allListings.length === 0 && batchErrors.length > 0) {
      // Every batch failed outright -- surface the error rather than silently returning nothing.
      return res.status(502).json({ error: batchErrors[0] });
    }
    res.json({ listings: allListings, partialFailures: batchErrors.length });
  } catch (err) {
    console.error('Listing extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
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
  console.log(process.env.ANTHROPIC_API_KEY
    ? `ANTHROPIC_API_KEY is set (starts with "${process.env.ANTHROPIC_API_KEY.slice(0, 8)}...")`
    : 'ANTHROPIC_API_KEY is NOT set \u2014 screenshot address extraction will not work until it is added.');
  await ensureUsersSeeded();
});
