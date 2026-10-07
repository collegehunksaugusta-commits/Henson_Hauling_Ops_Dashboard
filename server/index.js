const express = require('express');
const cors = require('cors');
const Redis = require('ioredis');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '15mb', verify: (req, res, buf) => { req.rawBody = buf; } }));
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
  'compliance-coi-list',
  'settings-config-files',
  'settings-handoff-guide',
  'mail-marketing-list',
  'mail-apartment-outreach',
  'mail-storage-outreach',
  'mail-neighborhoods',
  'mail-neighborhood-visits',
  'mail-marketing-materials',
  'mail-mailed-history',
  'square-tip-allocations',
  'square-tip-paid-weeks',
  'roster-manual-additions',
  'materials-items',
  'materials-checkouts',
  'compliance-eod-inspections',
  'damage-claims',
  'junk-removal-jobs',
  'moving-damage-reports',
  'manager-review-items',
  'financial-state-tax-records',
  'monthly-financials',
  'hourly-rate-history',
  'extra-pay-manual',
  'wingman-questions',
  'wingman-ratings',
  'captain-questions',
  'captain-ratings',
  'wingman-tasks',
  'materials-checkins',
  'wingman-review-skips',
  'google-review-allocations',
  'weight-tickets',
  'damage-claim-crew-acks',
  'hiring-documents',
  'hiring-candidates',
  'hiring-reveal-log',
  'ops-manager-metrics-monthly-locks'
]);
const ALLOWED_KEY_PREFIXES = ['weight-ticket-photo-', 'fleet-invoice-', 'paperwork-job-link-', 'paperwork-upload-', 'compliance-doc-', 'settings-config-doc-', 'marketing-material-doc-', 'compliance-pti-photo-', 'compliance-eod-photo-', 'damage-claim-photo-', 'junk-removal-photo-', 'moving-photo-', 'junk-removal-invoice-', 'hiring-doc-file-', 'hiring-signature-'];

function isAllowedKey(key) {
  if (ALLOWED_KEYS.has(key)) return true;
  return ALLOWED_KEY_PREFIXES.some(prefix => key.startsWith(prefix));
}

// ============ GitHub webhook: auto-archive source snapshots ============
// Fires on every push to the repo's default branch. If index.html or
// server/index.js changed, fetches that exact commit's version and stores
// it in the same in-app "Dashboard Source Code" archive the manual upload
// panel writes to (settings-config-files / settings-config-doc-*), so a
// snapshot lands there automatically without a second manual upload step.
// Configured on GitHub's side under Repo Settings > Webhooks, pointed at
// this endpoint, with the shared secret set as GITHUB_WEBHOOK_SECRET here.
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;
const CONFIG_SNAPSHOT_TARGETS = [
  { path: 'index.html', fileType: 'html', mimeType: 'text/html' },
  { path: 'server/index.js', fileType: 'server', mimeType: 'text/javascript' }
];

function verifyGithubSignature(req) {
  if (!GITHUB_WEBHOOK_SECRET || !req.rawBody) return false;
  const signature = req.headers['x-hub-signature-256'];
  if (typeof signature !== 'string' || !signature.startsWith('sha256=')) return false;
  const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');
  const sigBuf = Buffer.from(signature);
  const digestBuf = Buffer.from(digest);
  if (sigBuf.length !== digestBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, digestBuf);
}

app.post('/api/github-webhook', async (req, res) => {
  // Respond immediately -- GitHub expects a fast response and will flag the
  // webhook as unhealthy otherwise, regardless of whether there's anything
  // in this particular push worth snapshotting.
  res.json({ ok: true });

  if (!verifyGithubSignature(req)) {
    console.error('GitHub webhook: invalid or missing signature, ignoring.');
    return;
  }
  if (req.headers['x-github-event'] !== 'push') return;

  const payload = req.body || {};
  const commit = payload.head_commit;
  const repoFullName = payload.repository && payload.repository.full_name;
  const defaultBranch = payload.repository && payload.repository.default_branch;
  if (!commit || !repoFullName) return; // e.g. a branch deletion push has no head_commit
  if (defaultBranch && payload.ref !== `refs/heads/${defaultBranch}`) return; // ignore pushes to other branches

  const changedFiles = new Set([...(commit.added || []), ...(commit.modified || [])]);

  for (const target of CONFIG_SNAPSHOT_TARGETS) {
    if (!changedFiles.has(target.path)) continue;
    try {
      const rawUrl = `https://raw.githubusercontent.com/${repoFullName}/${commit.id}/${target.path}`;
      const fileRes = await fetch(rawUrl);
      if (!fileRes.ok) {
        console.error(`GitHub webhook: could not fetch ${target.path} at ${commit.id}, status ${fileRes.status}`);
        continue;
      }
      const content = await fileRes.text();
      const dataUri = `data:${target.mimeType};base64,${Buffer.from(content, 'utf-8').toString('base64')}`;

      const fileId = 'config_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
      await redis.set('settings-config-doc-' + fileId, JSON.stringify(dataUri));

      const filesRaw = await redis.get('settings-config-files');
      const files = filesRaw ? JSON.parse(filesRaw) : [];
      const shortSha = commit.id.slice(0, 7);
      const commitMessage = (commit.message || '').split('\n')[0].slice(0, 200);
      files.push({
        id: fileId,
        fileType: target.fileType,
        fileName: target.path.split('/').pop(),
        notes: `Auto-saved from GitHub commit ${shortSha}${commitMessage ? ': ' + commitMessage : ''}`,
        uploadedAt: commit.timestamp || new Date().toISOString()
      });
      await redis.set('settings-config-files', JSON.stringify(files));
      console.log(`GitHub webhook: saved ${target.path} snapshot from commit ${shortSha}`);
    } catch (err) {
      console.error(`GitHub webhook: failed to snapshot ${target.path}:`, err.message);
    }
  }
});

// ============ Auth: user accounts (stored separately, never exposed via /api/data) ============
// ======================================================================
// LOCATION PROFILE -- everything that ties this server to one College
// Hunks location. Each value can be set in Render (Environment) with the
// LOCATION_* name shown; otherwise the default here is used. The matching
// block for the dashboard is window.LOCATION_PROFILE at the top of
// index.html.
// ======================================================================
const LOCATION = {
  name: process.env.LOCATION_NAME || 'College Hunks Augusta',
  // Name searched on Google Maps to find this location's listing, and the
  // word the right Business Profile listing's title contains.
  googleListingQuery: process.env.LOCATION_GOOGLE_LISTING_QUERY || 'College Hunks Hauling Junk and Moving Augusta',
  googleListingMatch: process.env.LOCATION_GOOGLE_LISTING_MATCH || 'Augusta',
  officeLat: Number(process.env.LOCATION_OFFICE_LAT) || 33.5506581,
  officeLng: Number(process.env.LOCATION_OFFICE_LNG) || -82.1236477,
  // Local time zone: decides what "today" is for weight tickets, Google
  // review dates and similar.
  timeZone: process.env.LOCATION_TIME_ZONE || 'America/New_York',
  // First logins created on a brand-new install (owner as admin).
  initialAdminEmail: process.env.LOCATION_INITIAL_ADMIN_EMAIL || 'aaron.henson@chhj.com',
  initialUserEmails: (process.env.LOCATION_INITIAL_USER_EMAILS || 'administrative.assistantaug@chhj.com').split(',').map(e => e.trim()).filter(Boolean),
  // Defaults offered until changed in Configuration.
  googleReviewLink: process.env.LOCATION_GOOGLE_REVIEW_LINK || 'https://g.page/r/CTsnaSA6YbvlEBM/review',
  completedPaperworkCc: process.env.LOCATION_COMPLETED_PAPERWORK_CC || 'administrative.assistantaug@chhj.com,aaron.henson@chhj.com',
  emailSignature: process.env.LOCATION_EMAIL_SIGNATURE || 'College Hunks Hauling Junk & Moving \u2013 Augusta'
};

const USERS_KEY = 'auth:users';
const SESSION_PREFIX = 'auth:session:';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

const SEED_USERS = [
  { email: LOCATION.initialAdminEmail, role: 'admin' },
  ...LOCATION.initialUserEmails.map(email => ({ email, role: 'user' }))
];
const TEMP_PASSWORD = 'Password123!';

// ============ Auth: per-driver SSN-last-4 login for Pre-Trip Inspections ============
// A completely separate, narrowly-scoped credential path -- deliberately NOT
// part of the regular auth:users system. A driver session token only ever
// satisfies requireDriverAuth (below), never the regular requireAuth used by
// every other endpoint, so this can never reach payroll, fleet financials,
// or anything else even if it's passed around loosely.
//
// DRIVER_AUTH_LOOKUP_KEY holds { [last4]: employeeName }, rebuilt automatically
// from two sources every time either one is saved (see the labor-weeks and
// compliance-drivers write handlers below): the most recent payroll week's
// employee list (for the SSN data) crossed against compliance-drivers (for
// who is actually checkmarked as a driver on the Compliance tile). Being on
// payroll alone is never enough -- an office employee never gets Driver
// Portal access just by having last-4 SSN data on file. It is NOT in
// ALLOWED_KEYS, so it has no HTTP-reachable read or write path at all -- not
// even for an admin -- it only exists for this file's own login-time lookup.
// Turnover and role changes are both handled naturally: someone who drops
// off the last two weeks' payroll, or gets unchecked as a driver, simply
// isn't in the lookup rebuilt from either change, with no separate
// deprovisioning step needed.
const DRIVER_AUTH_LOOKUP_KEY = 'driver-auth-lookup';
const DRIVER_SESSION_PREFIX = 'auth:driver-session:';
// Wingman Portal access: same last-4-of-SSN login, same payroll source,
// but for everyone on the last two payroll weeks who is NOT checkmarked as an
// active driver. Kept in its own lookup key and its own session namespace,
// so a wingman session can never satisfy requireDriverAuth (and vice
// versa) -- the only crossover is requireDriverOrTaskWingman below, which
// lets a wingman act on a Captain's behalf strictly for a task that
// Captain assigned them.
const WINGMAN_AUTH_LOOKUP_KEY = 'wingman-auth-lookup';
const WINGMAN_SESSION_PREFIX = 'auth:wingman-session:';
const DRIVER_SESSION_TTL_SECONDS = 60 * 60 * 16; // 16 hours -- a work shift

// Last 4 of SSN for manually added employees, by name. Deliberately NOT an
// /api/data key -- it can only be written or cleared through the admin
// endpoints below, and the digits are never sent back to the dashboard.
const MANUAL_SSN_KEY = 'roster-manual-ssn';

async function rebuildDriverAuthLookup() {
  try {
    const [weeksRaw, driversRaw] = await Promise.all([
      redis.get('labor-weeks'),
      redis.get('compliance-drivers')
    ]);
    const weeks = weeksRaw ? JSON.parse(weeksRaw) : [];
    const compDrivers = driversRaw ? JSON.parse(driversRaw) : [];
    // Only names actively checkmarked as a driver on the Compliance tile --
    // an office employee who happens to be on payroll never gets Driver
    // Portal access just by having last-4 SSN data on file.
    const activeDriverNames = new Set(compDrivers.filter(d => d && d.active).map(d => d.employeeName));

    // The two most recent payroll weeks -- the same window the employee
    // roster uses -- so someone who took an unpaid week off (and so isn't
    // on the latest export) can still sign in. Older week first, so the
    // latest week's data wins wherever the two disagree.
    const recentTwo = weeks.slice().sort((a, b) => (b.weekStart || '').localeCompare(a.weekStart || '')).slice(0, 2);
    const employees = recentTwo.slice().reverse().flatMap(w => w.employees || []);
    const lookup = {};
    const wingmanLookup = {};
    employees.forEach(e => {
      if (!(e && e.name && e.ssnLast4 && /^\d{4}$/.test(e.ssnLast4))) return;
      // A given last-4 maps to exactly one person and one portal.
      delete lookup[e.ssnLast4];
      delete wingmanLookup[e.ssnLast4];
      if (activeDriverNames.has(e.name)) lookup[e.ssnLast4] = e.name;
      else wingmanLookup[e.ssnLast4] = e.name;
    });
    // Manually added employees (Roster Additions -- brand-new hires not on
    // a payroll report yet) with a last-4 entered get access too, as long
    // as payroll doesn't already have them and the digits aren't already
    // someone else's. Once they appear on payroll, payroll takes over and
    // their manual entry is dropped (see the roster reconciliation).
    try {
      const [manualRaw, manualSsnRaw] = await Promise.all([redis.get('roster-manual-additions'), redis.get(MANUAL_SSN_KEY)]);
      const manualNames = manualRaw ? JSON.parse(manualRaw) : [];
      const manualSsn = manualSsnRaw ? JSON.parse(manualSsnRaw) : {};
      const onManualList = new Set(manualNames.map(n => nameDedupKey(n)));
      const onPayroll = new Set(employees.filter(e => e && e.name).map(e => nameDedupKey(e.name)));
      let pruned = false;
      Object.keys(manualSsn).forEach(name => {
        // Removed from the list, or now on payroll: forget the manual digits.
        if (!onManualList.has(nameDedupKey(name)) || onPayroll.has(nameDedupKey(name))) { delete manualSsn[name]; pruned = true; return; }
        const last4 = manualSsn[name];
        if (!/^\d{4}$/.test(last4) || lookup[last4] || wingmanLookup[last4]) return;
        const isDriver = [...activeDriverNames].some(d => nameDedupKey(d) === nameDedupKey(name));
        if (isDriver) lookup[last4] = name; else wingmanLookup[last4] = name;
      });
      if (pruned) await redis.set(MANUAL_SSN_KEY, JSON.stringify(manualSsn));
    } catch (err) {
      console.error('Manual employee access step failed:', err.message);
    }

    // TEMPORARY diagnostic logging -- names and counts only, never SSN
    // digits -- to pinpoint exactly where a specific person's access is
    // coming from. Safe to remove once the current issue is resolved.
    console.log('[driver-auth-lookup] payroll weeks used:', recentTwo.map(w => w.weekStart).join(', ') || '(none)');
    console.log('[driver-auth-lookup] payroll employee names:', employees.map(e => e && e.name).filter(Boolean));
    console.log('[driver-auth-lookup] checkmarked active driver names:', [...activeDriverNames]);
    console.log('[driver-auth-lookup] final lookup names:', Object.values(lookup));
    await redis.set(DRIVER_AUTH_LOOKUP_KEY, JSON.stringify(lookup));
    await redis.set(WINGMAN_AUTH_LOOKUP_KEY, JSON.stringify(wingmanLookup));
  } catch (err) {
    console.error('Driver auth lookup rebuild failed:', err.message);
  }
}

// ---- App access for manually added employees ----
// Which manually added names have a last-4 on file (names only, never digits).
app.get('/api/admin/manual-employee-access', requireAuth, requireAdmin, async (req, res) => {
  try {
    const raw = await redis.get(MANUAL_SSN_KEY);
    res.json({ names: Object.keys(raw ? JSON.parse(raw) : {}) });
  } catch (err) {
    res.status(500).json({ error: 'Could not load.' });
  }
});

app.post('/api/admin/manual-employee-access', requireAuth, requireAdmin, async (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  const last4 = String((req.body && req.body.last4) || '').trim();
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  if (!/^\d{4}$/.test(last4)) return res.status(400).json({ error: 'Enter exactly 4 digits.' });
  try {
    const [manualRaw, ssnRaw, weeksRaw] = await Promise.all([redis.get('roster-manual-additions'), redis.get(MANUAL_SSN_KEY), redis.get('labor-weeks')]);
    const manualNames = manualRaw ? JSON.parse(manualRaw) : [];
    const listed = manualNames.find(n => nameDedupKey(n) === nameDedupKey(name));
    if (!listed) return res.status(400).json({ error: 'Add the name to Roster Additions first.' });
    const manualSsn = ssnRaw ? JSON.parse(ssnRaw) : {};
    // The same 4 digits can only sign in one person.
    const weeks = weeksRaw ? JSON.parse(weeksRaw) : [];
    const recent = weeks.slice().sort((a, b) => (b.weekStart || '').localeCompare(a.weekStart || '')).slice(0, 2).flatMap(w => w.employees || []);
    const payrollHolder = recent.find(e => e && e.ssnLast4 === last4 && nameDedupKey(e.name || '') !== nameDedupKey(listed));
    const manualHolder = Object.keys(manualSsn).find(n => manualSsn[n] === last4 && nameDedupKey(n) !== nameDedupKey(listed));
    if (payrollHolder || manualHolder) {
      return res.status(409).json({ error: `Those 4 digits already belong to ${payrollHolder ? payrollHolder.name : manualHolder} \u2014 double-check them.` });
    }
    Object.keys(manualSsn).forEach(n => { if (nameDedupKey(n) === nameDedupKey(listed)) delete manualSsn[n]; });
    manualSsn[listed] = last4;
    await redis.set(MANUAL_SSN_KEY, JSON.stringify(manualSsn));
    await rebuildDriverAuthLookup();
    console.log(`[manual-employee-access] app access set for ${listed}`);
    res.json({ ok: true, name: listed });
  } catch (err) {
    console.error('Manual employee access save failed:', err.message);
    res.status(500).json({ error: 'Could not save.' });
  }
});

app.delete('/api/admin/manual-employee-access', requireAuth, requireAdmin, async (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  try {
    const raw = await redis.get(MANUAL_SSN_KEY);
    const manualSsn = raw ? JSON.parse(raw) : {};
    Object.keys(manualSsn).forEach(n => { if (nameDedupKey(n) === nameDedupKey(name)) delete manualSsn[n]; });
    await redis.set(MANUAL_SSN_KEY, JSON.stringify(manualSsn));
    await rebuildDriverAuthLookup();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not remove.' });
  }
});

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
  const last4 = ((req.body || {}).last4 || '').toString().trim();
  if (!/^\d{4}$/.test(last4)) {
    return res.status(400).json({ error: 'Enter the last 4 digits of your SSN.' });
  }
  try {
    recordLoginAttempt(ip);
    const [raw, wingmanRaw] = await Promise.all([
      redis.get(DRIVER_AUTH_LOOKUP_KEY),
      redis.get(WINGMAN_AUTH_LOOKUP_KEY)
    ]);
    const lookup = raw ? JSON.parse(raw) : {};
    const wingmanLookup = wingmanRaw ? JSON.parse(wingmanRaw) : {};
    const driverName = lookup[last4];
    const token = crypto.randomBytes(32).toString('hex');
    if (driverName) {
      await redis.set(DRIVER_SESSION_PREFIX + token, driverName, 'EX', DRIVER_SESSION_TTL_SECONDS);
      return res.json({ token, driverName, role: 'captain' });
    }
    const wingmanName = wingmanLookup[last4];
    // Same generic message either way -- doesn't hint whether the digits
    // simply don't match anyone, so there's nothing to learn from a wrong guess.
    if (!wingmanName) {
      return res.status(401).json({ error: 'Those digits don\u2019t match anyone on file.' });
    }
    await redis.set(WINGMAN_SESSION_PREFIX + token, wingmanName, 'EX', DRIVER_SESSION_TTL_SECONDS);
    res.json({ token, driverName: wingmanName, role: 'wingman' });
  } catch (err) {
    console.error('Driver login failed:', err.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/driver-logout', async (req, res) => {
  const { token } = req.body || {};
  if (token) {
    try { await redis.del(DRIVER_SESSION_PREFIX + token, WINGMAN_SESSION_PREFIX + token); } catch (err) { console.error('Driver logout failed:', err.message); }
  }
  res.json({ ok: true });
});

// Only ever satisfied by a driver-session token -- a driver token never
// satisfies requireAuth above (different Redis key namespace entirely), so
// it cannot be used against any other endpoint in this file. The session
// value is the specific driver's name (verified at login against payroll
// data), attached here so every downstream handler uses a server-verified
// identity instead of trusting whatever name a client happens to send.
async function requireDriverAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    const valid = await redis.get(DRIVER_SESSION_PREFIX + token);
    if (!valid) return res.status(401).json({ error: 'Session expired \u2014 please log in again.' });
    req.driverName = valid;
    next();
  } catch (err) {
    console.error('Driver auth check failed:', err.message);
    res.status(500).json({ error: 'Auth check failed.' });
  }
}

// ============ Wingman Portal: auth, task delegation ============
async function requireWingmanAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    const name = await redis.get(WINGMAN_SESSION_PREFIX + token);
    if (!name) return res.status(401).json({ error: 'Session expired \u2014 please log in again.' });
    req.wingmanName = name;
    next();
  } catch (err) {
    console.error('Wingman auth check failed:', err.message);
    res.status(500).json({ error: 'Auth check failed.' });
  }
}

const WINGMAN_TASKS_KEY = 'wingman-tasks';
const WINGMAN_TASK_TYPES = {
  'pretrip': 'Pre-Trip Inspection',
  'materials-checkout': 'Material Checkout',
  'eod': 'End of Day Inspection',
  'materials-checkin': 'Material Checkin'
};
function todayIsoDate() { return new Date().toISOString().slice(0, 10); }

async function loadWingmanTasks() {
  const raw = await redis.get(WINGMAN_TASKS_KEY);
  return raw ? JSON.parse(raw) : [];
}
async function completeWingmanTask(taskId, completedBy) {
  const tasks = await loadWingmanTasks();
  const task = tasks.find(t => t.id === taskId);
  if (!task || task.status !== 'open') return;
  task.status = 'completed';
  task.completedAt = new Date().toISOString();
  task.completedBy = completedBy;
  await redis.set(WINGMAN_TASKS_KEY, JSON.stringify(tasks));
}

// Accepts either a normal Captain session, or a wingman session acting
// on an open task a Captain assigned them (identified by the
// X-Wingman-Task-Id header). In the wingman case, req.driverName is set
// to the assigning Captain -- so the record lands exactly where the
// Captain's own submission would, and Captain Metrics, PTI/EOD
// compliance and the Materials reconciliation all work unchanged -- and
// req.actingWingmanName records who actually did it. allowedTypes limits
// which task types may use the endpoint (null = any open task, for the
// read-only lookups the forms need). completesType, when the task is of
// that type, marks it complete once the endpoint responds successfully.
function requireDriverOrTaskWingman(allowedTypes, completesType) {
  return async (req, res, next) => {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not logged in.' });
    try {
      const driverName = await redis.get(DRIVER_SESSION_PREFIX + token);
      if (driverName) { req.driverName = driverName; return next(); }
      const wingmanName = await redis.get(WINGMAN_SESSION_PREFIX + token);
      if (!wingmanName) return res.status(401).json({ error: 'Session expired \u2014 please log in again.' });
      const taskId = String(req.headers['x-wingman-task-id'] || '');
      if (!taskId) return res.status(403).json({ error: 'This needs a task assigned to you by a Captain.' });
      const tasks = await loadWingmanTasks();
      const task = tasks.find(t => t.id === taskId);
      if (!task || task.status !== 'open' || nameDedupKey(task.wingmanName) !== nameDedupKey(wingmanName)) {
        return res.status(403).json({ error: 'That task is no longer assigned to you.' });
      }
      if (allowedTypes && !allowedTypes.includes(task.type)) {
        return res.status(403).json({ error: 'That task doesn\u2019t cover this.' });
      }
      req.driverName = task.captainName;
      req.actingWingmanName = wingmanName;
      req.wingmanTask = task;
      if (completesType && task.type === completesType) {
        res.on('finish', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            completeWingmanTask(task.id, wingmanName).catch(err => console.error('Wingman task completion failed:', err.message));
          }
        });
      }
      next();
    } catch (err) {
      console.error('Driver/wingman auth check failed:', err.message);
      res.status(500).json({ error: 'Auth check failed.' });
    }
  };
}

// Minimal truck list for the driver-facing form -- name only, nothing else
// from the fleet record (no VIN, purchase price, etc.).
app.get('/api/driver/trucks', requireDriverOrTaskWingman(null), async (req, res) => {
  try {
    const raw = await redis.get('fleet-trucks');
    const trucks = raw ? JSON.parse(raw) : [];
    // isDiesel / isJunk decide which extra Pre-Trip questions a truck gets.
    res.json({ trucks: trucks.map(t => ({ id: t.id, nickname: t.nickname, isDiesel: !!t.isDiesel, isJunk: !!t.isJunk })) });
  } catch (err) {
    console.error('Driver truck list failed:', err.message);
    res.status(500).json({ error: 'Could not load trucks.' });
  }
});

// Read-only view of a truck's Registration and Insurance Card, for drivers
// who need to show proof in the field. Uses the exact same storage keys the
// admin-side Insurance section writes to (compliance-doc-truck-<id>-<type>)
// -- there's only ever one copy of each document, drivers just get a
// read-only window into it. No write access from this endpoint.
app.get('/api/driver/truck-docs/:truckId', requireDriverAuth, async (req, res) => {
  const truckId = req.params.truckId;
  if (!truckId) return res.status(400).json({ error: 'Truck ID is required.' });
  try {
    const [regRaw, insRaw] = await Promise.all([
      redis.get(`compliance-doc-truck-${truckId}-registration`),
      redis.get(`compliance-doc-truck-${truckId}-insuranceCard`)
    ]);
    res.json({
      registration: regRaw ? JSON.parse(regRaw) : null,
      insuranceCard: insRaw ? JSON.parse(insRaw) : null
    });
  } catch (err) {
    console.error('Driver truck-docs fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load truck documents.' });
  }
});

// Same name list as the staff /api/roster endpoint (most recent ADP payroll
// week), just reachable via the driver-scoped session instead of a regular
// staff login. Names only -- no pay, hours, or other payroll detail.
// This roster's only current consumer is the driver app's wingman-
// selection dropdown (who to rate after an EOD inspection) -- active
// drivers (Captains) are excluded entirely, since a Captain who
// occasionally fills in as someone else's wingman on a slower day is
// never themselves evaluated as one.
app.get('/api/driver/roster', requireDriverAuth, async (req, res) => {
  try {
    const [weeksRaw, manualRaw, activeDriverKeys] = await Promise.all([
      redis.get('labor-weeks'),
      redis.get('roster-manual-additions'),
      fetchActiveDriverKeys()
    ]);
    const weeks = weeksRaw ? JSON.parse(weeksRaw) : [];
    const manualAdditions = manualRaw ? JSON.parse(manualRaw) : [];
    const names = computeRosterNames(weeks, manualAdditions).filter(n => !activeDriverKeys.has(nameDedupKey(n)));
    res.json({ names });
  } catch (err) {
    console.error('Driver roster fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load roster.' });
  }
});

// The current Wingman Metrics questions -- read-only for drivers, who only
// need to see what's currently configured, never edit it. Only non-empty
// slots are meaningful; the frontend filters blanks before asking anything.
app.get('/api/driver/wingman-questions', requireDriverAuth, async (req, res) => {
  try {
    const raw = await redis.get('wingman-questions');
    const questions = raw ? JSON.parse(raw) : [];
    res.json({ questions });
  } catch (err) {
    console.error('Driver wingman questions fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load wingman questions.' });
  }
});

// One wingman's set of yes/no answers from a single Captain, for a single
// EOD inspection -- a Captain reviewing several wingmen submits one of
// these per wingman. captainName comes from the authenticated session, not
// the request body, so it can't be spoofed.
app.post('/api/driver/wingman-rating', requireDriverAuth, async (req, res) => {
  const { wingmanName, answers } = req.body || {};
  if (typeof wingmanName !== 'string' || !wingmanName.trim()) {
    return res.status(400).json({ error: 'wingmanName is required.' });
  }
  if (!Array.isArray(answers) || answers.length === 0 || answers.some(a => !a || typeof a.question !== 'string' || typeof a.answer !== 'boolean')) {
    return res.status(400).json({ error: 'answers must be a non-empty array of { question, answer }.' });
  }
  try {
    const raw = await redis.get('wingman-ratings');
    const ratings = raw ? JSON.parse(raw) : [];
    ratings.push({
      id: 'wr_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      captainName: req.driverName,
      wingmanName: wingmanName.trim().slice(0, 100),
      date: new Date().toISOString().slice(0, 10),
      answers: answers.map(a => ({ question: String(a.question).slice(0, 300), answer: !!a.answer })),
      createdAt: new Date().toISOString()
    });
    await redis.set('wingman-ratings', JSON.stringify(ratings));
    res.json({ ok: true });
  } catch (err) {
    console.error('Wingman rating submission failed:', err.message);
    res.status(500).json({ error: 'Could not save that wingman review.' });
  }
});

// ============ Required daily Wingman Review ============
// Once a Captain's End of Day Inspection is in, Wingman Review is a
// required step: the Driver Portal keeps sending him back to it until he
// has reviewed at least one wingman, or confirmed he worked alone that
// day. Keyed off his most recent End of Day in the last 18 hours (rather
// than a calendar date, since an evening End of Day can cross midnight
// UTC) -- so closing the app, a reload, or a dropped connection right
// after submitting can no longer lose the review.
const WINGMAN_REVIEW_WINDOW_MS = 18 * 60 * 60 * 1000;
const WINGMAN_REVIEW_LOOKBACK_MS = 16 * 60 * 60 * 1000; // reviews done earlier in the same shift still count
app.get('/api/driver/wingman-review-status', requireDriverAuth, async (req, res) => {
  try {
    const [qRaw, eodRaw, ratingsRaw, skipsRaw] = await Promise.all([
      redis.get('wingman-questions'),
      redis.get('compliance-eod-inspections'),
      redis.get('wingman-ratings'),
      redis.get('wingman-review-skips')
    ]);
    const questions = qRaw ? JSON.parse(qRaw) : [];
    const questionsConfigured = Array.isArray(questions) && questions.some(q => (q || '').trim());
    const eods = eodRaw ? JSON.parse(eodRaw) : [];
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];
    const skips = skipsRaw ? JSON.parse(skipsRaw) : [];
    const now = Date.now();
    const latestEod = eods
      .filter(e => e.driverName === req.driverName && e.submittedAt && (now - Date.parse(e.submittedAt)) <= WINGMAN_REVIEW_WINDOW_MS)
      .sort((a, b) => b.submittedAt.localeCompare(a.submittedAt))[0];
    if (!latestEod) return res.json({ required: false, questionsConfigured, reviewedNames: [], declaredSolo: false });
    const since = new Date(Date.parse(latestEod.submittedAt) - WINGMAN_REVIEW_LOOKBACK_MS).toISOString();
    const reviewedNames = ratings.filter(r => r.captainName === req.driverName && (r.createdAt || '') >= since).map(r => r.wingmanName);
    const declaredSolo = skips.some(k => k.captainName === req.driverName && (k.createdAt || '') >= since);
    res.json({
      required: questionsConfigured && reviewedNames.length === 0 && !declaredSolo,
      questionsConfigured, reviewedNames, declaredSolo,
      eodSubmittedAt: latestEod.submittedAt
    });
  } catch (err) {
    console.error('Wingman review status failed:', err.message);
    res.status(500).json({ error: 'Could not check wingman review status.' });
  }
});

// A Captain confirming he had no wingman on any job that day -- the only
// way past a required Wingman Review without reviewing someone. Recorded
// so the office can see who's saying it, and how often.
app.post('/api/driver/wingman-review-solo', requireDriverAuth, async (req, res) => {
  try {
    const raw = await redis.get('wingman-review-skips');
    const skips = raw ? JSON.parse(raw) : [];
    skips.push({
      id: 'wrskip_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      captainName: req.driverName,
      date: todayIsoDate(),
      createdAt: new Date().toISOString()
    });
    await redis.set('wingman-review-skips', JSON.stringify(skips));
    res.json({ ok: true });
  } catch (err) {
    console.error('Wingman review solo declaration failed:', err.message);
    res.status(500).json({ error: 'Could not save that.' });
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
  const { neighborhoodId, neighborhoodName } = req.body || {};
  const driverName = req.driverName;
  if (!neighborhoodId) {
    return res.status(400).json({ error: 'Neighborhood is required.' });
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

app.post('/api/driver/pretrip', requireDriverOrTaskWingman(['pretrip'], 'pretrip'), async (req, res) => {
  const { truckId, truckNickname, date, odometer, checklist, additionalNotes, backPhoto } = req.body || {};
  const driverName = req.driverName;
  if (!truckId || !Array.isArray(checklist) || checklist.length === 0) {
    return res.status(400).json({ error: 'Truck and checklist are required.' });
  }
  if (!backPhoto || typeof backPhoto !== 'string' || !backPhoto.startsWith('data:image/')) {
    return res.status(400).json({ error: 'A photo of the back of the truck is required.' });
  }
  const inspectionDate = date || new Date().toISOString().slice(0, 10);
  try {
    // A Materials Checkout must be on file for this driver, for this same
    // date, before their Pre-Trip Inspection can be submitted. Enforced
    // here (not just in the UI) so it can't be bypassed by calling this
    // endpoint directly.
    const checkoutsRaw = await redis.get('materials-checkouts');
    const checkouts = checkoutsRaw ? JSON.parse(checkoutsRaw) : [];
    const hasCheckoutToday = checkouts.some(c => c.driverName === driverName && c.date === inspectionDate);
    if (!hasCheckoutToday) {
      return res.status(400).json({ error: 'Please complete a Materials Checkout for today before submitting your Pre-Trip Inspection.', requiresMaterialsCheckout: true });
    }

    const raw = await redis.get('compliance-pretrip-inspections');
    const records = raw ? JSON.parse(raw) : [];
    const hasDefect = checklist.some(c => c.status === 'defect');
    const id = 'pti_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    // Stored as its own blob key (not inline on the record) so the main PTI
    // list stays lean -- same pattern as Completed Paperwork uploads.
    const backPhotoKey = 'compliance-pti-photo-' + id;
    await redis.set(backPhotoKey, JSON.stringify(backPhoto));
    records.push({
      id,
      truckId, truckNickname: truckNickname || '',
      driverName: String(driverName).slice(0, 100),
      date: inspectionDate,
      odometer: odometer || '',
      checklist,
      overallStatus: hasDefect ? 'defects' : 'ok',
      additionalNotes: (additionalNotes || '').slice(0, 2000),
      backPhotoKey,
      ...(req.actingWingmanName ? { completedByWingman: String(req.actingWingmanName).slice(0, 100) } : {}),
      submittedAt: new Date().toISOString()
    });
    await redis.set('compliance-pretrip-inspections', JSON.stringify(records));
    res.json({ ok: true });
  } catch (err) {
    console.error('Pre-trip submission failed:', err.message);
    res.status(500).json({ error: 'Could not submit inspection.' });
  }
});

// Materials list for the driver checkout form -- item identity only (number
// and description), never price or minimum-quantity, which are internal
// inventory-management fields with no reason to be driver-visible.
app.get('/api/driver/materials-items', requireDriverOrTaskWingman(null), async (req, res) => {
  try {
    const raw = await redis.get('materials-items');
    const items = raw ? JSON.parse(raw) : [];
    res.json({ items: items.map(i => ({ id: i.id, supplierItemNumber: i.supplierItemNumber, description: i.description, nickname: i.nickname })) });
  } catch (err) {
    console.error('Driver materials list failed:', err.message);
    res.status(500).json({ error: 'Could not load materials.' });
  }
});

// The authenticated driver's own jobs scheduled for today -- powers the
// Materials Checkout job dropdown in Pre-Trip Inspection, so a Captain
// with more than one job that day can tie each checkout to the correct
// one instead of typing job numbers freehand (which used to double-count
// the full quantity against every job typed, rather than splitting it).
app.get('/api/driver/today-jobs', requireDriverOrTaskWingman(null), async (req, res) => {
  try {
    const archiveRaw = await redis.get(JOB_ARCHIVE_KEY);
    const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
    const todayStr = new Date().toISOString().slice(0, 10);
    const jobs = archive
      .filter(j => j.captainName === req.driverName && j.assignmentDate === todayStr && j.jobNumber)
      .map(j => ({ jobNumber: j.jobNumber, clientName: j.clientName || '' }));
    res.json({ jobs });
  } catch (err) {
    console.error('Driver today-jobs fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load today\u2019s jobs.' });
  }
});

// Lets the driver portal check -- before a driver fills out the whole
// Pre-Trip Inspection form -- whether today's Materials Checkout is already
// on file, so it can redirect them proactively instead of only rejecting
// the PTI submission afterward. The actual enforcement lives in
// /api/driver/pretrip itself; this is just for a better prompt.
app.get('/api/driver/materials-checkout-status', requireDriverOrTaskWingman(null), async (req, res) => {
  const driverName = req.driverName;
  const date = (req.query.date || new Date().toISOString().slice(0, 10)).toString();
  try {
    const raw = await redis.get('materials-checkouts');
    const checkouts = raw ? JSON.parse(raw) : [];
    const hasCheckoutToday = checkouts.some(c => c.driverName === driverName && c.date === date);
    res.json({ hasCheckoutToday });
  } catch (err) {
    console.error('Materials checkout status check failed:', err.message);
    res.status(500).json({ error: 'Could not check checkout status.' });
  }
});

app.post('/api/driver/materials-checkout', requireDriverOrTaskWingman(['pretrip', 'materials-checkout']), async (req, res) => {
  const { jobNumbers, items, date } = req.body || {};
  const driverName = req.driverName;
  const cleanItems = Array.isArray(items)
    ? items.filter(i => i && i.itemId && Number(i.quantity) > 0).map(i => ({ itemId: String(i.itemId), quantity: Math.floor(Number(i.quantity)) }))
    : [];
  const cleanJobNumbers = Array.isArray(jobNumbers) ? jobNumbers.map(j => String(j).trim()).filter(Boolean) : [];
  const totalQuantity = cleanItems.reduce((sum, i) => sum + i.quantity, 0);
  // A job number is only required when something was actually taken --
  // reporting "nothing today" needs no job to attribute it to.
  if (totalQuantity > 0 && cleanJobNumbers.length === 0) {
    return res.status(400).json({ error: 'At least one Job Number is required when materials were taken.' });
  }
  const checkoutDate = date || new Date().toISOString().slice(0, 10);
  try {
    const [itemsRaw, checkoutsRaw] = await Promise.all([
      redis.get('materials-items'),
      redis.get('materials-checkouts')
    ]);
    const materialsItems = itemsRaw ? JSON.parse(itemsRaw) : [];
    const checkouts = checkoutsRaw ? JSON.parse(checkoutsRaw) : [];

    // Snapshot item number/description onto the checkout record itself, so
    // this checkout's history stays accurate and readable even if an item
    // is later renamed or deleted from the active list.
    const itemsById = new Map(materialsItems.map(i => [i.id, i]));
    const checkoutItems = cleanItems.map(i => {
      const item = itemsById.get(i.itemId);
      return {
        itemId: i.itemId,
        supplierItemNumber: item ? item.supplierItemNumber : '',
        description: item ? item.description : '(item no longer on file)',
        quantity: i.quantity
      };
    });

    checkouts.push({
      id: 'checkout_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      driverName: String(driverName).slice(0, 100),
      date: checkoutDate,
      jobNumbers: cleanJobNumbers,
      items: checkoutItems,
      ...(req.actingWingmanName ? { completedByWingman: String(req.actingWingmanName).slice(0, 100) } : {}),
      checkedOutAt: new Date().toISOString()
    });

    // Checking materials out of the racks decrements on-hand inventory --
    // this is the one place quantityOnHand actually goes down.
    cleanItems.forEach(i => {
      const item = itemsById.get(i.itemId);
      if (item) item.quantityOnHand = Math.max(0, (Number(item.quantityOnHand) || 0) - i.quantity);
    });

    await Promise.all([
      redis.set('materials-items', JSON.stringify(materialsItems)),
      redis.set('materials-checkouts', JSON.stringify(checkouts))
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Materials checkout submission failed:', err.message);
    res.status(500).json({ error: 'Could not submit checkout.' });
  }
});

// ============ Driver: End of Day Inspection ============
// Requires a photo of the truck's cargo area, plus quantities of any unused
// packing materials being returned to the racks. Returned quantities credit
// back to inventory (the mirror of Materials Checkout decrementing it), and
// are also the basis for netting "actually used" against what was billed --
// see the Materials tile's Underbilled Jobs comparison.
const COMPARE_TRUCK_PHOTOS_TOOL = {
  name: 'compare_truck_photos',
  description: 'Compare a moving truck\u2019s cargo area photo from the start and end of the day, and flag any equipment issues.',
  input_schema: {
    type: 'object',
    properties: {
      issues: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            issue: { type: 'string', description: 'A short, specific description, e.g. "Missing furniture dolly", "Moving blankets not folded", "Fewer blankets visible than this morning".' },
            severity: { type: 'string', enum: ['minor', 'moderate'], description: 'How significant this looks.' }
          },
          required: ['issue', 'severity']
        },
        description: 'Equipment issues noticed between the two photos -- missing items (dollies, moving blankets, straps, hand trucks), blankets left unfolded or messy, or anything that looks damaged or different in a way that matters for equipment upkeep. Do not flag ordinary cargo/boxes changing, since that\u2019s expected as jobs get completed. Empty array if the truck looks properly equipped and organized in both photos.'
      },
      summary: { type: 'string', description: 'One sentence overall assessment.' }
    },
    required: ['issues', 'summary']
  }
};

async function compareTruckPhotos(ptiPhotoDataUri, eodPhotoDataUri) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { status: 'failed', issues: [], summary: '' };
  const ptiMatch = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(ptiPhotoDataUri || '');
  const eodMatch = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(eodPhotoDataUri || '');
  if (!ptiMatch || !eodMatch) return { status: 'failed', issues: [], summary: '' };
  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [COMPARE_TRUCK_PHOTOS_TOOL],
        tool_choice: { type: 'tool', name: 'compare_truck_photos' },
        messages: [{
          role: 'user',
          content: [
            { type: 'text', text: 'This first photo is the back/cargo area of a moving truck, taken this morning during Pre-Trip Inspection:' },
            { type: 'image', source: { type: 'base64', media_type: ptiMatch[1], data: ptiMatch[2] } },
            { type: 'text', text: 'This second photo is the same truck, taken this evening during End of Day Inspection:' },
            { type: 'image', source: { type: 'base64', media_type: eodMatch[1], data: eodMatch[2] } },
            { type: 'text', text: 'Compare the two. Flag any equipment issues: missing items (dollies, moving blankets, straps, hand trucks), blankets left unfolded or not properly stored, or anything that looks damaged. Do not flag ordinary cargo/box changes, since that\u2019s expected as jobs get completed during the day.' }
          ]
        }]
      })
    });
    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Truck photo comparison failed:', anthropicRes.status, errBody);
      return { status: 'failed', issues: [], summary: '' };
    }
    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'compare_truck_photos');
    if (!toolUseBlock) return { status: 'failed', issues: [], summary: '' };
    const issues = Array.isArray(toolUseBlock.input.issues) ? toolUseBlock.input.issues : [];
    return { status: issues.length > 0 ? 'issues_found' : 'ok', issues, summary: toolUseBlock.input.summary || '' };
  } catch (err) {
    console.error('Truck photo comparison failed:', err.message);
    return { status: 'failed', issues: [], summary: '' };
  }
}

// ============ Junk Removal: volume estimation ============
const JUNK_REMOVAL_TIERS = [
  '1/8', '1/6', '1/4', '1/3', '3/8', '1/2', '5/8', '2/3', '3/4', '5/6', '7/8', 'full'
];

const ESTIMATE_JUNK_VOLUME_TOOL = {
  name: 'estimate_junk_volume',
  description: 'Estimate what fraction of a moving truck a pile of junk/furniture/trash would fill, or how full a truck bed already is.',
  input_schema: {
    type: 'object',
    properties: {
      tier: {
        type: 'string',
        enum: JUNK_REMOVAL_TIERS,
        description: 'The closest matching fraction of a full truckload.'
      },
      reasoning: {
        type: 'string',
        description: 'One or two sentences explaining the estimate -- mention the key items/volume you\u2019re weighing and how they compare to the fridge-volume reference.'
      }
    },
    required: ['tier', 'reasoning']
  }
};

const JUNK_VOLUME_REFERENCE_TEXT = 'A College HUNKS junk removal truck holds up to 8 full-size refrigerators\u2019 worth of volume standing upright -- each 1/8 of the truck equals one of those refrigerators. Use that as your reference scale when judging size.';

async function estimateJunkVolume(photoDataUris, stage) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { status: 'failed', tier: null, reasoning: '' };
  const images = (photoDataUris || [])
    .map(uri => /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(uri || ''))
    .filter(Boolean);
  if (images.length === 0) return { status: 'failed', tier: null, reasoning: '' };

  const framingText = stage === 'final'
    ? `This photo (or photos) shows a moving truck bed already loaded with junk/furniture/items. ${JUNK_VOLUME_REFERENCE_TEXT} Looking at how much of the truck bed is filled in the photo(s), estimate the closest tier.`
    : `This photo (or photos) shows a pile of junk, furniture, or trash that needs to be removed and hauled away, before it has been loaded into a truck. ${JUNK_VOLUME_REFERENCE_TEXT} Estimate how much of the truck these items would fill once loaded, and pick the closest tier.`;

  const content = [{ type: 'text', text: framingText }];
  images.forEach(m => content.push({ type: 'image', source: { type: 'base64', media_type: m[1], data: m[2] } }));

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [ESTIMATE_JUNK_VOLUME_TOOL],
        tool_choice: { type: 'tool', name: 'estimate_junk_volume' },
        messages: [{ role: 'user', content }]
      })
    });
    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Junk volume estimate failed:', anthropicRes.status, errBody);
      return { status: 'failed', tier: null, reasoning: '' };
    }
    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'estimate_junk_volume');
    if (!toolUseBlock) return { status: 'failed', tier: null, reasoning: '' };
    return { status: 'ok', tier: toolUseBlock.input.tier, reasoning: toolUseBlock.input.reasoning || '' };
  } catch (err) {
    console.error('Junk volume estimate failed:', err.message);
    return { status: 'failed', tier: null, reasoning: '' };
  }
}

async function getJunkRemovalPricing() {
  try {
    const raw = await redis.get(APP_SETTINGS_KEY);
    const saved = raw ? JSON.parse(raw) : null;
    const merged = mergeAppSettings(saved);
    return merged.junkRemoval.pricing;
  } catch (err) {
    console.error('Could not load junk removal pricing, using defaults:', err.message);
    return DEFAULT_APP_SETTINGS.junkRemoval.pricing;
  }
}

app.post('/api/driver/eod-inspection', requireDriverOrTaskWingman(['eod'], 'eod'), async (req, res) => {
  const { truckId, truckNickname, date, jobNumbers, returnedItems, backPhoto, additionalNotes } = req.body || {};
  const driverName = req.driverName;
  if (!truckId) {
    return res.status(400).json({ error: 'Truck is required.' });
  }
  if (!backPhoto || typeof backPhoto !== 'string' || !backPhoto.startsWith('data:image/')) {
    return res.status(400).json({ error: 'A photo of the back of the truck is required.' });
  }
  const cleanReturnedItems = Array.isArray(returnedItems)
    ? returnedItems.filter(i => i && i.itemId && Number(i.quantity) > 0).map(i => ({ itemId: String(i.itemId), quantity: Math.floor(Number(i.quantity)) }))
    : [];
  const cleanJobNumbers = Array.isArray(jobNumbers) ? jobNumbers.map(j => String(j).trim()).filter(Boolean) : [];
  const totalReturned = cleanReturnedItems.reduce((sum, i) => sum + i.quantity, 0);
  // A job number is required when returning something, same reasoning as
  // checkout -- it's what lets the return be credited to the right job.
  if (totalReturned > 0 && cleanJobNumbers.length === 0) {
    return res.status(400).json({ error: 'At least one Job Number is required when returning materials, so it can be credited to the right job.' });
  }
  const inspectionDate = date || new Date().toISOString().slice(0, 10);

  try {
    const [itemsRaw, eodRaw, ptiRaw] = await Promise.all([
      redis.get('materials-items'),
      redis.get('compliance-eod-inspections'),
      redis.get('compliance-pretrip-inspections')
    ]);
    const materialsItems = itemsRaw ? JSON.parse(itemsRaw) : [];
    const eodRecords = eodRaw ? JSON.parse(eodRaw) : [];
    const ptiRecords = ptiRaw ? JSON.parse(ptiRaw) : [];

    const itemsById = new Map(materialsItems.map(i => [i.id, i]));
    const returnedItemDetails = cleanReturnedItems.map(i => {
      const item = itemsById.get(i.itemId);
      return {
        itemId: i.itemId,
        supplierItemNumber: item ? item.supplierItemNumber : '',
        description: item ? item.description : '(item no longer on file)',
        quantity: i.quantity
      };
    });

    // Returning materials to the racks credits inventory back -- the mirror
    // of Materials Checkout decrementing it.
    cleanReturnedItems.forEach(i => {
      const item = itemsById.get(i.itemId);
      if (item) item.quantityOnHand = (Number(item.quantityOnHand) || 0) + i.quantity;
    });

    const id = 'eod_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    const backPhotoKey = 'compliance-eod-photo-' + id;
    await redis.set(backPhotoKey, JSON.stringify(backPhoto));

    // Same truck, same date's PTI photo is the "before" picture -- if it's
    // on file, compare now so the finding is ready as soon as the admin
    // looks at Captain Metrics, rather than computed on demand later.
    const matchingPti = ptiRecords.find(p => p.truckId === truckId && p.date === inspectionDate && p.backPhotoKey);
    let visionStatus = 'no_pti_photo';
    let visionIssues = [];
    let visionSummary = '';
    if (matchingPti) {
      try {
        const ptiPhotoRaw = await redis.get(matchingPti.backPhotoKey);
        const ptiPhoto = ptiPhotoRaw ? JSON.parse(ptiPhotoRaw) : null;
        if (ptiPhoto) {
          const result = await compareTruckPhotos(ptiPhoto, backPhoto);
          visionStatus = result.status;
          visionIssues = result.issues;
          visionSummary = result.summary;
        }
      } catch (err) {
        console.error('Truck photo lookup/comparison failed:', err.message);
        visionStatus = 'failed';
      }
    }

    eodRecords.push({
      id,
      truckId, truckNickname: truckNickname || '',
      driverName: String(driverName).slice(0, 100),
      date: inspectionDate,
      jobNumbers: cleanJobNumbers,
      returnedItems: returnedItemDetails,
      backPhotoKey,
      additionalNotes: (additionalNotes || '').slice(0, 2000),
      visionStatus, visionIssues, visionSummary,
      ...(req.actingWingmanName ? { completedByWingman: String(req.actingWingmanName).slice(0, 100) } : {}),
      submittedAt: new Date().toISOString()
    });

    // Feeds Manager Review's Truck Conditions tab -- a discrete, reviewable
    // record separate from the EOD record itself, since it needs its own
    // independent reviewed/open state that a live re-scan of eodRecords
    // couldn't track.
    if (visionStatus === 'issues_found' && Array.isArray(visionIssues) && visionIssues.length > 0) {
      try {
        const reviewRaw = await redis.get('manager-review-items');
        const reviewItems = reviewRaw ? JSON.parse(reviewRaw) : [];
        reviewItems.push({
          id: 'mgrreview_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
          type: 'truck-condition',
          createdAt: new Date().toISOString(),
          reviewedAt: null,
          reviewedBy: null,
          eodRecordId: id,
          driverName: String(driverName).slice(0, 100),
          truckNickname: truckNickname || '',
          date: inspectionDate,
          visionSummary,
          visionIssues
        });
        await redis.set('manager-review-items', JSON.stringify(reviewItems));
      } catch (err) {
        console.error('Manager review truck-condition write failed:', err.message);
      }
    }

    await Promise.all([
      redis.set('materials-items', JSON.stringify(materialsItems)),
      redis.set('compliance-eod-inspections', JSON.stringify(eodRecords))
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('End of day inspection submission failed:', err.message);
    res.status(500).json({ error: 'Could not submit inspection.' });
  }
});

// ============ Material Checkin (standalone) ============
// The returned-materials half of End of Day Inspection, on its own, for
// when a Captain hands just that part to a wingman. Same shape as an EOD
// record's jobNumbers/returnedItems, kept in its own key so it never
// counts as an End of Day Inspection for compliance -- the Materials
// reconciliation reads both. Credits inventory back exactly like EOD does.
app.post('/api/driver/materials-checkin', requireDriverOrTaskWingman(['materials-checkin'], 'materials-checkin'), async (req, res) => {
  const { jobNumbers, returnedItems, date } = req.body || {};
  const cleanReturnedItems = Array.isArray(returnedItems)
    ? returnedItems.filter(i => i && i.itemId && Number(i.quantity) > 0).map(i => ({ itemId: String(i.itemId), quantity: Math.floor(Number(i.quantity)) }))
    : [];
  const cleanJobNumbers = Array.isArray(jobNumbers) ? jobNumbers.map(j => String(j).trim()).filter(Boolean) : [];
  const totalReturned = cleanReturnedItems.reduce((sum, i) => sum + i.quantity, 0);
  if (totalReturned > 0 && cleanJobNumbers.length === 0) {
    return res.status(400).json({ error: 'At least one Job Number is required when returning materials, so it can be credited to the right job.' });
  }
  try {
    const [itemsRaw, checkinsRaw] = await Promise.all([
      redis.get('materials-items'),
      redis.get('materials-checkins')
    ]);
    const materialsItems = itemsRaw ? JSON.parse(itemsRaw) : [];
    const checkins = checkinsRaw ? JSON.parse(checkinsRaw) : [];
    const itemsById = new Map(materialsItems.map(i => [i.id, i]));
    const returnedItemDetails = cleanReturnedItems.map(i => {
      const item = itemsById.get(i.itemId);
      return {
        itemId: i.itemId,
        supplierItemNumber: item ? item.supplierItemNumber : '',
        description: item ? item.description : '(item no longer on file)',
        quantity: i.quantity
      };
    });
    cleanReturnedItems.forEach(i => {
      const item = itemsById.get(i.itemId);
      if (item) item.quantityOnHand = (Number(item.quantityOnHand) || 0) + i.quantity;
    });
    checkins.push({
      id: 'checkin_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      driverName: String(req.driverName).slice(0, 100),
      date: date || todayIsoDate(),
      jobNumbers: cleanJobNumbers,
      returnedItems: returnedItemDetails,
      ...(req.actingWingmanName ? { completedByWingman: String(req.actingWingmanName).slice(0, 100) } : {}),
      submittedAt: new Date().toISOString()
    });
    await Promise.all([
      redis.set('materials-items', JSON.stringify(materialsItems)),
      redis.set('materials-checkins', JSON.stringify(checkins))
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Material checkin failed:', err.message);
    res.status(500).json({ error: 'Could not submit material checkin.' });
  }
});

// ============ Weight Tickets (Long Distance Moves) ============
// A Captain on a Long Distance Move photographs two scale tickets -- the
// truck weighed empty and weighed full. Each ticket's highest printed
// weight is read with Claude; the load's weight is the higher of the two
// minus the lower. The photos are held here only until that job's invoice
// is uploaded on Job Paperwork, which then appends them to the client's
// completed paperwork package and deletes them.
const WEIGHT_TICKETS_KEY = 'weight-tickets';
const WEIGHT_TICKET_KINDS = ['empty', 'full'];
const READ_WEIGHT_TICKET_TOOL = {
  name: 'read_weight_ticket',
  description: 'Report the weights printed on a truck scale ticket.',
  input_schema: {
    type: 'object',
    properties: {
      isWeightTicket: { type: 'boolean', description: 'True if this is a photo of a vehicle scale / weigh station ticket or receipt.' },
      weights: {
        type: 'array',
        description: 'Every weight figure printed on the ticket, exactly as printed (e.g. gross, tare, net, steer/drive/trailer axle, total).',
        items: { type: 'object', properties: { label: { type: 'string' }, value: { type: 'number' } }, required: ['value'] }
      },
      highestWeight: { type: 'number', description: 'The single largest weight printed on the ticket. Usually the gross or total weight. Use 0 if none can be read.' },
      unit: { type: 'string', enum: ['lb', 'kg'], description: 'Unit of the weights. US truck scales print pounds (lb).' },
      confident: { type: 'boolean', description: 'False if the photo is blurry, cut off, or the numbers are hard to read.' }
    },
    required: ['isWeightTicket', 'weights', 'highestWeight', 'unit', 'confident']
  }
};

async function readWeightTicketPhoto(photoDataUri) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(photoDataUri || '');
  if (!apiKey || !match) return { error: 'Could not read that photo.' };
  const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      tools: [READ_WEIGHT_TICKET_TOOL],
      tool_choice: { type: 'tool', name: 'read_weight_ticket' },
      messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } },
        { type: 'text', text: 'This is a photo of a truck scale weight ticket from a moving company\u2019s truck. List every weight printed on it, and report the highest one. Read digits carefully -- a misread digit changes the bill.' }
      ] }]
    })
  });
  if (!anthropicRes.ok) {
    console.error('Weight ticket read failed:', anthropicRes.status, await anthropicRes.text().catch(() => ''));
    return { error: 'Could not read the ticket right now \u2014 try again in a moment.' };
  }
  const data = await anthropicRes.json();
  const block = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'read_weight_ticket');
  if (!block) return { error: 'Could not read the ticket \u2014 try again.' };
  const r = block.input || {};
  // The highest weight is taken from the individual figures too, in case
  // the model's own "highest" disagrees with what it listed.
  const listed = (Array.isArray(r.weights) ? r.weights : []).map(w => Number(w.value)).filter(v => v > 0);
  let highest = Math.max(Number(r.highestWeight) || 0, ...listed, 0);
  if (r.unit === 'kg') highest = Math.round(highest * 2.20462);
  return { isWeightTicket: !!r.isWeightTicket, highestWeight: Math.round(highest), weights: r.weights || [], unitRead: r.unit || 'lb', confident: !!r.confident };
}

// The Captain's Long Distance Moves for today (Eastern), plus yesterday's,
// so a ticket from a late finish can still be added the next morning.
async function captainLongDistanceJobs(captainName) {
  const archiveRaw = await redis.get(JOB_ARCHIVE_KEY);
  const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
  const today = easternDateFromMs(Date.now());
  const yesterday = easternDateFromMs(Date.now() - 24 * 60 * 60 * 1000);
  return archive.filter(j => j.jobNumber && j.jobType === 'longdistance' &&
    nameDedupKey(j.captainName || '') === nameDedupKey(captainName) &&
    (j.assignmentDate === today || j.assignmentDate === yesterday));
}

function summarizeWeightTicketJob(job, tickets, today) {
  const forJob = tickets.filter(t => t.jobNumber === job.jobNumber);
  const pick = kind => {
    const t = forJob.find(x => x.kind === kind);
    return t ? { highestWeight: t.highestWeight, uploadedAt: t.uploadedAt, confident: t.confident } : null;
  };
  const empty = pick('empty'), full = pick('full');
  const netWeight = empty && full ? Math.abs(full.highestWeight - empty.highestWeight) : null;
  return { jobNumber: job.jobNumber, clientName: job.clientName || '', assignmentDate: job.assignmentDate, isToday: job.assignmentDate === today, empty, full, netWeight };
}

app.get('/api/driver/weight-tickets', requireDriverAuth, async (req, res) => {
  try {
    const [jobs, raw] = await Promise.all([captainLongDistanceJobs(req.driverName), redis.get(WEIGHT_TICKETS_KEY)]);
    const tickets = raw ? JSON.parse(raw) : [];
    const today = easternDateFromMs(Date.now());
    // Yesterday's job only stays on the list while it's still missing a ticket.
    const summaries = jobs.map(j => summarizeWeightTicketJob(j, tickets, today))
      .filter(sm => sm.isToday || !(sm.empty && sm.full));
    res.json({ jobs: summaries });
  } catch (err) {
    console.error('Weight tickets fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load weight tickets.' });
  }
});

// Reads and stores one ticket for a job; shared by the Captain's upload
// and the office's upload at work package closure. A retake replaces the
// earlier ticket of the same kind.
async function saveWeightTicket(job, kind, photo, uploadedBy, uploaderName) {
  if (!WEIGHT_TICKET_KINDS.includes(kind)) return { status: 400, body: { error: 'Say which ticket this is \u2014 empty or full.' } };
  if (typeof photo !== 'string' || !photo.startsWith('data:image/')) return { status: 400, body: { error: 'Take a photo of the ticket first.' } };
  const reading = await readWeightTicketPhoto(photo);
  if (reading.error) return { status: 502, body: { error: reading.error } };
  if (!reading.isWeightTicket || !reading.highestWeight) {
    return { status: 422, body: { error: 'Couldn\u2019t find a weight on that photo. Retake it straight-on, close enough to read the numbers, with no glare.' } };
  }
  const raw = await redis.get(WEIGHT_TICKETS_KEY);
  const tickets = raw ? JSON.parse(raw) : [];
  const previous = tickets.filter(t => t.jobNumber === job.jobNumber && t.kind === kind);
  const id = 'wt_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
  const kept = tickets.filter(t => !(t.jobNumber === job.jobNumber && t.kind === kind));
  kept.push({
    id, jobNumber: job.jobNumber, kind, captainName: job.captainName || '', jobDate: job.assignmentDate,
    highestWeight: reading.highestWeight, weights: reading.weights, unitRead: reading.unitRead, confident: reading.confident,
    // 'captain' from the Driver Portal; 'office' when the Ops Manager had
    // to upload it at closure -- i.e. the Captain didn't.
    uploadedBy, uploaderName: String(uploaderName || '').slice(0, 100),
    photoKey: 'weight-ticket-photo-' + id, uploadedAt: new Date().toISOString(), mergedAt: null
  });
  // Stored JSON-encoded like every other /api/data value, so the
  // dashboard can read it back.
  await redis.set('weight-ticket-photo-' + id, JSON.stringify(photo));
  await redis.set(WEIGHT_TICKETS_KEY, JSON.stringify(kept));
  if (previous.length) await redis.del(...previous.map(t => t.photoKey));
  return { status: 200, body: { ok: true, job: summarizeWeightTicketJob(job, kept, easternDateFromMs(Date.now())) } };
}

app.post('/api/driver/weight-ticket', requireDriverAuth, async (req, res) => {
  const { jobNumber, kind, photo } = req.body || {};
  try {
    const jobs = await captainLongDistanceJobs(req.driverName);
    const job = jobs.find(j => j.jobNumber === String(jobNumber));
    if (!job) return res.status(403).json({ error: 'That isn\u2019t one of your Long Distance Moves today.' });
    const result = await saveWeightTicket(job, kind, photo, 'captain', req.driverName);
    res.status(result.status).json(result.body);
  } catch (err) {
    console.error('Weight ticket upload failed:', err.message);
    res.status(500).json({ error: 'Could not save that weight ticket.' });
  }
});

// The office side: any Long Distance Move, any date -- used when a
// Captain handed in paper tickets instead of uploading them.
app.post('/api/admin/weight-ticket', requireAuth, async (req, res) => {
  const { jobNumber, kind, photo } = req.body || {};
  try {
    const archiveRaw = await redis.get(JOB_ARCHIVE_KEY);
    const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
    const job = archive.find(j => j.jobNumber === String(jobNumber) && j.jobType === 'longdistance');
    if (!job) return res.status(404).json({ error: 'That job isn\u2019t on file as a Long Distance Move.' });
    const result = await saveWeightTicket(job, kind, photo, 'office', req.userEmail);
    res.status(result.status).json(result.body);
  } catch (err) {
    console.error('Office weight ticket upload failed:', err.message);
    res.status(500).json({ error: 'Could not save that weight ticket.' });
  }
});

// ============ Closed damage claims, shown to the crew ============
// When a damage claim is closed (its Resolution moved off Pending), the
// Captain and any wingmen it's charged to see it in their portal: the
// damage photos, the outcome, and their share coming off commission. Each
// person clears their own copy with "Reviewed". Acknowledgements live in
// their own key so the dashboard saving a claim never wipes them out.
const DAMAGE_ACKS_KEY = 'damage-claim-crew-acks';
const DAMAGE_RES_LABELS = { repaired: 'Repaired', replaced: 'Replaced', reimbursed: 'Reimbursed', denied: 'Denied', no_damage_found: 'No Damage Found' };

async function crewDamageNoticesFor(personName) {
  const [claimsRaw, archiveRaw, acksRaw, reportsRaw] = await Promise.all([
    redis.get('damage-claims'), redis.get(JOB_ARCHIVE_KEY), redis.get(DAMAGE_ACKS_KEY), redis.get('moving-damage-reports')
  ]);
  const claims = claimsRaw ? JSON.parse(claimsRaw) : [];
  const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
  const acks = acksRaw ? JSON.parse(acksRaw) : {};
  const reports = reportsRaw ? JSON.parse(reportsRaw) : [];
  const me = nameDedupKey(personName);
  const cutoff = easternDateFromMs(Date.now() - 60 * 24 * 60 * 60 * 1000);
  const out = [];
  claims.forEach(c => {
    const res = c.resolution || 'pending';
    if (res === 'pending') return;
    const closedOn = c.resolvedDate || String(c.createdAt || '').slice(0, 10);
    if (closedOn < cutoff) return;
    const job = archive.find(j => String(j.jobNumber) === String(c.jobNumber)) || {};
    const captain = c.costCaptainName || job.captainName || '';
    const crew = [...new Set([captain, ...(c.costWingmen || [])].filter(Boolean))];
    if (!crew.some(n => nameDedupKey(n) === me)) return;
    if (acks[c.id] && acks[c.id][me]) return;
    const cost = Number(c.totalCost) || 0;
    const deducted = cost > 0 && c.costRecordedAt;
    const share = deducted ? Math.round(cost / crew.length * 100) / 100 : 0;
    const report = reports.find(r => String(r.jobNumber) === String(c.jobNumber)) || {};
    out.push({
      claimId: c.id, jobNumber: c.jobNumber, clientName: c.clientName || job.clientName || '',
      outcome: DAMAGE_RES_LABELS[res] || 'Closed', closedOn,
      totalCost: cost, share, splitWays: crew.length, jobDate: job.assignmentDate || null,
      photoCount: (c.photos || []).length + (report.causedPhotoKeys || []).length
    });
  });
  return out.sort((a, b) => (b.closedOn || '').localeCompare(a.closedOn || ''));
}

async function crewDamagePhotos(personName, claimId) {
  const notices = await crewDamageNoticesFor(personName);
  const n = notices.find(x => x.claimId === claimId);
  if (!n) return null;
  const claims = JSON.parse(await redis.get('damage-claims') || '[]');
  const c = claims.find(x => x.id === claimId);
  const report = JSON.parse(await redis.get('moving-damage-reports') || '[]').find(r => String(r.jobNumber) === String(c.jobNumber)) || {};
  const keys = [...(c.photos || []).map(p => `damage-claim-photo-${c.id}-${p.id}`), ...(report.causedPhotoKeys || [])].slice(0, 12);
  const photos = [];
  for (const k of keys) {
    const raw = await redis.get(k);
    let uri = null; try { uri = raw ? JSON.parse(raw) : null; } catch (e) { uri = raw; }
    if (typeof uri === 'string' && uri.startsWith('data:image/')) photos.push(uri);
  }
  return photos;
}

async function acknowledgeCrewDamage(personName, claimId) {
  const notices = await crewDamageNoticesFor(personName);
  if (!notices.some(x => x.claimId === claimId)) return false;
  const acks = JSON.parse(await redis.get(DAMAGE_ACKS_KEY) || '{}');
  acks[claimId] = acks[claimId] || {};
  acks[claimId][nameDedupKey(personName)] = { name: personName, at: new Date().toISOString() };
  await redis.set(DAMAGE_ACKS_KEY, JSON.stringify(acks));
  return true;
}

[['/api/driver/damage-notices', requireDriverAuth, req => req.driverName],
 ['/api/wingman/damage-notices', requireWingmanAuth, req => req.wingmanName]].forEach(([base, auth, who]) => {
  app.get(base, auth, async (req, res) => {
    try { res.json({ notices: await crewDamageNoticesFor(who(req)) }); }
    catch (err) { console.error('Damage notices failed:', err.message); res.status(500).json({ error: 'Could not load.' }); }
  });
  app.get(base + '/:claimId/photos', auth, async (req, res) => {
    try {
      const photos = await crewDamagePhotos(who(req), req.params.claimId);
      if (!photos) return res.status(404).json({ error: 'Not found.' });
      res.json({ photos });
    } catch (err) { console.error('Damage notice photos failed:', err.message); res.status(500).json({ error: 'Could not load photos.' }); }
  });
  app.post(base + '/:claimId/reviewed', auth, async (req, res) => {
    try {
      if (!(await acknowledgeCrewDamage(who(req), req.params.claimId))) return res.status(404).json({ error: 'Not found.' });
      console.log(`[damage-notice] ${who(req)} reviewed claim ${req.params.claimId}`);
      res.json({ ok: true });
    } catch (err) { console.error('Damage notice review failed:', err.message); res.status(500).json({ error: 'Could not save.' }); }
  });
});

// ============ Captain -> Wingman task assignment ============
// A Captain's own tasks for today (anything not cancelled), so the
// Driver Portal can show what's assigned, to whom, and whether it's done.
app.get('/api/driver/wingman-tasks', requireDriverAuth, async (req, res) => {
  try {
    const today = todayIsoDate();
    const tasks = (await loadWingmanTasks())
      .filter(t => t.date === today && t.status !== 'cancelled' && nameDedupKey(t.captainName) === nameDedupKey(req.driverName));
    res.json({ tasks, taskTypes: WINGMAN_TASK_TYPES });
  } catch (err) {
    console.error('Captain wingman-task list failed:', err.message);
    res.status(500).json({ error: 'Could not load tasks.' });
  }
});

app.post('/api/driver/wingman-tasks', requireDriverAuth, async (req, res) => {
  const { type, wingmanName } = req.body || {};
  if (!WINGMAN_TASK_TYPES[type]) return res.status(400).json({ error: 'Unknown task.' });
  if (typeof wingmanName !== 'string' || !wingmanName.trim()) return res.status(400).json({ error: 'Pick a wingman.' });
  try {
    // Same eligible list as the Wingman Review dropdown: the payroll roster
    // minus every active driver.
    const [weeksRaw, manualRaw, activeDriverKeys] = await Promise.all([
      redis.get('labor-weeks'),
      redis.get('roster-manual-additions'),
      fetchActiveDriverKeys()
    ]);
    const weeks = weeksRaw ? JSON.parse(weeksRaw) : [];
    const manualAdditions = manualRaw ? JSON.parse(manualRaw) : [];
    const eligible = computeRosterNames(weeks, manualAdditions).filter(n => !activeDriverKeys.has(nameDedupKey(n)));
    const match = eligible.find(n => nameDedupKey(n) === nameDedupKey(wingmanName));
    if (!match) return res.status(400).json({ error: 'That person isn\u2019t on the wingman roster.' });

    const today = todayIsoDate();
    const tasks = await loadWingmanTasks();
    const existing = tasks.find(t => t.date === today && t.type === type && t.status !== 'cancelled' && nameDedupKey(t.captainName) === nameDedupKey(req.driverName));
    if (existing) {
      return res.status(409).json({ error: existing.status === 'open'
        ? `Already assigned to ${existing.wingmanName} \u2014 unassign it first to hand it to someone else.`
        : 'That task is already done for today.' });
    }
    const task = {
      id: 'wtask_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      type,
      captainName: req.driverName,
      wingmanName: match,
      date: today,
      status: 'open',
      createdAt: new Date().toISOString()
    };
    // Keep the list from growing forever: drop anything older than 60 days.
    const cutoff = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const kept = tasks.filter(t => (t.date || '') >= cutoff);
    kept.push(task);
    await redis.set(WINGMAN_TASKS_KEY, JSON.stringify(kept));
    res.json({ ok: true, task });
  } catch (err) {
    console.error('Wingman task assignment failed:', err.message);
    res.status(500).json({ error: 'Could not assign that task.' });
  }
});

app.delete('/api/driver/wingman-tasks/:id', requireDriverAuth, async (req, res) => {
  try {
    const tasks = await loadWingmanTasks();
    const task = tasks.find(t => t.id === req.params.id);
    if (!task || nameDedupKey(task.captainName) !== nameDedupKey(req.driverName)) return res.status(404).json({ error: 'Task not found.' });
    if (task.status !== 'open') return res.status(409).json({ error: 'That task is already done.' });
    task.status = 'cancelled';
    task.cancelledAt = new Date().toISOString();
    await redis.set(WINGMAN_TASKS_KEY, JSON.stringify(tasks));
    res.json({ ok: true });
  } catch (err) {
    console.error('Wingman task cancel failed:', err.message);
    res.status(500).json({ error: 'Could not unassign that task.' });
  }
});

// ============ Wingman Portal endpoints ============
app.get('/api/wingman/motive-locations', requireWingmanAuth, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const result = await fetchMotiveTruckLocations();
  if (result.error) return res.status(result.status).json({ error: result.error });
  res.json({ trucks: result.trucks });
});

// Same current-month scoring the admin Wingman Metrics tile uses, shaped
// exactly like the Captain Leaderboard's response so the portal renders
// it with the same component.
app.get('/api/wingman/leaderboard', requireWingmanAuth, async (req, res) => {
  try {
    const { activeMonth } = await getActiveWingmanMetricsMonth();
    const [ratingsRaw, activeDriverKeys] = await Promise.all([
      redis.get('wingman-ratings'),
      fetchActiveDriverKeys()
    ]);
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];
    const scores = computeWingmanScoresForMonth(activeMonth, ratings, activeDriverKeys);
    const entries = Object.keys(scores)
      .filter(name => scores[name].overall !== null)
      .map(name => ({
        name,
        value: scores[name].overall,
        detail: `${scores[name].ratingCount} Captain review${scores[name].ratingCount === 1 ? '' : 's'}`
      }))
      .sort((a, b) => b.value - a.value);
    const categories = entries.length > 0 ? [{ key: 'overall', title: 'Overall Wingman Score', entries }] : [];
    res.json({ categories });
  } catch (err) {
    console.error('Wingman leaderboard fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load leaderboard.' });
  }
});

// Active Captains to choose from for a Captain Review, plus which ones
// this wingman has already reviewed today.
app.get('/api/wingman/captains', requireWingmanAuth, async (req, res) => {
  try {
    const [driversRaw, ratingsRaw] = await Promise.all([
      redis.get('compliance-drivers'),
      redis.get('captain-ratings')
    ]);
    const drivers = driversRaw ? JSON.parse(driversRaw) : [];
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];
    const names = [...new Set(drivers.filter(d => d && d.active && d.employeeName).map(d => d.employeeName))].sort((a, b) => a.localeCompare(b));
    const today = todayIsoDate();
    const reviewedToday = ratings
      .filter(r => r.date === today && nameDedupKey(r.wingmanName || '') === nameDedupKey(req.wingmanName))
      .map(r => r.captainName);
    res.json({ names, reviewedToday });
  } catch (err) {
    console.error('Wingman captain list failed:', err.message);
    res.status(500).json({ error: 'Could not load Captains.' });
  }
});

app.get('/api/wingman/captain-questions', requireWingmanAuth, async (req, res) => {
  try {
    const raw = await redis.get('captain-questions');
    res.json({ questions: raw ? JSON.parse(raw) : [] });
  } catch (err) {
    console.error('Captain questions fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load questions.' });
  }
});

// One set of yes/no answers from one wingman about one Captain. The
// wingman's name comes from the session, never the request body. One
// review per Captain per wingman per day.
app.post('/api/wingman/captain-rating', requireWingmanAuth, async (req, res) => {
  const { captainName, answers } = req.body || {};
  if (typeof captainName !== 'string' || !captainName.trim()) return res.status(400).json({ error: 'captainName is required.' });
  if (!Array.isArray(answers) || answers.length === 0 || answers.some(a => !a || typeof a.question !== 'string' || typeof a.answer !== 'boolean')) {
    return res.status(400).json({ error: 'answers must be a non-empty array of { question, answer }.' });
  }
  try {
    const [driversRaw, ratingsRaw] = await Promise.all([
      redis.get('compliance-drivers'),
      redis.get('captain-ratings')
    ]);
    const drivers = driversRaw ? JSON.parse(driversRaw) : [];
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];
    const captain = drivers.find(d => d && d.active && nameDedupKey(d.employeeName || '') === nameDedupKey(captainName));
    if (!captain) return res.status(400).json({ error: 'That Captain isn\u2019t on the active driver list.' });
    const today = todayIsoDate();
    const dup = ratings.some(r => r.date === today && nameDedupKey(r.captainName || '') === nameDedupKey(captain.employeeName) && nameDedupKey(r.wingmanName || '') === nameDedupKey(req.wingmanName));
    if (dup) return res.status(409).json({ error: 'You already reviewed this Captain today.' });
    ratings.push({
      id: 'cr_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      wingmanName: req.wingmanName,
      captainName: captain.employeeName,
      date: today,
      answers: answers.map(a => ({ question: String(a.question).slice(0, 300), answer: !!a.answer })),
      createdAt: new Date().toISOString()
    });
    await redis.set('captain-ratings', JSON.stringify(ratings));
    res.json({ ok: true });
  } catch (err) {
    console.error('Captain rating submission failed:', err.message);
    res.status(500).json({ error: 'Could not save that Captain review.' });
  }
});

// Today's tasks assigned to this wingman. An open Pre-Trip or End of Day
// task the Captain went ahead and did himself is closed out here, so the
// wingman isn't sent to redo it.
app.get('/api/wingman/tasks', requireWingmanAuth, async (req, res) => {
  try {
    const today = todayIsoDate();
    const [tasks, ptiRaw, eodRaw] = await Promise.all([
      loadWingmanTasks(),
      redis.get('compliance-pretrip-inspections'),
      redis.get('compliance-eod-inspections')
    ]);
    const ptis = ptiRaw ? JSON.parse(ptiRaw) : [];
    const eods = eodRaw ? JSON.parse(eodRaw) : [];
    let changed = false;
    const mine = tasks.filter(t => t.date === today && t.status !== 'cancelled' && nameDedupKey(t.wingmanName) === nameDedupKey(req.wingmanName));
    mine.forEach(t => {
      if (t.status !== 'open') return;
      const records = t.type === 'pretrip' ? ptis : (t.type === 'eod' ? eods : null);
      if (records && records.some(r => r.date === today && r.driverName === t.captainName)) {
        t.status = 'completed';
        t.completedAt = new Date().toISOString();
        t.completedBy = t.captainName;
        changed = true;
      }
    });
    if (changed) await redis.set(WINGMAN_TASKS_KEY, JSON.stringify(tasks));
    res.json({ tasks: mine, taskTypes: WINGMAN_TASK_TYPES });
  } catch (err) {
    console.error('Wingman task list failed:', err.message);
    res.status(500).json({ error: 'Could not load tasks.' });
  }
});

// Material Checkout can span several job-by-job submissions, so it's
// closed out explicitly once the wingman is done -- and only if a
// checkout is actually on file for that Captain today.
app.post('/api/wingman/tasks/:id/complete', requireWingmanAuth, async (req, res) => {
  try {
    const tasks = await loadWingmanTasks();
    const task = tasks.find(t => t.id === req.params.id);
    if (!task || task.status !== 'open' || nameDedupKey(task.wingmanName) !== nameDedupKey(req.wingmanName)) {
      return res.status(404).json({ error: 'That task is no longer assigned to you.' });
    }
    if (task.type !== 'materials-checkout') return res.status(400).json({ error: 'That task completes when you submit it.' });
    const raw = await redis.get('materials-checkouts');
    const checkouts = raw ? JSON.parse(raw) : [];
    if (!checkouts.some(c => c.driverName === task.captainName && c.date === task.date)) {
      return res.status(400).json({ error: 'No Material Checkout is on file yet for today.' });
    }
    await completeWingmanTask(task.id, req.wingmanName);
    res.json({ ok: true });
  } catch (err) {
    console.error('Wingman task complete failed:', err.message);
    res.status(500).json({ error: 'Could not complete that task.' });
  }
});

// ============ Junk Removal: driver-facing endpoints ============
const JUNK_REMOVAL_JOBS_KEY = 'junk-removal-jobs';

function junkRemovalPriceForTier(pricing, tier) {
  const entry = pricing.find(p => p.tier === tier);
  if (!entry) return null;
  return { low: entry.price - 40, high: entry.price + 40 };
}

// Full pricing table so the driver portal can instantly recompute the price
// range client-side as a Captain adjusts the estimated tier, with no extra
// round trip per adjustment.
app.get('/api/driver/junk-removal-pricing', requireDriverAuth, async (req, res) => {
  try {
    const pricing = await getJunkRemovalPricing();
    res.json({ pricing });
  } catch (err) {
    console.error('Driver junk removal pricing load failed:', err.message);
    res.status(500).json({ error: 'Could not load pricing.' });
  }
});

// Jobs assigned to a given Captain that aren't finished yet -- a completed
// job (final photo + estimate already recorded) drops off this list.
app.get('/api/driver/junk-removal-jobs', requireDriverAuth, async (req, res) => {
  const captainName = req.driverName;
  try {
    const raw = await redis.get(JUNK_REMOVAL_JOBS_KEY);
    const jobs = raw ? JSON.parse(raw) : [];
    const mine = jobs
      .filter(j => j.captainName === captainName && j.status !== 'completed')
      .map(j => ({
        id: j.id, jobNumber: j.jobNumber, clientName: j.clientName, status: j.status,
        initialEstimate: j.initialEstimate || null, initialConfirmedTier: j.initialConfirmedTier || null
      }));
    res.json({ jobs: mine });
  } catch (err) {
    console.error('Driver junk removal jobs load failed:', err.message);
    res.status(500).json({ error: 'Could not load jobs.' });
  }
});

// Lets a Captain pull up the photos already submitted for a stage, so they
// can add ones they forgot (or remove one) and re-submit for a fresh
// estimate, rather than being stuck with whatever they first uploaded.
app.get('/api/driver/junk-removal/:jobId/photos', requireDriverAuth, async (req, res) => {
  const stage = req.query.stage;
  if (stage !== 'initial' && stage !== 'final') {
    return res.status(400).json({ error: 'Invalid stage.' });
  }
  try {
    const raw = await redis.get(JUNK_REMOVAL_JOBS_KEY);
    const jobs = raw ? JSON.parse(raw) : [];
    const job = jobs.find(j => j.id === req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found.' });

    const keys = (stage === 'initial' ? job.initialPhotoKeys : job.finalPhotoKeys) || [];
    const photos = [];
    for (const key of keys) {
      const photoRaw = await redis.get(key);
      if (photoRaw) photos.push(JSON.parse(photoRaw));
    }
    res.json({ photos });
  } catch (err) {
    console.error('Driver junk removal photo fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load those photos.' });
  }
});

app.post('/api/driver/junk-removal/:jobId/estimate', requireDriverAuth, async (req, res) => {
  const { stage, photos } = req.body || {};
  if (stage !== 'initial' && stage !== 'final') {
    return res.status(400).json({ error: 'Invalid stage.' });
  }
  if (!Array.isArray(photos) || photos.length === 0) {
    return res.status(400).json({ error: 'At least one photo is required.' });
  }
  const MAX_JUNK_REMOVAL_PHOTOS = 20;
  if (photos.length > MAX_JUNK_REMOVAL_PHOTOS) {
    return res.status(400).json({ error: `Please upload ${MAX_JUNK_REMOVAL_PHOTOS} photos or fewer at a time.` });
  }
  for (const p of photos) {
    if (typeof p !== 'string' || !p.startsWith('data:image/')) {
      return res.status(400).json({ error: 'One of those files doesn\'t look like a photo.' });
    }
  }
  try {
    const raw = await redis.get(JUNK_REMOVAL_JOBS_KEY);
    const jobs = raw ? JSON.parse(raw) : [];
    const job = jobs.find(j => j.id === req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found.' });

    const result = await estimateJunkVolume(photos, stage);
    if (result.status !== 'ok') {
      return res.status(502).json({ error: 'Could not estimate volume from those photos \u2014 try again.' });
    }

    const photoKeys = [];
    for (const p of photos) {
      const photoId = crypto.randomBytes(8).toString('hex');
      const key = `junk-removal-photo-${job.id}-${stage}-${photoId}`;
      await redis.set(key, JSON.stringify(p));
      photoKeys.push(key);
    }

    const pricing = await getJunkRemovalPricing();
    const range = junkRemovalPriceForTier(pricing, result.tier);
    const now = new Date().toISOString();

    if (stage === 'initial') {
      job.initialPhotoKeys = photoKeys;
      job.initialPhotosAt = now;
      job.initialEstimate = { tier: result.tier, reasoning: result.reasoning };
      job.initialConfirmedTier = result.tier; // defaults to Claude's read; Captain can adjust via the confirm endpoint
      job.status = 'estimated';
    } else {
      job.finalPhotoKeys = photoKeys;
      job.finalPhotosAt = now;
      job.finalEstimate = { tier: result.tier, reasoning: result.reasoning };
      job.finalConfirmedTier = result.tier;
      job.status = 'completed';
    }
    job.updatedAt = now;
    await redis.set(JUNK_REMOVAL_JOBS_KEY, JSON.stringify(jobs));

    res.json({ tier: result.tier, reasoning: result.reasoning, priceLow: range ? range.low : null, priceHigh: range ? range.high : null });
  } catch (err) {
    console.error('Junk removal estimate failed:', err.message);
    res.status(500).json({ error: 'Could not process that estimate.' });
  }
});

// Lets the Captain adjust the tier before quoting the client (initial
// stage) or correct the final record if needed, without re-running vision.
app.post('/api/driver/junk-removal/:jobId/confirm-tier', requireDriverAuth, async (req, res) => {
  const { stage, tier } = req.body || {};
  if (stage !== 'initial' && stage !== 'final') {
    return res.status(400).json({ error: 'Invalid stage.' });
  }
  if (!JUNK_REMOVAL_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'Invalid tier.' });
  }
  try {
    const raw = await redis.get(JUNK_REMOVAL_JOBS_KEY);
    const jobs = raw ? JSON.parse(raw) : [];
    const job = jobs.find(j => j.id === req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found.' });

    const pricing = await getJunkRemovalPricing();
    const range = junkRemovalPriceForTier(pricing, tier);

    if (stage === 'initial') {
      job.initialConfirmedTier = tier;
      job.status = 'quoted';
    } else {
      job.finalConfirmedTier = tier;
    }
    job.updatedAt = new Date().toISOString();
    await redis.set(JUNK_REMOVAL_JOBS_KEY, JSON.stringify(jobs));

    res.json({ ok: true, priceLow: range ? range.low : null, priceHigh: range ? range.high : null });
  } catch (err) {
    console.error('Junk removal tier confirm failed:', err.message);
    res.status(500).json({ error: 'Could not save that.' });
  }
});

// ============ Moving: driver-facing damage documentation ============
// Job assignment is automatically detected from the same job-entry data
// already captured for every Move/Move Labor via Job Paperwork -- there is
// no separate "assign a moving job" step. paperwork-job-archive is the
// source of truth for which jobs exist and who's assigned; moving-damage-
// reports holds the actual submitted photos/notes, one record per job
// number, created the first time either category is submitted.
const JOB_ARCHIVE_KEY = 'paperwork-job-archive';
const MOVING_DAMAGE_REPORTS_KEY = 'moving-damage-reports';
const MOVING_JOB_LOOKBACK_DAYS = 14; // how far back an assignment date can be and still show as active for the driver
const MOVING_JOB_LOOKAHEAD_DAYS = 7; // lets a job entered a few days ahead of the move already show up
const MAX_MOVING_PHOTOS = 20;
const MOVING_JOB_TYPES = ['move', 'movelabor']; // Moves and Move Labors are treated identically throughout

function sanitizeMovingJobKey(jobNumber) {
  return String(jobNumber).replace(/[^a-zA-Z0-9_-]/g, '_');
}

// Jobs assigned to this driver as either a Move or Move Labor, whose
// assignment date falls in a relevant recent/upcoming window -- merged with
// whatever damage-report state (photo counts, submission timestamps)
// already exists for each one. Photo blobs themselves are never included
// here, only counts -- the list stays lightweight, and photos are fetched
// per-job only when a driver actually opens that job's detail view.
app.get('/api/driver/moving-jobs', requireDriverAuth, async (req, res) => {
  const driverName = req.driverName;
  try {
    const [archiveRaw, reportsRaw] = await Promise.all([
      redis.get(JOB_ARCHIVE_KEY),
      redis.get(MOVING_DAMAGE_REPORTS_KEY)
    ]);
    const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
    const reports = reportsRaw ? JSON.parse(reportsRaw) : [];
    const reportsByJobNumber = new Map(reports.map(r => [r.jobNumber, r]));

    const today = new Date();
    const windowStart = new Date(today); windowStart.setDate(windowStart.getDate() - MOVING_JOB_LOOKBACK_DAYS);
    const windowStartStr = windowStart.toISOString().slice(0, 10);
    const windowEnd = new Date(today); windowEnd.setDate(windowEnd.getDate() + MOVING_JOB_LOOKAHEAD_DAYS);
    const windowEndStr = windowEnd.toISOString().slice(0, 10);

    const mine = archive
      .filter(j => j.captainName === driverName && MOVING_JOB_TYPES.includes(j.jobType)
        && j.assignmentDate && j.assignmentDate >= windowStartStr && j.assignmentDate <= windowEndStr)
      .map(j => {
        const report = reportsByJobNumber.get(j.jobNumber);
        return {
          jobNumber: j.jobNumber,
          clientName: j.clientName,
          jobType: j.jobType,
          assignmentDate: j.assignmentDate,
          preExistingPhotoCount: (report && report.preExistingPhotoKeys && report.preExistingPhotoKeys.length) || 0,
          preExistingSubmittedAt: (report && report.preExistingSubmittedAt) || null,
          causedPhotoCount: (report && report.causedPhotoKeys && report.causedPhotoKeys.length) || 0,
          causedSubmittedAt: (report && report.causedSubmittedAt) || null
        };
      })
      .sort((a, b) => (b.assignmentDate || '').localeCompare(a.assignmentDate || ''));
    res.json({ jobs: mine });
  } catch (err) {
    console.error('Driver moving jobs load failed:', err.message);
    res.status(500).json({ error: 'Could not load jobs.' });
  }
});

// Lets a driver pull up the photos already submitted for a category, so
// they can add ones they forgot and re-submit -- same edit pattern as
// Junk Removal's photo flow.
app.get('/api/driver/moving/:jobNumber/photos', requireDriverAuth, async (req, res) => {
  const category = req.query.category;
  if (category !== 'preexisting' && category !== 'caused') {
    return res.status(400).json({ error: 'Invalid category.' });
  }
  try {
    const raw = await redis.get(MOVING_DAMAGE_REPORTS_KEY);
    const reports = raw ? JSON.parse(raw) : [];
    const report = reports.find(r => r.jobNumber === req.params.jobNumber);
    if (!report) return res.json({ photos: [], notes: '' });

    const keys = (category === 'preexisting' ? report.preExistingPhotoKeys : report.causedPhotoKeys) || [];
    const photos = [];
    for (const key of keys) {
      const photoRaw = await redis.get(key);
      if (photoRaw) photos.push(JSON.parse(photoRaw));
    }
    res.json({ photos, notes: (category === 'preexisting' ? report.preExistingNotes : report.causedNotes) || '' });
  } catch (err) {
    console.error('Driver moving photo fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load those photos.' });
  }
});

app.post('/api/driver/moving/:jobNumber/photos', requireDriverAuth, async (req, res) => {
  const driverName = req.driverName;
  const jobNumber = req.params.jobNumber;
  const { category, photos, notes } = req.body || {};
  if (category !== 'preexisting' && category !== 'caused') {
    return res.status(400).json({ error: 'Invalid category.' });
  }
  if (!Array.isArray(photos) || photos.length === 0) {
    return res.status(400).json({ error: 'At least one photo is required.' });
  }
  if (photos.length > MAX_MOVING_PHOTOS) {
    return res.status(400).json({ error: `Please upload ${MAX_MOVING_PHOTOS} photos or fewer at a time.` });
  }
  for (const p of photos) {
    if (typeof p !== 'string' || !p.startsWith('data:image/')) {
      return res.status(400).json({ error: 'One of those files doesn\'t look like a photo.' });
    }
  }
  try {
    // Confirms this job is actually assigned to the requesting driver
    // before accepting anything -- the archive's captainName is the
    // server-verified source of truth, never trusted from the client.
    const archiveRaw = await redis.get(JOB_ARCHIVE_KEY);
    const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
    const archivedJob = archive.find(j => j.jobNumber === jobNumber && MOVING_JOB_TYPES.includes(j.jobType));
    if (!archivedJob) return res.status(404).json({ error: 'Job not found.' });
    if (archivedJob.captainName !== driverName) return res.status(403).json({ error: 'This job isn\'t assigned to you.' });

    const raw = await redis.get(MOVING_DAMAGE_REPORTS_KEY);
    const reports = raw ? JSON.parse(raw) : [];
    let report = reports.find(r => r.jobNumber === jobNumber);
    if (!report) {
      report = { jobNumber, clientName: archivedJob.clientName, jobType: archivedJob.jobType, captainName: driverName };
      reports.push(report);
    }

    const jobKey = sanitizeMovingJobKey(jobNumber);
    const photoKeys = [];
    for (const p of photos) {
      const photoId = crypto.randomBytes(8).toString('hex');
      const key = `moving-photo-${jobKey}-${category}-${photoId}`;
      await redis.set(key, JSON.stringify(p));
      photoKeys.push(key);
    }

    const now = new Date().toISOString();
    if (category === 'preexisting') {
      report.preExistingPhotoKeys = photoKeys;
      report.preExistingNotes = (notes || '').toString().slice(0, 2000);
      report.preExistingSubmittedAt = now;
    } else {
      report.causedPhotoKeys = photoKeys;
      report.causedNotes = (notes || '').toString().slice(0, 2000);
      report.causedSubmittedAt = now;
    }
    report.updatedAt = now;
    await redis.set(MOVING_DAMAGE_REPORTS_KEY, JSON.stringify(reports));

    res.json({ ok: true });
  } catch (err) {
    console.error('Moving photo submission failed:', err.message);
    res.status(500).json({ error: 'Could not save those photos.' });
  }
});
// from the same admin-side records Captain Metrics uses, and returns only
// the aggregated results -- drivers never get raw access to
// compliance-pretrip-inspections, paperwork-job-archive, or paperwork-uploads
// directly (those stay behind requireAuth, not requireDriverAuth).
//
// Response shape is a generic list of categories so new metrics can be added
// here later without the driver-portal frontend needing any changes -- it
// just renders whatever categories come back.
// ============ Captain Metrics: shared monthly scoring ============
const CAPTAIN_METRICS_MONTHLY_LOCKS_KEY = 'captain-metrics-monthly-locks';

function monthAfter(monthStr) {
  const [y, m] = monthStr.split('-').map(Number);
  const nm = m === 12 ? 1 : m + 1;
  const ny = m === 12 ? y + 1 : y;
  return `${ny}-${String(nm).padStart(2, '0')}`;
}

// Computes each of the 5 scoring categories, and the combined weighted
// score, for every Captain, for one calendar month. A category a Captain
// has no applicable data for (e.g. no move jobs that month) is left out of
// their score entirely rather than counted as a 0 -- see the weight
// re-normalization below.
function computeCaptainScoresForMonth(monthStr, data, weights, opsManagerNames, activeDriverNames, travelLineCheckStartDate) {
  const rangeStart = monthStr + '-01';
  const rangeEnd = monthAfter(monthStr) + '-01'; // exclusive upper bound
  return computeCaptainScoresForRange(rangeStart, rangeEnd, data, weights, opsManagerNames, activeDriverNames, travelLineCheckStartDate);
}

// Same scoring logic as computeCaptainScoresForMonth, generalized to any
// [rangeStart, rangeEnd) date range -- reused by the weekly trend graph,
// which needs the identical formula at a finer granularity, not a
// second, drifting implementation of it.
// Normalizes a name for matching regardless of "Last, First" vs "First
// Last" order, casing, or extra whitespace -- ported from the frontend's
// identical nameDedupKey, so the same person is recognized consistently
// wherever their name might be typed slightly differently (a manually
// logged attendance record vs. the payroll-sourced Captain name, say).
function nameDedupKey(name) {
  return String(name || '').replace(/,/g, ' ').split(/\s+/).filter(Boolean).map(w => w.toLowerCase()).sort().join(' ');
}

function computeCaptainScoresForRange(rangeStart, rangeEnd, data, weights, opsManagerNames, activeDriverNames, travelLineCheckStartDate) {
  const todayStr = new Date().toISOString().slice(0, 10);
  const { archive, ptiRecords, eodRecords, uploads, attendanceRecords, movingReports, materialsCheckouts, materialsItems, managerReviewItems, junkRemovalJobs, captainRatings } = data;
  const nowMs = Date.now();
  const DAY_MS = 24 * 60 * 60 * 1000;
  const opsManagerKeys = new Set((opsManagerNames || []).map(nameDedupKey));
  // Only someone currently checked as a driver on Compliance is eligible
  // to be scored -- the Captain-selection dropdown on Job Data Entry pulls
  // from the full employee roster, not filtered by driver status, so
  // anyone could technically end up as a job's captainName even without
  // ever being marked a driver. undefined means "no driver list available"
  // (an older caller, or the data genuinely couldn't be fetched) -- treated
  // as no restriction, rather than silently excluding everyone.
  const activeDriverKeys = activeDriverNames ? new Set(activeDriverNames.map(nameDedupKey)) : null;

  // Only jobs whose scheduled day has actually passed count toward
  // anything here -- a job later in the range hasn't had a chance to be
  // late/incomplete/etc. yet. An Operations Manager is excluded from
  // scoring entirely, even on a day they're listed as a job's Captain --
  // that role doesn't get measured by Captain Metrics regardless of how
  // the job happened to be assigned.
  const monthJobsRaw = archive.filter(j =>
    j.captainName && j.jobNumber && j.assignmentDate &&
    j.assignmentDate >= rangeStart && j.assignmentDate < rangeEnd && j.assignmentDate < todayStr &&
    !opsManagerKeys.has(nameDedupKey(j.captainName)) &&
    (activeDriverKeys === null || activeDriverKeys.has(nameDedupKey(j.captainName)))
  );

  // Normalize Captain identity BEFORE any category computation runs --
  // two jobs with differently-spelled names for the same person (e.g.
  // "Gilbert Holland" vs "Holland, Gilbert") must be scored as ONE
  // Captain everywhere below, never as two separate people. Whichever
  // spelling appears on the most recently assigned job is used as that
  // person's display name, since it's the most likely to reflect the
  // current, correct spelling.
  const canonicalNameByKey = {};
  const latestDateByKey = {};
  monthJobsRaw.forEach(j => {
    const key = nameDedupKey(j.captainName);
    if (!latestDateByKey[key] || j.assignmentDate >= latestDateByKey[key]) {
      canonicalNameByKey[key] = j.captainName;
      latestDateByKey[key] = j.assignmentDate;
    }
  });
  const monthJobs = monthJobsRaw.map(j => Object.assign({}, j, { captainName: canonicalNameByKey[nameDedupKey(j.captainName)] }));

  // ---- 1. Completed Paperwork -- uploaded, emailed, and invoice
  // reconciled, matching the same definition already used by Ops Manager
  // Metrics' Paperwork Close-Out, just attributed per Captain here instead
  // of company-wide. An "angry" satisfaction rating needs no email and is
  // excluded entirely, same as that existing metric. ----
  const uploadsByJob = {};
  uploads.forEach(u => { if (u.jobNumber) uploadsByJob[u.jobNumber] = u; });
  const paperworkByCaptain = {};
  // A job whose paperwork isn't complete yet but is still inside the
  // close-out window isn't due yet, so it's left out entirely rather than
  // counted as a 0 -- the same "not yet due" rule Ops Manager Metrics'
  // Paperwork Close-Out uses. Once the window passes, an incomplete job
  // counts against the Captain like before.
  const paperworkWindowMs = (Number(data.paperworkCloseoutWindowDays) || 4) * DAY_MS;
  monthJobs.forEach(j => {
    const upload = uploadsByJob[j.jobNumber];
    if (upload && upload.satisfaction === 'angry') return;
    const complete = !!(upload && upload.emailSentAt && upload.invoiceUploadedAt && (Number(upload.invoiceBalanceDue) < 1 || upload.balanceDueOverridden));
    if (!complete && (nowMs - Date.parse(j.assignmentDate + 'T00:00:00Z')) <= paperworkWindowMs) return;
    if (!paperworkByCaptain[j.captainName]) paperworkByCaptain[j.captainName] = { complete: 0, total: 0 };
    paperworkByCaptain[j.captainName].total++;
    if (complete) paperworkByCaptain[j.captainName].complete++;
  });

  // ---- 2. Attendance -- any unexcused tardy or absence on file for a
  // Captain this month drops that category to 0% outright; otherwise 100%.
  // Only scored for a Captain who actually had a job this month. Matched
  // by normalized name, not exact string -- an attendance record logged
  // as "Gilbert Holland" must still count against a job archive's
  // "Holland, Gilbert" for the same person. ----
  const attendanceByCaptain = {};
  const captainsThisMonth = new Set(monthJobs.map(j => j.captainName));
  captainsThisMonth.forEach(captain => { attendanceByCaptain[captain] = 100; });
  const captainByNormalizedKey = {};
  captainsThisMonth.forEach(captain => { captainByNormalizedKey[nameDedupKey(captain)] = captain; });
  (attendanceRecords || []).filter(r => r.employeeName && r.date && r.date >= rangeStart && r.date < rangeEnd)
    .forEach(r => {
      const matchedCaptain = captainByNormalizedKey[nameDedupKey(r.employeeName)];
      if (matchedCaptain) attendanceByCaptain[matchedCaptain] = 0;
    });

  // ---- 3. Pre-Trip + End of Day Inspection Completion -- a day only
  // counts as compliant if BOTH are on file for that Captain that day.
  // Estimates never generate an archive record in the first place, so
  // nothing further is needed to exclude them. ----
  const assignedDaysByCaptain = {};
  monthJobs.forEach(j => {
    if (!assignedDaysByCaptain[j.captainName]) assignedDaysByCaptain[j.captainName] = new Set();
    assignedDaysByCaptain[j.captainName].add(j.assignmentDate);
  });
  const ptiEodByCaptain = {};
  Object.keys(assignedDaysByCaptain).forEach(captain => {
    const days = [...assignedDaysByCaptain[captain]];
    if (days.length === 0) return;
    const captainKey = nameDedupKey(captain);
    // Inspection dates are stamped in UTC, so an End of Day submitted
    // after 8 PM Eastern lands on the next calendar date -- one filed
    // before 10:00 UTC (6 AM Eastern) the next morning still counts for
    // the work day it belongs to.
    const nextDay = d => new Date(Date.parse(d + 'T00:00:00Z') + DAY_MS).toISOString().slice(0, 10);
    const eodCoversDay = (e, day) => e.date === day ||
      (e.date === nextDay(day) && e.submittedAt && new Date(e.submittedAt).getUTCHours() < 10);
    const isCompliant = day =>
      ptiRecords.some(p => nameDedupKey(p.driverName) === captainKey && p.date === day) &&
      eodRecords.some(e => nameDedupKey(e.driverName) === captainKey && eodCoversDay(e, day));
    // A day isn't due until 6 AM Eastern the next morning, unless it's
    // already complete -- so an evening job still waiting on its End of
    // Day doesn't show as a miss.
    const dueDays = days.filter(day => isCompliant(day) || nowMs >= Date.parse(day + 'T00:00:00Z') + DAY_MS + 10 * 60 * 60 * 1000);
    if (dueDays.length === 0) return;
    const compliant = dueDays.filter(isCompliant).length;
    ptiEodByCaptain[captain] = { pct: (compliant / dueDays.length) * 100 };
  });

  // ---- 4. Move Job Photo Upload -- "move" job type only, at least one
  // pre-existing-damage photo on file for that job. ----
  const moveJobsByCaptain = {};
  monthJobs.filter(j => j.jobType === 'move').forEach(j => {
    if (!moveJobsByCaptain[j.captainName]) moveJobsByCaptain[j.captainName] = { withPhoto: 0, total: 0 };
    moveJobsByCaptain[j.captainName].total++;
    const report = (movingReports || []).find(r => r.jobNumber === j.jobNumber);
    if (report && Array.isArray(report.preExistingPhotoKeys) && report.preExistingPhotoKeys.length > 0) {
      moveJobsByCaptain[j.captainName].withPhoto++;
    }
  });

  // ---- 5. Underbilled Jobs -- "% of applicable jobs that are NOT
  // manager-confirmed bad." A job is applicable if it had materials
  // checked out, is a Junk Removal job that's been invoiced, or is a
  // Move/Move Labor job dated on or after travelLineCheckStartDate. A
  // job the AI never flagged at all counts as good automatically --
  // nothing to review means nothing wrong. A job the AI flagged but the
  // Manager hasn't reviewed yet is excluded entirely (not yet due), same
  // as everywhere else in this app. A job counts as bad only once the
  // Manager has reviewed at least one of its flagged issues and marked
  // it Fail; a job can have more than one flagged issue (e.g. missing
  // materials AND a missing travel line), and any single confirmed Fail
  // is enough to make the whole job count as bad.
  const billableItemIds = new Set((materialsItems || []).filter(i => !i.neverBilled).map(i => i.id));
  const checkedOutByJob = {};
  (materialsCheckouts || []).forEach(co => {
    (co.jobNumbers || []).forEach(jobNumber => {
      if (!checkedOutByJob[jobNumber]) checkedOutByJob[jobNumber] = {};
      (co.items || []).forEach(it => {
        if (!billableItemIds.has(it.itemId)) return;
        checkedOutByJob[jobNumber][it.itemId] = (checkedOutByJob[jobNumber][it.itemId] || 0) + Number(it.quantity || 0);
      });
    });
  });
  const MOVE_JOB_TYPES_FOR_TRAVEL_CHECK = new Set(['move', 'movelabor']);
  // Same rule as Junk Removal below: a Move/Move Labor job isn't
  // applicable to the travel-line check until its invoice is on file.
  // Before that, "no confirmed travel line" just means "no invoice yet."
  const invoicedJobNumbers = new Set((uploads || []).filter(u => u.jobNumber && u.invoiceUploadedAt).map(u => u.jobNumber));
  const underbilledItemsByJob = {};
  (managerReviewItems || []).forEach(item => {
    if (item.type !== 'underbilled' || !item.jobNumber) return;
    if (!underbilledItemsByJob[item.jobNumber]) underbilledItemsByJob[item.jobNumber] = [];
    underbilledItemsByJob[item.jobNumber].push(item);
  });
  const underbilledVerdict = (jobNumber) => {
    const items = underbilledItemsByJob[jobNumber] || [];
    if (items.some(i => i.reviewedAt && i.outcome === 'fail')) return 'bad';
    if (items.some(i => !i.reviewedAt)) return 'pending';
    return 'good';
  };
  const underbilledByCaptain = {};
  const tallyUnderbilled = (rawCaptainName, verdict) => {
    if (verdict === 'pending' || !rawCaptainName) return;
    if (opsManagerKeys.has(nameDedupKey(rawCaptainName))) return;
    if (activeDriverKeys !== null && !activeDriverKeys.has(nameDedupKey(rawCaptainName))) return;
    const captainKey = nameDedupKey(rawCaptainName);
    const captainName = canonicalNameByKey[captainKey] || rawCaptainName;
    if (!underbilledByCaptain[captainName]) underbilledByCaptain[captainName] = { ok: 0, total: 0 };
    underbilledByCaptain[captainName].total++;
    if (verdict === 'good') underbilledByCaptain[captainName].ok++;
  };
  monthJobs.forEach(j => {
    const checkedOut = checkedOutByJob[j.jobNumber];
    // Like the travel line, materials are only checkable once the invoice
    // is on file -- before that, nothing has been billed yet.
    const hasMaterialsCheckedOut = !!(checkedOut && Object.keys(checkedOut).length > 0) && invoicedJobNumbers.has(j.jobNumber);
    const needsTravelLine = MOVE_JOB_TYPES_FOR_TRAVEL_CHECK.has(j.jobType) &&
      (!travelLineCheckStartDate || j.assignmentDate >= travelLineCheckStartDate) &&
      invoicedJobNumbers.has(j.jobNumber);
    if (!hasMaterialsCheckedOut && !needsTravelLine) return; // not applicable either way
    tallyUnderbilled(j.captainName, underbilledVerdict(j.jobNumber));
  });
  // Junk Removal jobs live in their own storage key, separate from the
  // main job archive, so they need their own pass over the same range
  // and exclusion rules monthJobs already applied.
  (junkRemovalJobs || []).forEach(j => {
    if (!j.jobNumber || !j.captainName || !j.assignmentDate) return;
    if (!(Number(j.invoiceTotal) > 0)) return; // not yet invoiced -- not applicable yet
    if (j.assignmentDate < rangeStart || j.assignmentDate >= rangeEnd) return;
    tallyUnderbilled(j.captainName, underbilledVerdict(j.jobNumber));
  });

  // ---- 6. Truck Conditions -- "% of EOD inspections that are NOT
  // manager-confirmed bad," its own category separate from Underbilled
  // Jobs. Every EOD inspection a Captain filed this month is in the
  // denominator, attributed via the same normalized driver-name match
  // PTI/EOD compliance already uses -- one the AI never flagged counts
  // as good automatically. One the AI flagged but the Manager hasn't
  // reviewed yet is excluded entirely (not yet due). One the AI flagged
  // AND the Manager confirmed Fail counts as bad.
  const truckConditionItemByEodId = {};
  (managerReviewItems || []).forEach(item => {
    if (item.type === 'truck-condition' && item.eodRecordId) truckConditionItemByEodId[item.eodRecordId] = item;
  });
  const truckConditionsByCaptain = {};
  (eodRecords || []).forEach(e => {
    if (!e.driverName || !e.date || e.date < rangeStart || e.date >= rangeEnd) return;
    if (opsManagerKeys.has(nameDedupKey(e.driverName))) return;
    if (activeDriverKeys !== null && !activeDriverKeys.has(nameDedupKey(e.driverName))) return;

    const item = truckConditionItemByEodId[e.id];
    if (item && !item.reviewedAt) return; // flagged, still awaiting review -- excluded, not yet due

    const captainKey = nameDedupKey(e.driverName);
    const captainName = canonicalNameByKey[captainKey] || e.driverName;
    if (!truckConditionsByCaptain[captainName]) truckConditionsByCaptain[captainName] = { ok: 0, total: 0 };
    truckConditionsByCaptain[captainName].total++;
    const isBad = !!(item && item.reviewedAt && item.outcome === 'fail');
    if (!isBad) truckConditionsByCaptain[captainName].ok++;
  });

  // ---- 7. Captain Reviews -- share of "Yes" answers across every
  // Captain Review wingmen submitted about this Captain in the range.
  // No reviews means no score for this category (left out, not 0). ----
  const captainReviewsByCaptain = {};
  (captainRatings || []).forEach(r => {
    if (!r.captainName || !r.date || r.date < rangeStart || r.date >= rangeEnd) return;
    if (!Array.isArray(r.answers) || r.answers.length === 0) return;
    const captainKey = nameDedupKey(r.captainName);
    if (opsManagerKeys.has(captainKey)) return;
    if (activeDriverKeys !== null && !activeDriverKeys.has(captainKey)) return;
    const captainName = canonicalNameByKey[captainKey] || r.captainName;
    if (!captainReviewsByCaptain[captainName]) captainReviewsByCaptain[captainName] = { yes: 0, total: 0 };
    r.answers.forEach(a => {
      captainReviewsByCaptain[captainName].total++;
      if (a.answer === true) captainReviewsByCaptain[captainName].yes++;
    });
  });

  // ---- Combine into per-category percentages + one weighted overall
  // score, re-normalizing weights among only the categories each Captain
  // actually has applicable data for. ----
  const pct = (obj, numKey, denKey) => obj && obj[denKey] > 0 ? (obj[numKey] / obj[denKey]) * 100 : null;
  const categoryDefs = [
    { key: 'completedPaperwork', weight: Number(weights.completedPaperwork) || 0, get: c => pct(paperworkByCaptain[c], 'complete', 'total') },
    { key: 'attendance', weight: Number(weights.attendance) || 0, get: c => (attendanceByCaptain[c] != null ? attendanceByCaptain[c] : null) },
    { key: 'ptiEod', weight: Number(weights.ptiEod) || 0, get: c => (ptiEodByCaptain[c] ? ptiEodByCaptain[c].pct : null) },
    { key: 'movePhoto', weight: Number(weights.movePhoto) || 0, get: c => pct(moveJobsByCaptain[c], 'withPhoto', 'total') },
    { key: 'underbilled', weight: Number(weights.underbilled) || 0, get: c => pct(underbilledByCaptain[c], 'ok', 'total') },
    { key: 'truckConditions', weight: Number(weights.truckConditions) || 0, get: c => pct(truckConditionsByCaptain[c], 'ok', 'total') },
    { key: 'captainReviews', weight: Number(weights.captainReviews) || 0, get: c => pct(captainReviewsByCaptain[c], 'yes', 'total') }
  ];

  const allCaptains = new Set([
    ...Object.keys(paperworkByCaptain), ...Object.keys(attendanceByCaptain),
    ...Object.keys(ptiEodByCaptain), ...Object.keys(moveJobsByCaptain), ...Object.keys(underbilledByCaptain),
    ...Object.keys(truckConditionsByCaptain), ...Object.keys(captainReviewsByCaptain)
  ]);

  const scores = {};
  allCaptains.forEach(captain => {
    const values = categoryDefs.map(c => ({ ...c, pct: c.get(captain) }));
    const applicable = values.filter(c => c.pct !== null && c.weight > 0);
    const byCategory = {};
    values.forEach(c => { byCategory[c.key] = c.pct === null ? null : Math.round(c.pct); });
    if (applicable.length === 0) {
      scores[captain] = { overall: null, ...byCategory };
      return;
    }
    const totalWeight = applicable.reduce((s, c) => s + c.weight, 0);
    const overall = totalWeight > 0 ? applicable.reduce((s, c) => s + c.pct * c.weight, 0) / totalWeight : null;
    scores[captain] = { overall: overall === null ? null : Math.round(overall), ...byCategory };
  });
  return scores;
}

// A wingman's score is simply the percentage of "yes" answers across every
// rating they received (from any Captain, on any job) within a date range
// -- no weighted categories, since these are all plain yes/no questions.
// Matched by normalized name, same as everywhere else names get compared
// in this app, so a roster spelling correction doesn't split one person's
// ratings into two separate records.
function computeWingmanScoresForRange(rangeStart, rangeEnd, ratings, activeDriverKeys) {
  const scores = {};
  (ratings || []).forEach(r => {
    if (!r.wingmanName || !r.date || r.date < rangeStart || r.date >= rangeEnd) return;
    if (!Array.isArray(r.answers) || r.answers.length === 0) return;
    const key = nameDedupKey(r.wingmanName);
    // A Captain occasionally fills in as someone else's wingman on a
    // slower day, but is never evaluated AS a wingman themselves --
    // excluded entirely here, not just hidden from the selection list,
    // in case a rating already exists for them from before this rule.
    if (activeDriverKeys && activeDriverKeys.has(key)) return;
    if (!scores[key]) scores[key] = { displayName: r.wingmanName, totalYes: 0, totalQuestions: 0, ratingCount: 0 };
    // The most recently dated rating's spelling wins for display, same
    // canonicalization rule Captain Metrics already uses.
    if (r.date >= (scores[key].latestDate || '')) { scores[key].displayName = r.wingmanName; scores[key].latestDate = r.date; }
    r.answers.forEach(a => {
      scores[key].totalQuestions++;
      if (a.answer === true) scores[key].totalYes++;
    });
    scores[key].ratingCount++;
  });
  const byName = {};
  Object.values(scores).forEach(s => {
    byName[s.displayName] = {
      overall: s.totalQuestions > 0 ? Math.round((s.totalYes / s.totalQuestions) * 100) : null,
      totalYes: s.totalYes, totalQuestions: s.totalQuestions, ratingCount: s.ratingCount
    };
  });
  return byName;
}

function computeWingmanScoresForMonth(monthStr, ratings, activeDriverKeys) {
  const rangeStart = monthStr + '-01';
  const rangeEnd = monthAfter(monthStr) + '-01';
  return computeWingmanScoresForRange(rangeStart, rangeEnd, ratings, activeDriverKeys);
}

// A normalized set of every currently-active driver's name -- a Captain
// who occasionally wingmans for someone else is still excluded from
// ever being evaluated as one. Shared by every Wingman Metrics endpoint
// so there's one definition of "who's excluded," not several.
async function fetchActiveDriverKeys() {
  const driversRaw = await redis.get('compliance-drivers');
  const drivers = driversRaw ? JSON.parse(driversRaw) : [];
  return new Set(drivers.filter(d => d.active).map(d => nameDedupKey(d.employeeName)));
}

const WINGMAN_METRICS_MONTHLY_LOCKS_KEY = 'wingman-metrics-monthly-locks';

// Call this before reading current Wingman scores anywhere they're
// displayed, and also right after a payroll week save -- same monthly
// lock mechanism as Captain Metrics, same trigger.
async function getActiveWingmanMetricsMonth() {
  let cachedRatings = null;
  let cachedDriverKeys = null;
  const getRatings = async () => {
    if (!cachedRatings) {
      const ratingsRaw = await redis.get('wingman-ratings');
      cachedRatings = ratingsRaw ? JSON.parse(ratingsRaw) : [];
    }
    return cachedRatings;
  };
  return getActiveMetricsMonth(WINGMAN_METRICS_MONTHLY_LOCKS_KEY, async (monthStr) => {
    const ratings = await getRatings();
    if (!cachedDriverKeys) cachedDriverKeys = await fetchActiveDriverKeys();
    return computeWingmanScoresForMonth(monthStr, ratings, cachedDriverKeys);
  });
}

async function fetchCaptainMetricsRawData() {
  const [archiveRaw, ptiRaw, uploadsRaw, eodRaw, attendanceRaw, movingRaw, checkoutsRaw, itemsRaw, excludedRaw, driversRaw, reviewItemsRaw, junkRemovalJobsRaw, captainRatingsRaw, settingsRaw] = await Promise.all([
    redis.get('paperwork-job-archive'), redis.get('compliance-pretrip-inspections'),
    redis.get('paperwork-uploads'), redis.get('compliance-eod-inspections'),
    redis.get('attendance-records'), redis.get('moving-damage-reports'),
    redis.get('materials-checkouts'), redis.get('materials-items'),
    redis.get('settings-captain-metrics-excluded-employees'), redis.get('compliance-drivers'),
    redis.get('manager-review-items'), redis.get('junk-removal-jobs'),
    redis.get('captain-ratings'), redis.get(APP_SETTINGS_KEY)
  ]);
  const omSettings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null).opsManagerMetrics || {};
  const opsManagerNames = excludedRaw ? JSON.parse(excludedRaw) : [];
  // Distinguish "the key was never set" (driver data genuinely
  // unavailable -- fail open, apply no restriction) from "the key exists
  // but happens to list no one as currently active" (a real, deliberate
  // state that correctly restricts scoring to no one). Using driversRaw
  // itself for this, not the parsed array's length, since an empty array
  // is a valid, real value once the key exists.
  const activeDriverNames = driversRaw ? JSON.parse(driversRaw).filter(d => d.active).map(d => d.employeeName) : null;
  return {
    archive: archiveRaw ? JSON.parse(archiveRaw) : [],
    ptiRecords: ptiRaw ? JSON.parse(ptiRaw) : [],
    uploads: uploadsRaw ? JSON.parse(uploadsRaw) : [],
    eodRecords: eodRaw ? JSON.parse(eodRaw) : [],
    attendanceRecords: attendanceRaw ? JSON.parse(attendanceRaw) : [],
    movingReports: movingRaw ? JSON.parse(movingRaw) : [],
    materialsCheckouts: checkoutsRaw ? JSON.parse(checkoutsRaw) : [],
    materialsItems: itemsRaw ? JSON.parse(itemsRaw) : [],
    managerReviewItems: reviewItemsRaw ? JSON.parse(reviewItemsRaw) : [],
    junkRemovalJobs: junkRemovalJobsRaw ? JSON.parse(junkRemovalJobsRaw) : [],
    captainRatings: captainRatingsRaw ? JSON.parse(captainRatingsRaw) : [],
    // Same close-out window Ops Manager Metrics uses (Configuration ->
    // Ops Manager Metrics Settings), default 4 days.
    paperworkCloseoutWindowDays: Number(omSettings.timelyCloseoutWindowDays) || 4,
    opsManagerNames,
    activeDriverNames
  };
}

// The active (still-live, not yet locked) scoring month for ANY metric
// system, plus locks any months that have fallen due -- a month locks
// once a payroll week dated in a LATER month has been uploaded, since
// that's the trigger these monthly scores are meant to wait for. Handles
// a payroll catch-up spanning several months at once, locking each in
// turn, not just the immediately-next one. Shared by Captain Metrics,
// Wingman Metrics, and (from the frontend, since its scoring stays
// client-side) Ops Manager Metrics -- one mechanism, one set of rules,
// rather than three drifting copies of the same logic.
// computeMonthScoresFn(monthStr) should compute and return that month's
// scores; it's only ever called for months that actually need locking,
// preserving the original "don't do the expensive work unless there's
// locking to do" behavior.
async function getActiveMetricsMonth(locksKey, computeMonthScoresFn) {
  const laborWeeksRaw = await redis.get('labor-weeks');
  const laborWeeks = laborWeeksRaw ? JSON.parse(laborWeeksRaw) : [];
  const locksRaw = await redis.get(locksKey);
  let locks = locksRaw ? JSON.parse(locksRaw) : [];

  const currentCalendarMonth = new Date().toISOString().slice(0, 7);
  const latestPayrollMonth = laborWeeks.reduce((max, w) => {
    const m = (w.weekStart || '').slice(0, 7);
    return m > max ? m : max;
  }, '');

  let activeMonth = locks.length > 0
    ? monthAfter([...locks].map(l => l.month).sort().slice(-1)[0])
    : currentCalendarMonth;

  if (latestPayrollMonth && activeMonth < latestPayrollMonth) {
    const lockedMonthSet = new Set(locks.map(l => l.month));
    let changed = false;
    while (activeMonth < latestPayrollMonth) {
      if (!lockedMonthSet.has(activeMonth)) {
        const scores = await computeMonthScoresFn(activeMonth);
        locks.push({ month: activeMonth, lockedAt: new Date().toISOString(), scores });
        lockedMonthSet.add(activeMonth);
        changed = true;
      }
      activeMonth = monthAfter(activeMonth);
    }
    if (changed) await redis.set(locksKey, JSON.stringify(locks));
  }

  return { activeMonth, locks };
}

// Call this before reading current Captain scores anywhere they're
// displayed, and also right after a payroll week save.
async function getActiveCaptainMetricsMonth(weights, travelLineCheckStartDate) {
  let cachedData = null;
  const getData = async () => { if (!cachedData) cachedData = await fetchCaptainMetricsRawData(); return cachedData; };
  return getActiveMetricsMonth(CAPTAIN_METRICS_MONTHLY_LOCKS_KEY, async (monthStr) => {
    const data = await getData();
    return computeCaptainScoresForMonth(monthStr, data, weights, data.opsManagerNames, data.activeDriverNames, travelLineCheckStartDate);
  });
}

app.get('/api/driver/leaderboard', requireDriverAuth, async (req, res) => {
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const weights = settings.captainMetrics.weights;
    const travelLineCheckStartDate = settings.captainMetrics.travelLineCheckStartDate;

    const { activeMonth } = await getActiveCaptainMetricsMonth(weights, travelLineCheckStartDate);
    const data = await fetchCaptainMetricsRawData();
    const scores = computeCaptainScoresForMonth(activeMonth, data, weights, data.opsManagerNames, data.activeDriverNames, travelLineCheckStartDate);

    const labelMap = { completedPaperwork: 'Paperwork', attendance: 'Attendance', ptiEod: 'PTI/EOD', movePhoto: 'Move Photos', underbilled: 'Billing', truckConditions: 'Truck Conditions', captainReviews: 'Captain Reviews' };
    const entries = Object.keys(scores)
      .filter(captain => scores[captain].overall !== null)
      .map(captain => {
        const s = scores[captain];
        const breakdown = ['completedPaperwork', 'attendance', 'ptiEod', 'movePhoto', 'underbilled', 'truckConditions', 'captainReviews']
          .filter(k => s[k] !== null).map(k => `${labelMap[k]} ${s[k]}%`).join(' \u00b7 ');
        return { name: captain, value: s.overall, detail: breakdown };
      })
      .sort((a, b) => b.value - a.value);

    const categories = entries.length > 0 ? [{ key: 'overall', title: 'Overall Captain Score', entries }] : [];
    res.json({ categories });
  } catch (err) {
    console.error('Driver leaderboard fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load leaderboard.' });
  }
});

// Admin Captain Metrics tile: current (live, in-progress) month's scores
// per Captain, broken out by category -- unlike the driver leaderboard,
// this includes the full per-category breakdown, not just an overall
// number, since the admin tile shows the score within each category's own
// panel rather than a single combined leaderboard.
app.get('/api/admin/captain-metrics/current', requireAuth, async (req, res) => {
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const weights = settings.captainMetrics.weights;
    const travelLineCheckStartDate = settings.captainMetrics.travelLineCheckStartDate;
    const { activeMonth } = await getActiveCaptainMetricsMonth(weights, travelLineCheckStartDate);
    const data = await fetchCaptainMetricsRawData();
    const scores = computeCaptainScoresForMonth(activeMonth, data, weights, data.opsManagerNames, data.activeDriverNames, travelLineCheckStartDate);
    res.json({ month: activeMonth, scores });
  } catch (err) {
    console.error('Captain Metrics current-month fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Captain Metrics.' });
  }
});

// Wingman Reviews of Captains, for the admin Captain Metrics tile -- the
// individual reviews behind the Captain Reviews category.
// Same month the rest of the tile is showing, same yes-percentage math
// as Wingman Metrics, plus each Captain's individual reviews so the tile
// can show exactly who said what.
app.get('/api/admin/captain-metrics/wingman-reviews', requireAuth, async (req, res) => {
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const { activeMonth } = await getActiveCaptainMetricsMonth(settings.captainMetrics.weights, settings.captainMetrics.travelLineCheckStartDate);
    const raw = await redis.get('captain-ratings');
    const ratings = raw ? JSON.parse(raw) : [];
    const monthStart = activeMonth + '-01';
    const monthEnd = monthAfter(activeMonth) + '-01';
    const byKey = {};
    ratings
      .filter(r => r.captainName && r.date && r.date >= monthStart && r.date < monthEnd && Array.isArray(r.answers) && r.answers.length > 0)
      .forEach(r => {
        const key = nameDedupKey(r.captainName);
        if (!byKey[key]) byKey[key] = { displayName: r.captainName, latestDate: '', totalYes: 0, totalQuestions: 0, ratingCount: 0, reviews: [] };
        const entry = byKey[key];
        if (r.date >= entry.latestDate) { entry.displayName = r.captainName; entry.latestDate = r.date; }
        r.answers.forEach(a => { entry.totalQuestions++; if (a.answer === true) entry.totalYes++; });
        entry.ratingCount++;
        entry.reviews.push({ date: r.date, wingmanName: r.wingmanName, answers: r.answers, createdAt: r.createdAt });
      });
    const captains = Object.values(byKey).map(e => ({
      name: e.displayName,
      overall: e.totalQuestions > 0 ? Math.round((e.totalYes / e.totalQuestions) * 100) : null,
      totalYes: e.totalYes,
      totalQuestions: e.totalQuestions,
      ratingCount: e.ratingCount,
      reviews: e.reviews.sort((a, b) => (b.date || '').localeCompare(a.date || '') || (b.createdAt || '').localeCompare(a.createdAt || ''))
    })).sort((a, b) => (a.overall ?? 101) - (b.overall ?? 101));
    res.json({ month: activeMonth, captains });
  } catch (err) {
    console.error('Captain wingman-reviews fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load wingman reviews of Captains.' });
  }
});

// Triggered right after a payroll week is saved on the Labor Cost tile --
// checks whether that payroll week's month means an earlier Captain
// Metrics month has now fallen due to be locked, and locks it (and any
// others still overdue) if so. Safe to call anytime; a no-op when nothing
// is actually due.
app.post('/api/admin/captain-metrics/check-month-lock', requireAuth, requireAdmin, async (req, res) => {
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const { activeMonth, locks } = await getActiveCaptainMetricsMonth(settings.captainMetrics.weights, settings.captainMetrics.travelLineCheckStartDate);
    res.json({ ok: true, activeMonth, lockedMonths: locks.map(l => l.month) });
  } catch (err) {
    console.error('Captain Metrics month-lock check failed:', err.message);
    res.status(500).json({ error: 'Could not check Captain Metrics month lock.' });
  }
});

// Weekly overall-score trend for the admin Captain Metrics line graph --
// Monday-Sunday weeks, matching the payroll week convention used
// elsewhere in this app. Computed fresh on every request via the same
// scoring logic as the monthly figures (computeCaptainScoresForRange),
// just at week granularity -- this is for trend-spotting only, not tied
// to commission, so it needs no lock/snapshot system of its own.
// A single week's Captain Metrics scores, for commission calculation --
// distinct from the always-current-month "live" scores shown on the tile
// itself, and from the 12-week trend graph, since commission needs to be
// able to look at exactly one specific week regardless of how long ago it
// was. Reuses the identical scoring function both of those already use.
app.get('/api/admin/captain-metrics/for-week', requireAuth, async (req, res) => {
  const { weekStart } = req.query;
  if (!weekStart || !/^\d{4}-\d{2}-\d{2}$/.test(weekStart)) {
    return res.status(400).json({ error: 'weekStart (YYYY-MM-DD) is required.' });
  }
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const weights = settings.captainMetrics.weights;
    const travelLineCheckStartDate = settings.captainMetrics.travelLineCheckStartDate;
    const data = await fetchCaptainMetricsRawData();

    const weekEndDate = new Date(weekStart + 'T00:00:00Z');
    weekEndDate.setUTCDate(weekEndDate.getUTCDate() + 7); // exclusive
    const weekEnd = weekEndDate.toISOString().slice(0, 10);

    const scores = computeCaptainScoresForRange(weekStart, weekEnd, data, weights, data.opsManagerNames, data.activeDriverNames, travelLineCheckStartDate);
    res.json({ weekStart, scores });
  } catch (err) {
    console.error('Captain Metrics for-week fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Captain Metrics for that week.' });
  }
});

// A single week's Wingman scores, for commission calculation -- mirrors
// Captain Metrics' own for-week endpoint.
app.get('/api/admin/wingman-metrics/for-week', requireAuth, async (req, res) => {
  const { weekStart } = req.query;
  if (!weekStart || !/^\d{4}-\d{2}-\d{2}$/.test(weekStart)) {
    return res.status(400).json({ error: 'weekStart (YYYY-MM-DD) is required.' });
  }
  try {
    const [ratingsRaw, activeDriverKeys] = await Promise.all([
      redis.get('wingman-ratings'),
      fetchActiveDriverKeys()
    ]);
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];

    const weekEndDate = new Date(weekStart + 'T00:00:00Z');
    weekEndDate.setUTCDate(weekEndDate.getUTCDate() + 7); // exclusive
    const weekEnd = weekEndDate.toISOString().slice(0, 10);

    const scores = computeWingmanScoresForRange(weekStart, weekEnd, ratings, activeDriverKeys);
    res.json({ weekStart, scores });
  } catch (err) {
    console.error('Wingman Metrics for-week fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Wingman Metrics for that week.' });
  }
});

// Current (live, in-progress) month's Wingman scores -- same monthly
// cadence and month-locking as Captain Metrics, via the shared
// getActiveMetricsMonth mechanism. Plus each wingman's individual rating
// records for that same month, so the tile can show a full history, not
// just the aggregate score, for transparency into exactly why someone
// scored the way they did.
app.get('/api/admin/wingman-metrics/current', requireAuth, async (req, res) => {
  try {
    const { activeMonth } = await getActiveWingmanMetricsMonth();
    const [ratingsRaw, activeDriverKeys] = await Promise.all([
      redis.get('wingman-ratings'),
      fetchActiveDriverKeys()
    ]);
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];
    const scores = computeWingmanScoresForMonth(activeMonth, ratings, activeDriverKeys);

    const monthStart = activeMonth + '-01';
    const monthEnd = monthAfter(activeMonth) + '-01';
    const ratingsByName = {};
    ratings.filter(r => r.date && r.date >= monthStart && r.date < monthEnd && !activeDriverKeys.has(nameDedupKey(r.wingmanName || ''))).forEach(r => {
      const key = nameDedupKey(r.wingmanName || '');
      if (!ratingsByName[key]) ratingsByName[key] = [];
      ratingsByName[key].push(r);
    });
    Object.keys(ratingsByName).forEach(key => {
      ratingsByName[key].sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    });

    res.json({ month: activeMonth, scores, ratingsByName });
  } catch (err) {
    console.error('Wingman Metrics current fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load current Wingman Metrics.' });
  }
});

// Weekly overall-score trend for the admin Wingman Metrics line graph --
// mirrors Captain Metrics' own weekly-trend endpoint exactly: 12
// Monday-Sunday weeks, computed fresh via the identical range-scoring
// function at week granularity, for trend-spotting only.
app.get('/api/admin/wingman-metrics/weekly-trend', requireAuth, async (req, res) => {
  try {
    const [ratingsRaw, activeDriverKeys] = await Promise.all([
      redis.get('wingman-ratings'),
      fetchActiveDriverKeys()
    ]);
    const ratings = ratingsRaw ? JSON.parse(ratingsRaw) : [];

    const WEEKS_BACK = 12;
    const today = new Date();
    const day = today.getUTCDay();
    const diffToMonday = day === 0 ? -6 : 1 - day;
    const thisMonday = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
    thisMonday.setUTCDate(thisMonday.getUTCDate() + diffToMonday);

    const weeks = [];
    for (let i = WEEKS_BACK - 1; i >= 0; i--) {
      const weekStart = new Date(thisMonday);
      weekStart.setUTCDate(weekStart.getUTCDate() - (i * 7));
      const weekStartStr = weekStart.toISOString().slice(0, 10);
      const weekEndDate = new Date(weekStart);
      weekEndDate.setUTCDate(weekEndDate.getUTCDate() + 7);
      const weekEndStr = weekEndDate.toISOString().slice(0, 10);
      const scores = computeWingmanScoresForRange(weekStartStr, weekEndStr, ratings, activeDriverKeys);
      weeks.push({ weekStart: weekStartStr, label: weekStartStr.slice(5), scores });
    }

    res.json({ weeks });
  } catch (err) {
    console.error('Wingman Metrics weekly trend fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Wingman Metrics weekly trend.' });
  }
});

// Triggered right after a payroll week is saved -- checks whether a
// Wingman Metrics month has now fallen due to be locked, and locks it
// (and any others still overdue) if so. Mirrors Captain Metrics'
// identical check-month-lock endpoint.
app.post('/api/admin/wingman-metrics/check-month-lock', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { activeMonth, locks } = await getActiveWingmanMetricsMonth();
    res.json({ ok: true, activeMonth, lockedMonths: locks.map(l => l.month) });
  } catch (err) {
    console.error('Wingman Metrics month-lock check failed:', err.message);
    res.status(500).json({ error: 'Could not check Wingman Metrics month lock.' });
  }
});

// Same scoring as for-week, but for any explicit [rangeStart, rangeEnd)
// window rather than a fixed 7-day one -- needed by Ops Manager Metrics'
// monthly scoring, which needs a whole calendar month of Captain scores
// at once, not week by week.
app.get('/api/admin/captain-metrics/for-range', requireAuth, async (req, res) => {
  const { rangeStart, rangeEnd } = req.query;
  if (!rangeStart || !/^\d{4}-\d{2}-\d{2}$/.test(rangeStart) || !rangeEnd || !/^\d{4}-\d{2}-\d{2}$/.test(rangeEnd)) {
    return res.status(400).json({ error: 'rangeStart and rangeEnd (YYYY-MM-DD) are both required.' });
  }
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const weights = settings.captainMetrics.weights;
    const travelLineCheckStartDate = settings.captainMetrics.travelLineCheckStartDate;
    const data = await fetchCaptainMetricsRawData();

    const scores = computeCaptainScoresForRange(rangeStart, rangeEnd, data, weights, data.opsManagerNames, data.activeDriverNames, travelLineCheckStartDate);
    res.json({ rangeStart, rangeEnd, scores });
  } catch (err) {
    console.error('Captain Metrics for-range fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Captain Metrics for that range.' });
  }
});

app.get('/api/admin/captain-metrics/weekly-trend', requireAuth, async (req, res) => {
  try {
    const settingsRaw = await redis.get(APP_SETTINGS_KEY);
    const settings = mergeAppSettings(settingsRaw ? JSON.parse(settingsRaw) : null);
    const weights = settings.captainMetrics.weights;
    const travelLineCheckStartDate = settings.captainMetrics.travelLineCheckStartDate;
    const data = await fetchCaptainMetricsRawData();

    const WEEKS_BACK = 12;
    const today = new Date();
    const day = today.getUTCDay();
    const diffToMonday = day === 0 ? -6 : 1 - day;
    const thisMonday = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
    thisMonday.setUTCDate(thisMonday.getUTCDate() + diffToMonday);

    const weeks = [];
    for (let i = WEEKS_BACK - 1; i >= 0; i--) {
      const weekStart = new Date(thisMonday);
      weekStart.setUTCDate(weekStart.getUTCDate() - (i * 7));
      const weekStartStr = weekStart.toISOString().slice(0, 10);
      const weekEndDate = new Date(weekStart);
      weekEndDate.setUTCDate(weekEndDate.getUTCDate() + 7); // exclusive
      const weekEndStr = weekEndDate.toISOString().slice(0, 10);
      const scores = computeCaptainScoresForRange(weekStartStr, weekEndStr, data, weights, data.opsManagerNames, data.activeDriverNames, travelLineCheckStartDate);
      weeks.push({ weekStart: weekStartStr, label: weekStartStr.slice(5), scores });
    }

    res.json({ weeks });
  } catch (err) {
    console.error('Captain Metrics weekly trend fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Captain Metrics weekly trend.' });
  }
});

// A direct list of employee names excluded from Captain Metrics scoring
// entirely -- independent of the Compliance tile's Driver checkbox, so
// excluding someone here (an owner or manager who drives trucks when
// needed, say) doesn't touch their Driver Portal access or anything else
// tied to being a driver.
app.get('/api/admin/captain-metrics-excluded-employees', requireAuth, async (req, res) => {
  try {
    const raw = await redis.get('settings-captain-metrics-excluded-employees');
    res.json({ names: raw ? JSON.parse(raw) : [] });
  } catch (err) {
    console.error('Get Captain Metrics exclusions failed:', err.message);
    res.status(500).json({ error: 'Could not load Captain Metrics exclusions.' });
  }
});

app.post('/api/admin/captain-metrics-excluded-employees', requireAuth, requireAdmin, async (req, res) => {
  const { names } = req.body || {};
  if (!Array.isArray(names)) {
    return res.status(400).json({ error: 'names must be an array.' });
  }
  try {
    await redis.set('settings-captain-metrics-excluded-employees', JSON.stringify(names.filter(n => typeof n === 'string' && n.trim())));
    res.json({ ok: true });
  } catch (err) {
    console.error('Save Captain Metrics exclusions failed:', err.message);
    res.status(500).json({ error: 'Could not save Captain Metrics exclusions.' });
  }
});

// Admin-only visibility into who currently has driver-portal login access --
// names only, never the SSN digits themselves, which live only in the
// unexposed DRIVER_AUTH_LOOKUP_KEY used internally at login time.
app.get('/api/admin/driver-login-status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const raw = await redis.get(DRIVER_AUTH_LOOKUP_KEY);
    const lookup = raw ? JSON.parse(raw) : {};
    const names = Object.values(lookup).sort();
    res.json({ names });
  } catch (err) {
    console.error('Get driver login status failed:', err.message);
    res.status(500).json({ error: 'Could not load driver login status.' });
  }
});

// Storage usage for the admin warning banner. Queries Redis directly (INFO
// memory) for the real, current figure rather than tracking an approximate
// running total in application code. maxBytes reflects the actual Key Value
// plan limit -- set STORAGE_LIMIT_BYTES if the plan is ever upgraded, since
// Redis's own maxmemory setting isn't reliably populated on managed
// instances and can't be trusted as the source of truth here.
const STORAGE_LIMIT_BYTES = parseInt(process.env.STORAGE_LIMIT_BYTES, 10) || (256 * 1024 * 1024); // 256MB Starter plan default
app.get('/api/admin/storage-stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const infoText = await redis.info('memory');
    const match = /used_memory:(\d+)/.exec(infoText);
    const usedBytes = match ? parseInt(match[1], 10) : null;
    if (usedBytes === null) {
      return res.status(502).json({ error: 'Could not read memory usage from the data store.' });
    }
    res.json({ usedBytes, maxBytes: STORAGE_LIMIT_BYTES, percentUsed: usedBytes / STORAGE_LIMIT_BYTES });
  } catch (err) {
    console.error('Storage stats fetch failed:', err.message);
    res.status(500).json({ error: 'Could not check storage usage.' });
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
    completedPaperworkCc: LOCATION.completedPaperworkCc,
    googleReviewLink: LOCATION.googleReviewLink
  },
  materials: {
    supplierPhone: '',
    supplierAccountNumber: '',
    supplierEmail: '',
    shipDays: [],
    orderDeadlineDay: '',
    orderDeadlineTime: ''
  },
  damageClaims: {
    emailBodyTemplate: 'Hi there,\n\nWe\u2019re sorry to hear about the damage during your recent move. To help us process your claim quickly, please upload photos of the damage using the secure link below within the next 7 days:\n\n{{link}}\n\nOnce we receive your photos, our team will review your claim and follow up with next steps.\n\nThank you for your patience.\n\n- The College Hunks Team',
    finalEmailSubject: 'Your Damage Claim \u2014 Job {{jobNumber}}',
    finalEmailCc: '',
    finalEmailBody: 'Hi {{clientFirstName}},\n\nThank you for your patience while we reviewed your damage claim for job {{jobNumber}}. We\u2019ve completed our review using the photos provided and the valuation coverage you selected on your Bill of Lading: {{valuationOption}}.\n\nUnder Georgia Department of Public Safety Maximum Rate Tariff No. 7, the settlement amount for your claim is {{settlementAmount}}. The attached Settlement Summary explains how that amount was determined, item by item.\n\nThis will be refunded via the payment method you used for final billing. Please allow 5-7 business days for the refund to process.\n\nIf you have any questions, just reply to this email.\n\nThanks,\n' + LOCATION.emailSignature
  },
  hiring: {
    emailSubject: 'Welcome to College Hunks Hauling Junk & Moving \u2014 Onboarding Paperwork',
    emailBody: 'Hi {{firstName}},\n\nWelcome aboard! Please complete your onboarding paperwork using the secure link below \u2014 it works great from your phone.\n\n{{link}}\n\nIf you have any questions, just reach out.\n\nThanks,\n' + LOCATION.emailSignature,
    emailCc: ''
  },
  captainMetrics: {
    weights: { completedPaperwork: 30, attendance: 10, ptiEod: 30, movePhoto: 20, underbilled: 10, truckConditions: 0, captainReviews: 0 },
    // The travel-line-item requirement (Underbilled Jobs, for Move/Move
    // Labor jobs) only applies to jobs on or after this date. Set to the
    // day after that check actually went live (2026-09-24), so Captains
    // aren't scored against invoices that predate the feature and could
    // never have had a confirmed travel line in the first place.
    travelLineCheckStartDate: '2026-09-25'
  },
  opsManagerMetrics: {},
  commission: {
    driverRate: 0,
    opsManagerRate: 0,
    opsManagerAssignment: '',
    wingmanRate: 0,
    // Dollars paid per Google review credited to an employee (Manager
    // Review -> Google Reviews). Every employee credited on a review gets
    // the full amount.
    reviewBonusPerReview: 0
  },
  junkRemoval: {
    pricing: [
      { tier: '1/8', label: '1/8 Truckload', price: 119 },
      { tier: '1/6', label: '1/6 Truckload', price: 179 },
      { tier: '1/4', label: '1/4 Truckload', price: 239 },
      { tier: '1/3', label: '1/3 Truckload', price: 289 },
      { tier: '3/8', label: '3/8 Truckload', price: 329 },
      { tier: '1/2', label: '1/2 Truckload', price: 379 },
      { tier: '5/8', label: '5/8 Truckload', price: 419 },
      { tier: '2/3', label: '2/3 Truckload', price: 459 },
      { tier: '3/4', label: '3/4 Truckload', price: 489 },
      { tier: '5/6', label: '5/6 Truckload', price: 519 },
      { tier: '7/8', label: '7/8 Truckload', price: 559 },
      { tier: 'full', label: 'Full Truckload', price: 579 }
    ]
  },
  longDistanceQuote: {
    ccEmails: '',
    emailBodyTemplate: 'Hi {{clientFirstName}}! It was a pleasure speaking with you and I appreciate the opportunity to serve you on your upcoming Move! Attached is our weight and distance quote based on an estimated weight of {{weight}} lbs. This quote includes Full Value Protection (FVP) which would reimburse for the full value of any item damaged beyond repair. There is a free option which would reimburse you at a rate of 60 cents per pound for any item damaged beyond repair. If the free option is chosen, the total cost would be reduced by {{valuationCost}}. Feel free to give me a call if you have any questions/concerns or want to book the HUNKS!\nThanks!'
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

// ============ Damage claim: AI reimbursement recommendation ============
// Looks at a claim's photos (the client's, the crew's crew-caused photos,
// and the crew's pre-existing-damage photos for comparison), reads the
// valuation option the client signed on the bill of lading addendum in the
// job's scanned paperwork, and recommends a reimbursement under Georgia DPS
// Maximum Rate Tariff No. 7, Section V. Claude identifies the damaged
// articles and estimates each one's weight and repair/replacement cost;
// the tariff math itself is done here, so the dollar figure always follows
// the tariff's rules exactly.
const GA_TARIFF_7_VALUATION = `Georgia Department of Public Safety Maximum Rate Tariff No. 7 (effective January 13, 2026), Section V - Valuation and Declaration:
- Option 1, Released Value Protection: coverage at $0.60 per pound per article, based solely on the weight of the lost or damaged article(s). No additional charge. Carrier has the option of repairing and/or restoring to original condition.
- Option 2(a), Full Value Protection, no deductible: coverage based on current replacement value at the time of loss or damage, up to the dollar amount of valuation declared by the shipper. Carrier has the option of repairing and/or restoring to original condition.
- Option 2(b), Full Value Protection, $300.00 deductible: same as 2(a), less a $300 deductible.
- If the carrier fails to secure the shipper's signed declaration before the move, the shipper is considered to have chosen Option 2(a).
- Declared value must be at least $5,000 per room (excluding halls, attics, garages, closets and baths).
Bill of lading terms (Section 1): the carrier is not liable for damage resulting from an act, omission or order of the shipper; insects, moth, vermin and ordinary wear and tear; defect or inherent vice of the article (including susceptibility to temperature/humidity); acts of God; or for documents, currency, money, jewelry, watches, precious stones or articles of extraordinary value not specifically listed on the bill of lading. Claims must be filed in writing within 90 days.`;

const DAMAGE_REC_TOOL = {
  name: 'damage_claim_assessment',
  description: 'Assessment of a household-goods moving damage claim.',
  input_schema: {
    type: 'object',
    properties: {
      valuationFromPaperwork: { type: 'string', enum: ['1', '2a', '2b', 'not_found'], description: 'Which option is selected/signed on the "Addendum to Uniform Household Goods Bill of Lading - Shipper Declaration of Value" in the paperwork, or not_found if no signed selection can be seen.' },
      declaredValueFromPaperwork: { type: 'number', description: 'Declared dollar value written on the addendum for Option 2(a)/2(b), or 0 if none.' },
      paperworkEvidence: { type: 'string', description: 'Briefly, where/what you saw on the addendum (e.g. "Option 1 line signed and dated 10/3"), or why it could not be determined.' },
      items: {
        type: 'array',
        description: 'One entry per distinct physical article that is damaged. Never list the same article twice -- several photos of one article (close-up, wide shot, other angle, client vs crew) are ONE entry.',
        items: {
          type: 'object',
          properties: {
            article: { type: 'string', description: 'What the article is, e.g. "Oak dresser, 6-drawer".' },
            photoNumbers: { type: 'array', items: { type: 'integer' }, description: 'Every photo number that shows THIS physical article (close-ups and wide shots of the same thing all belong here).' },
            damage: { type: 'string', description: 'What the damage is and how severe.' },
            estimatedWeightLbs: { type: 'number', description: 'Estimated weight of the whole article in pounds (Released Value is per pound of the article).' },
            estimatedRepairOrReplaceCost: { type: 'number', description: 'Reasonable cost in dollars to repair the damage, or the current replacement value if repair is not practical.' },
            repairOrReplace: { type: 'string', enum: ['repair', 'replace'] },
            preExistingOverlap: { type: 'string', description: 'Whether the crew\'s pre-existing-damage photos show this same damage before the move ("none", "partial", "same damage"), with a few words.' },
            exclusionConcern: { type: 'string', description: 'Any tariff exclusion that may apply (wear and tear, inherent vice, shipper-packed, extraordinary value not listed), or "none".' },
            covered: { type: 'boolean', description: 'False if the damage appears pre-existing or excluded, so it should not be paid.' }
          },
          required: ['article', 'photoNumbers', 'damage', 'estimatedWeightLbs', 'estimatedRepairOrReplaceCost', 'repairOrReplace', 'preExistingOverlap', 'exclusionConcern', 'covered']
        }
      },
      confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
      concerns: { type: 'array', items: { type: 'string' }, description: 'Things the owner should verify before paying (unclear photos, missing receipts, possible pre-existing damage, etc.).' },
      writtenRecommendation: { type: 'string', description: 'A plain-language recommendation for the business owner, 2-4 short paragraphs: what was damaged, which valuation option applies and why, how the amount was reached under Tariff No. 7, and anything to verify. Do not invent dollar totals different from the item estimates.' }
    },
    required: ['valuationFromPaperwork', 'declaredValueFromPaperwork', 'paperworkEvidence', 'items', 'confidence', 'concerns', 'writtenRecommendation']
  }
};

function dataUriParts(uri) {
  const m = /^data:([^;,]+);base64,(.+)$/s.exec(String(uri || ''));
  return m ? { mediaType: m[1], data: m[2] } : null;
}

app.post('/api/admin/damage-claim/recommend', requireAuth, async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'AI recommendations need a Claude key (ANTHROPIC_API_KEY in Render).' });
  const { claimId, valuation, declaredValue, notes } = req.body || {};
  try {
    const [claimsRaw, reportsRaw, uploadsRaw, archiveRaw] = await Promise.all([
      redis.get('damage-claims'), redis.get('moving-damage-reports'), redis.get('paperwork-uploads'), redis.get(JOB_ARCHIVE_KEY)
    ]);
    const claim = (claimsRaw ? JSON.parse(claimsRaw) : []).find(c => c.id === claimId);
    if (!claim) return res.status(404).json({ error: 'Claim not found.' });
    const report = (reportsRaw ? JSON.parse(reportsRaw) : []).find(r => String(r.jobNumber) === String(claim.jobNumber)) || {};
    const job = (archiveRaw ? JSON.parse(archiveRaw) : []).find(j => String(j.jobNumber) === String(claim.jobNumber)) || {};

    // Photos, labeled by source, up to 18 in all.
    const groups = [
      { label: 'CLIENT CLAIM PHOTO (uploaded by the client after the move)', keys: (claim.photos || []).map(p => `damage-claim-photo-${claim.id}-${p.id}`) },
      { label: 'CREW-CAUSED DAMAGE PHOTO (taken by the crew, documenting damage they caused)', keys: report.causedPhotoKeys || [] },
      { label: 'PRE-EXISTING DAMAGE PHOTO (taken by the crew BEFORE the move -- damage here was already present and is not the carrier\'s responsibility)', keys: report.preExistingPhotoKeys || [] }
    ];
    const content = [];
    const counts = {};
    let total = 0;
    for (const g of groups) {
      counts[g.label.split(' (')[0]] = 0;
      for (const key of g.keys) {
        if (total >= 18) break;
        const raw = await redis.get(key);
        let uri = null; try { uri = raw ? JSON.parse(raw) : null; } catch (e) { uri = raw; }
        const parts = dataUriParts(uri);
        if (!parts || !parts.mediaType.startsWith('image/')) continue;
        content.push({ type: 'text', text: `Photo ${total + 1} \u2014 ${g.label}:` });
        content.push({ type: 'image', source: { type: 'base64', media_type: parts.mediaType, data: parts.data } });
        counts[g.label.split(' (')[0]]++;
        total++;
      }
    }
    if (total === 0) return res.status(400).json({ error: 'This claim has no photos to analyze yet.' });

    // The job's scanned paperwork packet, to read the signed valuation addendum.
    let paperworkIncluded = false;
    if (!valuation || valuation === 'paperwork') {
      const upload = (uploadsRaw ? JSON.parse(uploadsRaw) : []).filter(u => String(u.jobNumber) === String(claim.jobNumber))
        .sort((a, b) => (b.invoiceUploadedAt || b.uploadedAt || '').localeCompare(a.invoiceUploadedAt || a.uploadedAt || ''))[0];
      if (upload) {
        const raw = await redis.get('paperwork-upload-' + upload.id);
        let uri = null; try { uri = raw ? JSON.parse(raw) : null; } catch (e) { uri = raw; }
        const parts = dataUriParts(uri);
        if (parts && parts.mediaType === 'application/pdf') {
          content.unshift({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: parts.data } });
          content.unshift({ type: 'text', text: 'THE JOB\'S SCANNED PAPERWORK PACKET (find the "Addendum to Uniform Household Goods Bill of Lading - Shipper Declaration of Value" page and read which option the client signed):' });
          paperworkIncluded = true;
        } else if (parts && parts.mediaType.startsWith('image/')) {
          content.unshift({ type: 'image', source: { type: 'base64', media_type: parts.mediaType, data: parts.data } });
          content.unshift({ type: 'text', text: 'THE JOB\'S SCANNED PAPERWORK (look for the signed valuation addendum):' });
          paperworkIncluded = true;
        }
      }
    }

    const chosen = ['1', '2a', '2b'].includes(valuation) ? valuation : null;
    content.push({ type: 'text', text:
      `You are helping a College Hunks Hauling Junk & Moving franchise owner in Georgia evaluate a customer's moving damage claim.\n\n${GA_TARIFF_7_VALUATION}\n\n` +
      `Job ${claim.jobNumber}${job.jobType ? ' (' + job.jobType + ')' : ''}, client ${claim.clientName || job.clientName || 'unknown'}.\n` +
      (chosen ? `The owner states the client chose Option ${chosen}${Number(declaredValue) > 0 ? ' with a declared value of $' + Number(declaredValue) : ''}. Use that.\n` : (paperworkIncluded ? 'Read the client\'s valuation choice from the signed addendum in the paperwork.\n' : 'No paperwork is available; report valuationFromPaperwork as not_found.\n')) +
      (notes ? `Owner's notes about the claim: ${String(notes).slice(0, 2000)}\n` : '') +
      `\nIMPORTANT -- count each damaged ARTICLE once, not each photo. Clients and crews often send several photos of the same item: a zoomed-in close-up of the damage plus a wider shot, the same spot from another angle, or the client's photo and the crew's photo of the same piece. Before listing items, decide which photos show the same physical article (same color, material, shape, finish, setting) and group them into one entry, listing all of its photo numbers. Only list separate entries for articles that are clearly different objects. When unsure whether two photos show the same article, treat them as the same and say so in concerns.` +
      `\nIdentify each damaged article shown in the claim and crew-caused photos. Compare against the pre-existing-damage photos: damage that was already there before the move is not covered. Estimate each article's full weight in pounds and a reasonable current repair or replacement cost in US dollars. Be conservative and realistic, not generous. Then write the recommendation.` });

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 4096, tools: [DAMAGE_REC_TOOL], tool_choice: { type: 'tool', name: 'damage_claim_assessment' }, messages: [{ role: 'user', content }] })
    });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      console.error('[damage-rec] Claude call failed:', r.status, body.slice(0, 400));
      return res.status(502).json({ error: 'The AI service returned an error \u2014 try again in a minute.' });
    }
    const d = await r.json();
    const block = (d.content || []).find(b => b.type === 'tool_use');
    if (!block) return res.status(502).json({ error: 'The AI didn\u2019t return an assessment \u2014 try again.' });
    const a = block.input || {};

    // Tariff math, done here.
    const items = (a.items || []).map(it => {
      const weight = Math.max(0, Number(it.estimatedWeightLbs) || 0);
      const cost = Math.max(0, Number(it.estimatedRepairOrReplaceCost) || 0);
      const covered = it.covered !== false;
      const releasedCap = Math.round(weight * 0.60 * 100) / 100;
      return { ...it, estimatedWeightLbs: weight, estimatedRepairOrReplaceCost: cost, covered,
        releasedValueAmount: covered ? Math.min(cost, releasedCap) : 0, releasedValueCap: releasedCap,
        fullValueAmount: covered ? cost : 0 };
    });
    const round2 = n => Math.round(n * 100) / 100;
    const releasedTotal = round2(items.reduce((t, i) => t + i.releasedValueAmount, 0));
    const fullCostTotal = round2(items.reduce((t, i) => t + i.fullValueAmount, 0));
    const option = chosen || (['1', '2a', '2b'].includes(a.valuationFromPaperwork) ? a.valuationFromPaperwork : null);
    const declared = Number(chosen ? declaredValue : a.declaredValueFromPaperwork) || 0;
    const cap = v => declared > 0 ? Math.min(v, declared) : v;
    const totals = {
      '1': releasedTotal,
      '2a': round2(cap(fullCostTotal)),
      '2b': round2(cap(Math.max(0, fullCostTotal - 300)))
    };
    const result = {
      generatedAt: new Date().toISOString(), by: req.userEmail || '',
      option, optionSource: chosen ? 'entered' : (option ? 'paperwork' : 'not_found'),
      declaredValue: declared, paperworkIncluded, paperworkEvidence: a.paperworkEvidence || '',
      items, totals, recommendedTotal: option ? totals[option] : null,
      confidence: a.confidence || 'low', concerns: a.concerns || [], writtenRecommendation: a.writtenRecommendation || '',
      photoCounts: counts
    };
    // Kept on the claim so it can be reopened without re-running.
    const claims = JSON.parse(await redis.get('damage-claims') || '[]');
    const c = claims.find(x => x.id === claimId);
    if (c) { c.aiRecommendation = result; await redis.set('damage-claims', JSON.stringify(claims)); }
    console.log(`[damage-rec] claim ${claimId} job ${claim.jobNumber}: option ${option || 'unknown'} (${result.optionSource}), ${items.length} item(s), recommended ${result.recommendedTotal}`);
    res.json(result);
  } catch (err) {
    console.error('[damage-rec] failed:', err.message);
    res.status(500).json({ error: 'Could not prepare the recommendation.' });
  }
});

// ============ Google Reviews (Places API) ============
// Pulls the business's Google reviews so Manager Review can credit each
// one to the employees it's about. Google only ever returns the 5 newest
// reviews, so the server checks every hour and keeps every review it has
// ever seen -- nothing is missed unless more than 5 arrive within an hour.
// Needs GOOGLE_PLACES_API_KEY in Render's environment; GOOGLE_PLACE_ID is
// optional (looked up once by name and location, then remembered).
const GOOGLE_REVIEWS_KEY = 'google-reviews';
const GOOGLE_REVIEWS_META_KEY = 'google-reviews-meta';
const GOOGLE_PLACES_QUERY = LOCATION.googleListingQuery;
const GOOGLE_PLACES_CENTER = { latitude: LOCATION.officeLat, longitude: LOCATION.officeLng };
const GOOGLE_REVIEWS_POLL_MS = 60 * 60 * 1000;

function easternDateFromMs(ms) {
  return new Date(ms).toLocaleDateString('en-CA', { timeZone: LOCATION.timeZone });
}
// Stable across both of Google's API formats (and across text edits), so
// the same review is never stored twice.
function googleReviewId(authorName, unixSeconds) {
  return 'gr_' + crypto.createHash('sha1').update(String(authorName || '') + '|' + String(unixSeconds || '')).digest('hex').slice(0, 16);
}

async function resolveGooglePlaceId(apiKey, meta) {
  if (process.env.GOOGLE_PLACE_ID) return process.env.GOOGLE_PLACE_ID;
  if (meta.placeId) return meta.placeId;
  const r = await fetch('https://places.googleapis.com/v1/places:searchText', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress' },
    body: JSON.stringify({ textQuery: GOOGLE_PLACES_QUERY, locationBias: { circle: { center: GOOGLE_PLACES_CENTER, radius: 3000 } } })
  });
  const d = await r.json();
  if (!r.ok) throw new Error((d.error && d.error.message) || 'Google place search failed.');
  const place = (d.places || [])[0];
  if (!place) throw new Error('Could not find the business on Google Maps.');
  meta.placeId = place.id;
  meta.placeName = place.displayName ? place.displayName.text : '';
  meta.placeAddress = place.formattedAddress || '';
  return place.id;
}

// Tries the classic Place Details API first, since it can sort by newest;
// falls back to the current Places API, which newer Google Cloud projects
// are limited to. Both are normalized to the same shape.
async function fetchGoogleReviewsFromApi(apiKey, placeId) {
  let classicProblem = null;
  try {
    const url = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${encodeURIComponent(placeId)}&fields=rating,user_ratings_total,reviews&reviews_sort=newest&reviews_no_translations=true&key=${encodeURIComponent(apiKey)}`;
    const r = await fetch(url);
    const d = await r.json();
    if (d.status !== 'OK' || !d.result) {
      classicProblem = `${d.status || 'no status'}${d.error_message ? ': ' + d.error_message : ''}`;
      console.error('[google-reviews] legacy Places API unavailable, falling back to the new API (most-relevant reviews only) --', classicProblem);
    }
    if (d.status === 'OK' && d.result) {
      return {
        source: 'places-classic',
        rating: d.result.rating ?? null,
        total: d.result.user_ratings_total ?? null,
        reviews: (d.result.reviews || []).map(v => ({
          authorName: v.author_name || 'Google user', authorUrl: v.author_url || '', photoUrl: v.profile_photo_url || '',
          rating: Number(v.rating) || null, text: v.text || '', unix: Number(v.time) || 0
        }))
      };
    }
  } catch (err) {
    classicProblem = err.message;
    console.error('[google-reviews] classic Places request failed, trying the current API:', err.message);
  }
  const r = await fetch(`https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}`, {
    headers: { 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': 'rating,userRatingCount,reviews' }
  });
  const d = await r.json();
  if (!r.ok) throw new Error((d.error && d.error.message) || 'Google place details failed.');
  return {
    source: 'places-new',
    classicProblem,
    rating: d.rating ?? null,
    total: d.userRatingCount ?? null,
    reviews: (d.reviews || []).map(v => ({
      authorName: (v.authorAttribution && v.authorAttribution.displayName) || 'Google user',
      authorUrl: (v.authorAttribution && v.authorAttribution.uri) || '',
      photoUrl: (v.authorAttribution && v.authorAttribution.photoUri) || '',
      rating: Number(v.rating) || null,
      text: (v.originalText && v.originalText.text) || (v.text && v.text.text) || '',
      unix: v.publishTime ? Math.floor(Date.parse(v.publishTime) / 1000) : 0
    }))
  };
}

// ---- Google Business Profile (complete review history) ----
// The Places API above only ever returns 5 reviews. Once the listing's
// owner/manager connects their Google account here (one-time OAuth
// consent), the Business Profile API returns every review the listing has
// ever had, and becomes the source for the hourly check. Needs
// GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in Render, and
// Google's approval of the project for Business Profile API access.
// GBP_LOCATION_NAME (e.g. "locations/123...") is optional -- by default it
// picks the listing whose name includes LOCATION.googleListingMatch.
const GBP_TOKEN_KEY = 'google-business-oauth';
const GBP_OAUTH_STATE_PREFIX = 'auth:gbp-oauth-state:';
const GBP_SCOPE = 'https://www.googleapis.com/auth/business.manage';
const GBP_STAR_RATINGS = { ONE: 1, TWO: 2, THREE: 3, FOUR: 4, FIVE: 5 };

function gbpRedirectUri(req) {
  return `https://${req.get('host')}/api/google-business/oauth-callback`;
}
function gbpConfigured() {
  return !!(process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET);
}

async function gbpAccessToken() {
  const raw = await redis.get(GBP_TOKEN_KEY);
  const stored = raw ? JSON.parse(raw) : null;
  if (!stored || !stored.refreshToken) return null;
  if (stored.accessToken && stored.expiresAt && Date.now() < stored.expiresAt - 60 * 1000) return stored.accessToken;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      refresh_token: stored.refreshToken, grant_type: 'refresh_token'
    })
  });
  const d = await r.json();
  if (!r.ok) throw new Error(`Google sign-in expired or was revoked (${d.error_description || d.error || r.status}) \u2014 reconnect Google Business Profile.`);
  stored.accessToken = d.access_token;
  stored.expiresAt = Date.now() + (Number(d.expires_in) || 3600) * 1000;
  await redis.set(GBP_TOKEN_KEY, JSON.stringify(stored));
  return stored.accessToken;
}

async function gbpGet(url, token) {
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = (d.error && d.error.message) || `HTTP ${r.status}`;
    throw new Error(r.status === 429 || /quota/i.test(msg)
      ? `Google hasn\u2019t approved Business Profile API access for this project yet (${msg}).`
      : msg);
  }
  return d;
}

// Finds the account + listing to read reviews from, remembering it after
// the first lookup.
async function gbpResolveLocation(token, meta) {
  if (meta.gbpAccount && meta.gbpLocation) return { account: meta.gbpAccount, location: meta.gbpLocation };
  const accounts = (await gbpGet('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', token)).accounts || [];
  const wanted = process.env.GBP_LOCATION_NAME || '';
  let fallback = null;
  for (const acct of accounts) {
    let pageToken = '';
    do {
      const d = await gbpGet(`https://mybusinessbusinessinformation.googleapis.com/v1/${acct.name}/locations?readMask=name,title,storefrontAddress&pageSize=100${pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : ''}`, token);
      for (const loc of (d.locations || [])) {
        const hit = wanted ? loc.name === wanted : (loc.title || '').toLowerCase().includes(LOCATION.googleListingMatch.toLowerCase());
        if (hit) {
          Object.assign(meta, { gbpAccount: acct.name, gbpLocation: loc.name, gbpLocationTitle: loc.title || '' });
          return { account: acct.name, location: loc.name };
        }
        if (!fallback) fallback = { account: acct.name, location: loc.name, title: loc.title || '' };
      }
      pageToken = d.nextPageToken || '';
    } while (pageToken);
  }
  if (!fallback) throw new Error('The connected Google account doesn\u2019t manage any Business Profile listings.');
  Object.assign(meta, { gbpAccount: fallback.account, gbpLocation: fallback.location, gbpLocationTitle: fallback.title });
  return fallback;
}

// The full history on the first run, then just the newest page each hour.
async function gbpFetchReviews(token, meta) {
  const { account, location } = await gbpResolveLocation(token, meta);
  const locationId = location.split('/').pop();
  const out = [];
  let pageToken = '';
  let total = null, rating = null;
  do {
    const d = await gbpGet(`https://mybusiness.googleapis.com/v4/${account}/locations/${locationId}/reviews?pageSize=50&orderBy=updateTime%20desc${pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : ''}`, token);
    if (total === null) { total = d.totalReviewCount ?? null; rating = d.averageRating ?? null; }
    (d.reviews || []).forEach(v => out.push({
      gbpReviewId: v.reviewId,
      authorName: (v.reviewer && v.reviewer.displayName) || 'Google user',
      authorUrl: '', photoUrl: (v.reviewer && v.reviewer.profilePhotoUrl) || '',
      rating: GBP_STAR_RATINGS[v.starRating] || null,
      text: v.comment || '',
      unix: v.createTime ? Math.floor(Date.parse(v.createTime) / 1000) : 0
    }));
    pageToken = d.nextPageToken || '';
  } while (pageToken && !meta.gbpBackfilledAt);
  meta.gbpBackfilledAt = meta.gbpBackfilledAt || new Date().toISOString();
  return { source: 'business-profile', rating, total, reviews: out };
}

app.get('/api/admin/google-business/auth-url', requireAuth, requireAdmin, async (req, res) => {
  if (!gbpConfigured()) {
    return res.status(400).json({ error: 'GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET need to be added in Render first.' });
  }
  const state = crypto.randomBytes(24).toString('hex');
  await redis.set(GBP_OAUTH_STATE_PREFIX + state, '1', 'EX', 15 * 60);
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, redirect_uri: gbpRedirectUri(req), response_type: 'code',
    scope: GBP_SCOPE, access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true', state
  });
  res.json({ url });
});

app.get('/api/google-business/oauth-callback', async (req, res) => {
  const page = (title, msg) => res.send(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;padding:0 20px;line-height:1.5"><h2>${title}</h2><p>${msg}</p><p>You can close this tab and go back to the dashboard.</p></body>`);
  const { code, state, error } = req.query;
  if (error) return page('Not connected', `Google said: ${String(error).replace(/[<>&]/g, '')}`);
  if (!code || !state || !(await redis.get(GBP_OAUTH_STATE_PREFIX + state))) return page('Not connected', 'This sign-in link expired or was already used \u2014 start again from the Google Reviews tab.');
  await redis.del(GBP_OAUTH_STATE_PREFIX + state);
  try {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: String(code), client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
        redirect_uri: gbpRedirectUri(req), grant_type: 'authorization_code'
      })
    });
    const d = await r.json();
    if (!r.ok || !d.refresh_token) throw new Error(d.error_description || d.error || 'Google didn\u2019t return a long-term sign-in.');
    await redis.set(GBP_TOKEN_KEY, JSON.stringify({
      refreshToken: d.refresh_token, accessToken: d.access_token,
      expiresAt: Date.now() + (Number(d.expires_in) || 3600) * 1000, connectedAt: new Date().toISOString()
    }));
    // Pull the full history right away.
    const metaRaw = await redis.get(GOOGLE_REVIEWS_META_KEY);
    const meta = metaRaw ? JSON.parse(metaRaw) : {};
    delete meta.gbpBackfilledAt; delete meta.gbpAccount; delete meta.gbpLocation;
    await redis.set(GOOGLE_REVIEWS_META_KEY, JSON.stringify(meta));
    refreshGoogleReviews().catch(() => {});
    page('Connected \u2713', 'Google Business Profile is connected. Every review on the listing is being pulled in now \u2014 refresh the Google Reviews tab in a minute.');
  } catch (err) {
    console.error('[google-business] OAuth exchange failed:', err.message);
    page('Not connected', `Google returned an error: ${String(err.message).replace(/[<>&]/g, '')}`);
  }
});

app.post('/api/admin/google-business/disconnect', requireAuth, requireAdmin, async (req, res) => {
  await redis.del(GBP_TOKEN_KEY);
  res.json({ ok: true });
});

let googleReviewsRefreshInFlight = null;
function refreshGoogleReviews() {
  if (googleReviewsRefreshInFlight) return googleReviewsRefreshInFlight;
  googleReviewsRefreshInFlight = (async () => {
    let gbpTokenError = null;
    const apiKey = process.env.GOOGLE_PLACES_API_KEY;
    const gbpToken = gbpConfigured() ? await gbpAccessToken().catch(err => { gbpTokenError = err.message; return null; }) : null;
    if (!apiKey && !gbpToken) return { added: 0, configured: false };
    const [reviewsRaw, metaRaw] = await Promise.all([redis.get(GOOGLE_REVIEWS_KEY), redis.get(GOOGLE_REVIEWS_META_KEY)]);
    const reviews = reviewsRaw ? JSON.parse(reviewsRaw) : [];
    const meta = metaRaw ? JSON.parse(metaRaw) : {};
    try {
      let result = null;
      meta.gbpError = gbpTokenError;
      if (gbpToken) {
        try { result = await gbpFetchReviews(gbpToken, meta); }
        catch (err) {
          // Keep reviews flowing from Places while Business Profile is
          // unavailable (e.g. still waiting on Google's approval).
          meta.gbpError = err.message;
          console.error('[google-business] review fetch failed, using Places instead:', err.message);
        }
      }
      if (!result) {
        if (!apiKey) throw new Error(meta.gbpError || 'No Google review source is available.');
        const placeId = await resolveGooglePlaceId(apiKey, meta);
        result = await fetchGoogleReviewsFromApi(apiKey, placeId);
      } else {
        meta.gbpError = null;
      }
      const byId = new Map(reviews.map(r => [r.id, r]));
      // The same review reaches us from Places and from Business Profile
      // with slightly different details, so a Business Profile review is
      // matched to one already on file by reviewer and time -- keeping its
      // id, and any credit already given for it.
      const norm = n => String(n || '').trim().toLowerCase();
      const findExisting = (v, id) => {
        if (byId.has(id)) return byId.get(id);
        if (v.gbpReviewId) {
          const sameGbp = [...byId.values()].find(r => r.gbpReviewId === v.gbpReviewId);
          if (sameGbp) return sameGbp;
          return [...byId.values()].find(r => !r.gbpReviewId && norm(r.authorName) === norm(v.authorName) &&
            Math.abs(Date.parse(r.publishedAt) / 1000 - v.unix) <= 36 * 60 * 60);
        }
        return null;
      };
      let added = 0;
      result.reviews.forEach(v => {
        if (!v.unix) return;
        const id = googleReviewId(v.authorName, v.unix);
        const normalized = {
          authorName: v.authorName, authorUrl: v.authorUrl, photoUrl: v.photoUrl,
          rating: v.rating, text: v.text,
          publishedAt: new Date(v.unix * 1000).toISOString(),
          date: easternDateFromMs(v.unix * 1000),
          ...(v.gbpReviewId ? { gbpReviewId: v.gbpReviewId } : {})
        };
        const existing = findExisting(v, id);
        if (existing) Object.assign(existing, normalized); // a reviewer can edit their text or stars
        else { byId.set(id, Object.assign({ id }, normalized, { firstSeenAt: new Date().toISOString() })); added++; }
      });
      // The first check ever sets where crediting starts: reviews from the
      // previous week onward, so older reviews already on the listing
      // don't all turn into back pay.
      if (!meta.trackingStartDate) meta.trackingStartDate = easternDateFromMs(Date.now() - 7 * 24 * 60 * 60 * 1000);
      Object.assign(meta, { rating: result.rating, total: result.total, source: result.source, classicProblem: result.classicProblem || null, lastCheckedAt: new Date().toISOString(), lastError: null });
      console.log(`[google-reviews] checked via ${result.source}: ${result.reviews.length} returned, ${added} new, newest posted ${result.reviews.map(v => v.unix).sort((a, b) => b - a).map(u => easternDateFromMs(u * 1000))[0] || 'n/a'}`);
      const merged = [...byId.values()].sort((a, b) => (b.publishedAt || '').localeCompare(a.publishedAt || ''));
      await Promise.all([redis.set(GOOGLE_REVIEWS_KEY, JSON.stringify(merged)), redis.set(GOOGLE_REVIEWS_META_KEY, JSON.stringify(meta))]);
      if (added > 0) console.log(`[google-reviews] ${added} new review(s) via ${result.source}`);
      return { added, configured: true };
    } catch (err) {
      console.error('[google-reviews] refresh failed:', err.message);
      Object.assign(meta, { lastCheckedAt: new Date().toISOString(), lastError: err.message });
      await redis.set(GOOGLE_REVIEWS_META_KEY, JSON.stringify(meta));
      throw err;
    }
  })().finally(() => { googleReviewsRefreshInFlight = null; });
  return googleReviewsRefreshInFlight;
}

async function googleReviewsPayload() {
  const [reviewsRaw, metaRaw] = await Promise.all([redis.get(GOOGLE_REVIEWS_KEY), redis.get(GOOGLE_REVIEWS_META_KEY)]);
  const gbpRaw = await redis.get(GBP_TOKEN_KEY);
  const gbp = gbpRaw ? JSON.parse(gbpRaw) : null;
  return {
    configured: !!process.env.GOOGLE_PLACES_API_KEY || !!gbp,
    businessProfile: { available: gbpConfigured(), connected: !!(gbp && gbp.refreshToken), connectedAt: gbp ? gbp.connectedAt : null },
    reviews: reviewsRaw ? JSON.parse(reviewsRaw) : [],
    meta: metaRaw ? JSON.parse(metaRaw) : {}
  };
}

app.get('/api/admin/google-reviews', requireAuth, async (req, res) => {
  try {
    const payload = await googleReviewsPayload();
    // Opportunistic top-up if the hourly check is overdue (e.g. the
    // server was asleep) -- doesn't hold up this response.
    const last = payload.meta.lastCheckedAt ? Date.parse(payload.meta.lastCheckedAt) : 0;
    if (payload.configured && Date.now() - last > GOOGLE_REVIEWS_POLL_MS) refreshGoogleReviews().catch(() => {});
    res.json(payload);
  } catch (err) {
    console.error('Google reviews fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load Google reviews.' });
  }
});

app.post('/api/admin/google-reviews/refresh', requireAuth, async (req, res) => {
  if (!process.env.GOOGLE_PLACES_API_KEY && !(await redis.get(GBP_TOKEN_KEY))) {
    return res.status(400).json({ error: 'Google reviews aren\u2019t connected yet \u2014 GOOGLE_PLACES_API_KEY needs to be added in Render.' });
  }
  try {
    const result = await refreshGoogleReviews();
    res.json(Object.assign(await googleReviewsPayload(), { added: result.added }));
  } catch (err) {
    res.status(502).json({ error: `Google returned an error: ${err.message}` });
  }
});

setTimeout(() => refreshGoogleReviews().catch(() => {}), 20 * 1000);
setInterval(() => refreshGoogleReviews().catch(() => {}), GOOGLE_REVIEWS_POLL_MS);

// ============ Materials: Balance Due Override PIN ============
// Kept out of the general settings-app-config blob (and its requireAuth-only
// GET) on purpose -- the PIN value itself should never reach the frontend
// in plaintext, even to an authenticated non-admin user viewing settings.
// Only whether a PIN is currently set is exposed; verification happens
// entirely server-side.
const MATERIALS_OVERRIDE_PIN_KEY = 'settings-materials-override-pin';

app.get('/api/admin/override-pin-status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const pin = await redis.get(MATERIALS_OVERRIDE_PIN_KEY);
    res.json({ isSet: !!pin });
  } catch (err) {
    console.error('Override PIN status check failed:', err.message);
    res.status(500).json({ error: 'Could not check PIN status.' });
  }
});

app.post('/api/admin/override-pin', requireAuth, requireAdmin, async (req, res) => {
  const { pin } = req.body || {};
  if (typeof pin !== 'string' || !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be exactly 4 digits.' });
  }
  try {
    await redis.set(MATERIALS_OVERRIDE_PIN_KEY, pin);
    res.json({ ok: true });
  } catch (err) {
    console.error('Save override PIN failed:', err.message);
    res.status(500).json({ error: 'Could not save PIN.' });
  }
});

app.post('/api/verify-override-pin', requireAuth, async (req, res) => {
  const { pin } = req.body || {};
  if (typeof pin !== 'string') {
    return res.status(400).json({ error: 'PIN is required.' });
  }
  try {
    const savedPin = await redis.get(MATERIALS_OVERRIDE_PIN_KEY);
    if (!savedPin) {
      return res.status(400).json({ error: 'No override PIN has been set up yet \u2014 ask an administrator to set one in Settings.' });
    }
    res.json({ valid: pin === savedPin });
  } catch (err) {
    console.error('Verify override PIN failed:', err.message);
    res.status(500).json({ error: 'Could not verify PIN.' });
  }
});

// ============ Completed Paperwork: Client Invoice Extraction ============
// Reads the Balance Due and billed material line items off a HunkWare
// completed invoice -- the "concrete source of truth" for both the payment
// reconciliation gate and the materials-billed reconciliation, replacing
// manual entry when available.
// Step 1 of a two-step extraction: identify which pages (if any) are a
// genuine invoice/receipt BEFORE extracting any dollar figures. The actual
// figure-extraction call (below) then only ever sees those specific pages
// -- removing work order/contract/estimate pages from its context entirely,
// rather than just instructing it to ignore them, since instruction alone
// proved insufficient to stop it pulling a real number from the wrong page.
const IDENTIFY_INVOICE_PAGES_TOOL = {
  name: 'identify_invoice_pages',
  description: 'Identify which pages of this multi-page document, if any, are a genuine invoice or receipt, as opposed to a work order, contract, estimate, or signature page.',
  input_schema: {
    type: 'object',
    properties: {
      invoicePageIndices: {
        type: 'array',
        items: { type: 'integer' },
        description: '0-indexed page numbers (matching the order pages were provided, first page is 0) that are a genuine HunkWare invoice or receipt page -- has a Balance Due, Subtotal, or Tax line explicitly printed and labeled as such on that specific page. A work order, contract, estimate, or signature page is NOT an invoice, even if it shows a dollar total. Empty array if no such page exists anywhere in the document.'
      },
      jobType: { type: 'string', enum: ['move', 'movelabor', 'longdistance'], description: 'If any page is a work order showing a job type, report it: a full move ("move"), labor-only ("movelabor"), or long distance ("longdistance"). If the document contains work orders for more than one job number, report the type for the specific job number given in the prompt, not any other job that happens to appear. Omit this field entirely if no work order page with this info is present.' },
      originAddress: { type: 'string', description: 'If any page is a work order showing a "FROM" / Origin Address field, report it exactly as printed. If the document contains work orders for more than one job number, report the address for the specific job number given in the prompt, not any other job that happens to appear. Omit this field entirely if no such page is present.' }
    },
    required: ['invoicePageIndices']
  }
};

// Shared grounding utilities -- proven across the invoice extraction work,
// reused by any endpoint that needs to verify a model-claimed dollar figure
// actually has a basis in the real document rather than trusting it outright.
//
// Layer 1: a claimed dollar figure is only trusted if its quoted "as
// printed" line actually contains the right keyword AND a dollar amount
// that numerically matches (within rounding) what was reported -- catches
// an internally inconsistent fabrication.
//
// Numbers are matched with an OPTIONAL decimal part: some documents always
// print cents ("$3,993.23"), but others (e.g. Fathom-style management
// reports) print whole dollars with no decimal point at all ("$182") for
// every figure, cents or not. Requiring a decimal previously meant every
// single figure on that second document type silently failed to ground,
// regardless of how correct the reading was.
function validateAgainstQuote(amount, quotedLine, keyword) {
  const amt = Number(amount) || 0;
  if (amt <= 0) return amt;
  const quote = (quotedLine || '').trim();
  if (!quote) return 0;
  if (!new RegExp(keyword, 'i').test(quote)) return 0;
  const numbersInQuote = (quote.match(/[\d,]+(?:\.\d{1,2})?/g) || []).map(s => parseFloat(s.replace(/,/g, '')));
  const matchesReportedAmount = numbersInQuote.some(n => Math.abs(n - amt) < 0.01);
  return matchesReportedAmount ? amt : 0;
}

// Layer 2 (only possible in text mode, and much stronger): search the
// server's OWN independently-extracted text for the claimed dollar amount
// appearing near the relevant keyword -- not just checking the model's
// self-reported quote for internal consistency, but verifying against
// ground truth the model never got to author. Catches a figure that has
// zero basis anywhere on the real document at all, which a self-consistency
// check alone cannot. sourceText must already be lowercased, whitespace-
// collapsed, and comma-stripped (comma-stripping matters: a printed
// "$3,993.23" would otherwise never match amt.toFixed(2)'s comma-free
// "3993.23", silently rejecting every real amount of $1,000 or more).
//
// Tries both a cents-formatted search ("182.00") and, when the amount is a
// whole number, a plain whole-dollar search ("182") too -- some documents
// never print cents at all. The whole-number search uses word boundaries
// so it can never match as a false substring inside a larger number (e.g.
// "182" must never match inside "1820.00").
//
// Checks EVERY occurrence of the amount in the text, not just the first --
// a P&L can print the identical figure on several consecutive lines under
// different labels (e.g. "Earnings Before Tax $182", "Earnings After Tax
// $182", "Net Income $182" all in a row when nothing further adjusts the
// number between them). Stopping at the first occurrence risks landing on
// the wrong line and never reaching the correct one just below it.
function verifyAgainstSourceText(sourceText, amount, keyword) {
  const amt = Number(amount) || 0;
  if (amt <= 0) return amt;
  const candidates = [amt.toFixed(2)];
  if (Number.isInteger(amt)) candidates.push(String(amt));
  for (const amountStr of candidates) {
    const escaped = amountStr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp('\\b' + escaped + '\\b', 'g');
    let match;
    while ((match = regex.exec(sourceText)) !== null) {
      const idx = match.index;
      // Asymmetric on purpose: a label always precedes its value in every
      // document type seen so far, so 40 chars behind covers a real label
      // reliably, while only 15 chars ahead avoids reaching past this
      // row's own trailing text (a percentage, a stray character) into
      // the START of the NEXT row -- which matters when a short sub-total
      // row sits immediately before the row actually wanted (e.g. "Total
      // Other Equity $121,566 Total Equity $69,255"): a wide "after"
      // window let the wrong amount's search pick up the next row's
      // correctly-labeled text and falsely pass.
      const window = sourceText.slice(Math.max(0, idx - 40), idx + 15);
      if (new RegExp(keyword, 'i').test(window)) return amt;
    }
  }
  return 0; // the claimed amount doesn't appear anywhere in the real text with the keyword nearby, in any occurrence
}

// A fixed, shared vocabulary of field meanings that repeat across hiring
// documents -- letting a value entered once (or known up front, like the
// candidate's name) carry across every document that needs it, instead of
// a new hire retyping their name and SSN on all eleven forms. null means
// the field is genuinely specific to that one document.
const HIRING_CANONICAL_FIELD_KEYS = [
  'employee_full_name', 'employee_first_name', 'employee_last_name',
  'employee_address', 'employee_city', 'employee_state', 'employee_zip',
  'employee_phone', 'employee_email', 'employee_dob',
  'ssn', 'bank_name', 'account_number', 'routing_number', 'account_type',
  'today_date', 'start_date', 'starting_pay', 'position_title', 'work_location'
];
const HIRING_SENSITIVE_FIELD_TYPES = new Set(['ssn', 'account_number', 'routing_number']);

const EXTRACT_HIRING_DOCUMENT_FIELDS_TOOL = {
  name: 'extract_hiring_document_fields',
  description: 'Identify every blank a new hire must personally fill in on this onboarding document (not fields an employer/HR person fills in, like Form I-9 Section 2), plus whether the new hire needs to sign it.',
  input_schema: {
    type: 'object',
    properties: {
      requiresSignature: { type: 'boolean', description: 'True if this document has a line for the new hire (not the employer) to sign and/or date as their own acknowledgment/signature.' },
      fields: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            label: { type: 'string', description: 'A short, human-readable label for this blank, as a new hire would understand it, e.g. "Routing Number", "Apartment/Unit Number". Do not include the word "blank" or field numbering from the form.' },
            type: { type: 'string', enum: ['text', 'ssn', 'routing_number', 'account_number', 'date', 'phone', 'email', 'address', 'checkbox', 'number', 'select'], description: 'The kind of input this is. Use ssn/routing_number/account_number specifically for those exact values (not just anything numeric) so they can be masked correctly. Use select whenever the form asks the new hire to pick exactly ONE option from a set of choices (a checkbox group, a lettered/numbered list of statuses, or an explicit "choose one" instruction) -- e.g. citizenship/immigration status, tax filing status, a marital-status letter code. Use checkbox only for a single, independent yes/no box (e.g. "check here if..."), never for one option within a group of mutually-exclusive choices -- that whole group is one select field, not several checkboxes.' },
            options: { type: 'array', items: { type: 'string' }, description: 'Required when type is select, omitted otherwise. Every choice exactly as printed on the form, in the same order, e.g. ["A citizen of the United States", "A noncitizen national of the United States", "A lawful permanent resident", "A noncitizen authorized to work"]. Keep each option\u2019s own wording intact rather than summarizing it, since a new hire needs to recognize which one matches their situation.' },
            canonicalKey: { type: ['string', 'null'], enum: [...HIRING_CANONICAL_FIELD_KEYS, null], description: 'If this blank means the same thing as one of the canonical keys (the new hire\u2019s own name, address, SSN, bank info, etc.), the matching key -- so a value entered once can fill the same blank on other documents. null if this blank is specific to this one document only (e.g. a document-specific checkbox or a value only this form asks for). A select field is almost always document-specific (null) -- different forms rarely share the exact same set of options.' },
            required: { type: 'boolean', description: 'True unless the form itself marks this as optional/conditional (e.g. "if any").' }
          },
          required: ['label', 'type', 'required']
        },
        description: 'Every blank the new hire (not the employer) must fill in. Do not include employer-only sections (e.g. Form I-9 Section 2, "Employer Review and Verification"), the document title, or purely informational text. Do not include a field for the new hire\u2019s signature itself -- that is covered by requiresSignature, not a field.'
      }
    },
    required: ['requiresSignature', 'fields']
  }
};

const EXTRACT_CLIENT_INVOICE_TOOL = {
  name: 'extract_client_invoice',
  description: 'Extract the balance due, total sale, tax, and billed line items from a HunkWare completed job invoice or receipt page specifically -- never from a work order, contract, or estimate page, even if one is included alongside it.',
  input_schema: {
    type: 'object',
    properties: {
      invoicePageFound: { type: 'boolean', description: 'True only if at least one of the provided pages is clearly a HunkWare invoice or receipt (has a Balance Due, Subtotal, or Tax line explicitly printed and labeled as such). False if the provided pages are only a work order, contract, estimate, or signature page with no actual invoice/receipt page present. All the dollar fields below must be 0 and confident must be false when this is false.' },
      // Travel fields deliberately sit up front, ahead of the line-item
      // rules: as the last field the model sometimes skipped it entirely,
      // and the line-item rules' "never include fees" wording was bleeding
      // into this separate question.
      hasTravelLineItem: { type: 'boolean', description: 'True if ANY billed line anywhere on the invoice has a description containing the word "travel" (case-insensitive) -- e.g. "Travel Fee", "Truck and Travel Fee", "Travel Time". This is a separate question from lineItems below: fee and labor lines that are excluded from lineItems still count here. False only if no such line exists, or if invoicePageFound is false.' },
      travelLineAsPrinted: { type: 'string', description: 'The complete text of the travel line found above, exactly as printed, e.g. "Truck and Travel Fee    $149.00". Literal transcription only. Empty string if hasTravelLineItem is false.' },
      balanceDue: { type: 'number', description: 'The Balance Due amount, in dollars, but ONLY if read directly from a line explicitly labeled "Balance Due" on a genuine invoice/receipt page. Never estimate, calculate, or infer this. Report 0 if invoicePageFound is false, or if the invoice shows the balance is fully paid.' },
      totalSale: { type: 'number', description: 'The Total Sale / Subtotal amount, in dollars, but ONLY if read directly from a line explicitly labeled "Total Sale", "Subtotal", or "Product Total" on a genuine invoice/receipt page. Never estimate, calculate, or infer this -- and never pull this from a work order\u2019s estimated total or an unrelated dollar figure elsewhere on the page. Report 0 if invoicePageFound is false, or if totalSaleLineAsPrinted is empty.' },
      totalSaleLineAsPrinted: { type: 'string', description: 'The complete text of the line showing the Total Sale/Subtotal/Product Total, exactly as printed, e.g. "Subtotal    $412.00" or "Product Total    $753.25". This must be a literal transcription of text visible on the page -- copy it, do not summarize or compute it. Leave as an empty string if no such line exists; in that case totalSale must be 0.' },
      tax: { type: 'number', description: 'The Tax amount, in dollars, but ONLY if read directly from a line explicitly labeled "Tax" or "Sales Tax" on a genuine invoice/receipt page. Never estimate, calculate, or infer this from any other number on the page or on a different page. Report 0 if invoicePageFound is false, if the invoice explicitly shows no tax was charged, or if taxLineAsPrinted is empty.' },
      taxLineAsPrinted: { type: 'string', description: 'The complete text of the line showing the Tax amount, exactly as printed, e.g. "Tax    $0.00" or "Sales Tax  $12.00". This must be a literal transcription of text visible on the page -- copy it, do not summarize or compute it. Leave as an empty string if no line explicitly labeled Tax/Sales Tax exists anywhere on the page; in that case tax must be 0.' },
      lineItems: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            description: { type: 'string', description: 'The line item description exactly as printed, e.g. "Small Box", "Shrink Wrap".' },
            quantity: { type: 'number', description: 'The quantity billed for this line.' },
            lineTotal: { type: 'number', description: 'The dollar amount billed to the client for this specific line (quantity x rate, or however it is totaled on the invoice), read directly from that line. Never estimate, calculate, or infer this from a unit rate -- read the printed line total itself. Report 0 if lineTotalAsPrinted is empty.' },
            lineTotalAsPrinted: { type: 'string', description: 'The complete text of this specific line exactly as printed, including its dollar amount, e.g. "TV Crate    $50.00    3    $150.00". This must be a literal transcription of text visible on the page. Leave as an empty string if the line has no legible dollar amount; in that case lineTotal must be 0.' }
          },
          required: ['description', 'quantity']
        },
        description: 'Every billed line item that looks like a packing/moving material or physical good (boxes, tape, wrap, crates, etc.) -- not labor, mileage, or other service fees. Include unusual or one-off items too (e.g. "TV Crate", "Wardrobe Box") even if they look uncommon -- do not skip a line just because it seems unfamiliar. Empty array if invoicePageFound is false.'
      },
      confident: { type: 'boolean', description: 'True only if invoicePageFound is true AND the Balance Due, Total Sale, and Tax lines were all read clearly and unambiguously from that genuine invoice/receipt page. False otherwise, including whenever invoicePageFound is false.' }
    },
    required: ['invoicePageFound', 'hasTravelLineItem', 'travelLineAsPrinted', 'balanceDue', 'lineItems', 'confident']
  }
};

app.post('/api/admin/extract-client-invoice', requireAuth, async (req, res) => {
  const { images, pageTexts, jobNumber, materialsNicknames } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 80) {
    return res.status(400).json({ error: 'Please split this into invoices of 80 pages or fewer.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Invoice extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Extraction is not configured on the server yet.' });
  }

  try {
    const reqId = Math.random().toString(36).slice(2, 8);
    const imageBlocks = images.map(dataUri => {
      const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(dataUri || '');
      if (!match) return null;
      return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
    }).filter(Boolean);
    if (imageBlocks.length === 0) {
      return res.status(400).json({ error: 'No valid images were provided.' });
    }

    // A real text layer (from a machine-generated PDF, as opposed to a
    // scanned image with nothing embedded) lets the AI read exact
    // characters instead of visually guessing at them, and lets the server
    // independently verify any claimed figure against ground-truth text it
    // extracted itself. Falls back to image/vision mode when there's no
    // usable text (e.g. a photographed paper document).
    const texts = Array.isArray(pageTexts) ? pageTexts.map(t => (typeof t === 'string' ? t : '')) : [];
    const combinedTextLength = texts.reduce((sum, t) => sum + t.length, 0);
    const hasUsableText = texts.length === imageBlocks.length && combinedTextLength > 50;
    console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] start: pages=${imageBlocks.length} pageTextsProvided=${texts.length} combinedTextLength=${combinedTextLength} mode=${hasUsableText ? 'TEXT' : 'VISION'}`);
    if (hasUsableText) {
      texts.forEach((t, i) => console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] page ${i} text (${t.length} chars): ${t.slice(0, 500).replace(/\n/g, ' | ')}`));
    }

    function pageContentBlocks(indices) {
      if (hasUsableText) {
        return [{ type: 'text', text: indices.map(i => `--- PAGE ${i} ---\n${texts[i]}`).join('\n\n') }];
      }
      return indices.map(i => imageBlocks[i]);
    }

    async function callClaude(tools, toolName, content) {
      const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 2048,
          tools,
          tool_choice: { type: 'tool', name: toolName },
          messages: [{ role: 'user', content }]
        })
      });
      if (!anthropicRes.ok) {
        const errBody = await anthropicRes.text().catch(() => '');
        console.error('Client invoice extraction call failed:', anthropicRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        const err = new Error(`Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}`);
        err.status = 502;
        throw err;
      }
      const data = await anthropicRes.json();
      const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === toolName);
      if (!toolUseBlock) {
        console.error(`Client invoice extraction: no ${toolName} tool_use block. stop_reason=`, data.stop_reason);
        const err = new Error('Could not read a structured response from the extraction service.');
        err.status = 502;
        throw err;
      }
      return toolUseBlock.input || {};
    }

    const allIndices = imageBlocks.map((_, i) => i);

    // Step 1: classify which pages (if any) are a genuine invoice, and pull
    // job type / origin address from any work order page found -- BEFORE
    // any dollar figure is extracted.
    const classification = await callClaude([IDENTIFY_INVOICE_PAGES_TOOL], 'identify_invoice_pages', [
      ...pageContentBlocks(allIndices),
      { type: 'text', text: `These are ${imageBlocks.length} page(s) from a moving/junk removal job's paperwork -- this may be ONLY the invoice, or it may be the invoice merged together with the job's work order, contract, and signature pages.${hasUsableText ? ' Each page\u2019s text is labeled "--- PAGE n ---" above, using the same 0-indexed page numbers you should report.' : ''} Identify exactly which page(s), if any, are a genuine HunkWare invoice or receipt (has Balance Due / Subtotal / Tax lines explicitly printed and labeled on that specific page). A work order, contract, or estimate page is NOT an invoice, even if it shows a dollar total -- do not include those page numbers.${jobNumber ? ` The specific job you are looking for is Job ${jobNumber} -- if the document contains paperwork for more than one job (a merged multi-job packet), only report the job type and Origin Address that are printed alongside Job ${jobNumber} specifically, not any other job number that happens to appear.` : ''} Separately, if a work order page is present, report the job type and Origin Address ("FROM") shown on it.` }
    ]);
    console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step1 classification: ${JSON.stringify(classification)}`);
    const invoicePageIndices = (Array.isArray(classification.invoicePageIndices) ? classification.invoicePageIndices : [])
      .filter(i => Number.isInteger(i) && i >= 0 && i < imageBlocks.length);

    const baseResult = {
      jobType: classification.jobType,
      originAddress: classification.originAddress
    };

    if (invoicePageIndices.length === 0) {
      // No genuine invoice page found -- nothing to extract, and no second
      // call needed. jobType/originAddress from step 1 still carry through,
      // since those can come from a work order page even with no invoice.
      console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] no invoice page found -- returning early with all-zero financials`);
      return res.json({ ...baseResult, invoicePageFound: false, balanceDue: 0, totalSale: 0, tax: 0, lineItems: [], confident: false, hasTravelLineItem: false });
    }

    // Step 2: extract financial figures using ONLY the pages step 1
    // classified as a genuine invoice -- the model literally cannot see
    // (let alone pull a number from) any work order/estimate page here,
    // rather than just being told to ignore pages it can still see.
    const validNicknames = Array.isArray(materialsNicknames)
      ? materialsNicknames.map(n => (typeof n === 'string' ? n.trim() : '')).filter(Boolean)
      : [];
    const lineItemInstruction = validNicknames.length > 0
      ? `For line items, ONLY look for and report items whose description matches one of these exact names from the materials catalog: ${validNicknames.map(n => `"${n}"`).join(', ')}. Do not report ANY other billed item, even if it looks like a physical good -- labor, hourly rates, truckload/shipping charges, fees, discounts, tips, and anything else not on this list must never appear in lineItems, regardless of how it's labeled on the invoice.`
      : `Find every billed line item that represents a physical good sold -- not labor, mileage, or other service fees.`;
    const extraction = await callClaude([EXTRACT_CLIENT_INVOICE_TOOL], 'extract_client_invoice', [
      ...pageContentBlocks(invoicePageIndices),
      { type: 'text', text: `${hasUsableText ? 'This is the exact text from' : 'These are'} the page(s) already confirmed to be a genuine HunkWare invoice/receipt for this job. FIRST, before anything else: check every billed line on the invoice -- fees, labor, and service charges included -- for one whose description contains the word "travel" (e.g. "Travel Fee", "Truck and Travel Fee"). Report that in hasTravelLineItem and copy that line word for word into travelLineAsPrinted. The line-item rules that follow do NOT apply to this travel check. THEN: find the Balance Due amount, the Total Sale/Subtotal/Product Total amount, and the Tax amount. ${lineItemInstruction} For each reported line item, include the exact dollar amount billed for it, since that is what was actually charged to the client and is what matters for sales tax, not any catalog or cost price. Before reporting the Total Sale, Tax, and each line item's dollar amount, transcribe the exact line each was read from, word for word, in totalSaleLineAsPrinted, taxLineAsPrinted, and lineTotalAsPrinted -- if you can't point to a specific printed line for one of them, report that figure as 0 and leave its "as printed" field blank rather than guessing.` }
    ]);
    console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step2 RAW extraction (before any validation): tax=${extraction.tax} taxLineAsPrinted=${JSON.stringify(extraction.taxLineAsPrinted)} totalSale=${extraction.totalSale} totalSaleLineAsPrinted=${JSON.stringify(extraction.totalSaleLineAsPrinted)} balanceDue=${extraction.balanceDue} lineItems=${JSON.stringify(extraction.lineItems)}`);

    // The invoice reading should only ever look for items that are
    // actually in the materials catalog -- everything else (labor,
    // shipping/truckload charges, fees, discounts, tips, and anything
    // else) is excluded from Total Sales, no matter how it's labeled on
    // the invoice. The prompt above already scopes the model's search to
    // this closed list, but this is the authoritative, guaranteed check:
    // hard-filter to only descriptions that exactly match a real
    // materials Nickname, rather than trusting the model's judgment about
    // what "looks like" a good.
    if (Array.isArray(extraction.lineItems)) {
      const before = extraction.lineItems.length;
      if (validNicknames.length > 0) {
        const nicknameSet = new Set(validNicknames.map(n => n.toLowerCase()));
        extraction.lineItems = extraction.lineItems.filter(li => nicknameSet.has((li.description || '').trim().toLowerCase()));
      } else {
        // No materials catalog was provided at all -- fall back to a
        // pattern-based exclusion of obvious non-goods lines as a
        // last-resort safety net, rather than trusting every line item.
        const NON_GOODS_PATTERN = /per\s*hour|\bhour(s)?\b|\bhunk(s)?\b|\blabor\b|\btravel\b|mileage|\bfee\b|\btruck(load)?\b/i;
        extraction.lineItems = extraction.lineItems.filter(li => !NON_GOODS_PATTERN.test(li.description || ''));
      }
      if (extraction.lineItems.length !== before) {
        console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step2b filtered out ${before - extraction.lineItems.length} line item(s) not in the materials catalog`);
      }
    }

    // Server-side validation, Layer 1: see the shared validateAgainstQuote
    // utility near the top of this file.
    const taxAfterLayer1 = validateAgainstQuote(extraction.tax, extraction.taxLineAsPrinted, 'tax');
    const totalSaleAfterLayer1 = validateAgainstQuote(extraction.totalSale, extraction.totalSaleLineAsPrinted, 'sub\\s*total|total\\s*sale|product\\s*total');
    console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step3 after layer 1 (quote self-consistency): tax ${extraction.tax} -> ${taxAfterLayer1}${extraction.tax !== taxAfterLayer1 ? ' REJECTED' : ''}, totalSale ${extraction.totalSale} -> ${totalSaleAfterLayer1}${extraction.totalSale !== totalSaleAfterLayer1 ? ' REJECTED' : ''}`);
    extraction.tax = taxAfterLayer1;
    extraction.totalSale = totalSaleAfterLayer1;

    // Same layer-1 grounding, applied per line item: a claimed lineTotal is
    // only trusted if its own quoted line actually mentions that specific
    // item (by description) AND contains a dollar figure matching what was
    // reported. This is what Total Sales is actually built from now, since
    // the Materials catalog price is the vendor cost, not what was billed.
    if (Array.isArray(extraction.lineItems)) {
      extraction.lineItems = extraction.lineItems.map(li => {
        const descKeyword = (li.description || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const lineTotalAfterLayer1 = descKeyword ? validateAgainstQuote(li.lineTotal, li.lineTotalAsPrinted, descKeyword) : 0;
        return { ...li, lineTotal: lineTotalAfterLayer1 };
      });
      console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step3b line items after layer 1: ${JSON.stringify(extraction.lineItems.map(li => ({ description: li.description, lineTotal: li.lineTotal })))}`);
    }

    // Layer 2 (only possible in text mode, and much stronger): search the
    // server's OWN independently-extracted text for the claimed dollar
    // amount appearing near the relevant keyword -- not just checking the
    // model's self-reported quote for internal consistency, but verifying
    // against ground truth the model never got to author. Catches a figure
    // that has zero basis anywhere on the real document at all, which a
    // self-consistency check alone cannot.
    if (hasUsableText) {
      const invoiceText = invoicePageIndices.map(i => texts[i]).join(' ').toLowerCase().replace(/\s+/g, ' ').replace(/,/g, '');
      // Server-side validation, Layer 2: see the shared verifyAgainstSourceText
      // utility near the top of this file.
      const taxAfterLayer2 = verifyAgainstSourceText(invoiceText, extraction.tax, 'tax');
      const totalSaleAfterLayer2 = verifyAgainstSourceText(invoiceText, extraction.totalSale, 'sub\\s*total|total\\s*sale|product\\s*total');
      console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step4 after layer 2 (ground-truth text search): tax ${extraction.tax} -> ${taxAfterLayer2}${extraction.tax !== taxAfterLayer2 ? ' REJECTED' : ''}, totalSale ${extraction.totalSale} -> ${totalSaleAfterLayer2}${extraction.totalSale !== totalSaleAfterLayer2 ? ' REJECTED' : ''}`);
      extraction.tax = taxAfterLayer2;
      extraction.totalSale = totalSaleAfterLayer2;

      if (Array.isArray(extraction.lineItems)) {
        extraction.lineItems = extraction.lineItems.map(li => {
          const descKeyword = (li.description || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const lineTotalAfterLayer2 = descKeyword ? verifyAgainstSourceText(invoiceText, li.lineTotal, descKeyword) : 0;
          return { ...li, lineTotal: lineTotalAfterLayer2 };
        });
        console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] step4b line items after layer 2: ${JSON.stringify(extraction.lineItems.map(li => ({ description: li.description, lineTotal: li.lineTotal })))}`);
      }
    }

    // The model occasionally omits the confident field from its tool_use
    // response entirely, even though the schema marks it required. That's
    // a model quirk, not a real signal of low confidence -- and the two
    // grounding layers above have already independently verified every
    // dollar figure against the actual printed text, zeroing out anything
    // that didn't check out. So a missing field defaults to true rather
    // than discarding an otherwise well-grounded extraction; an explicit
    // confident:false from the model is still respected as-is.
    if (extraction.confident === undefined) extraction.confident = true;
    // Travel line: decided from the document itself wherever possible,
    // not from the model's yes/no alone. In text mode the invoice pages'
    // own extracted text is ground truth -- if "travel" is printed on an
    // invoice page the line is there, whatever the model answered, and if
    // it isn't printed the model can't have seen it either. In vision mode
    // there is no ground-truth text, so the model's answer is accepted if
    // it said true OR transcribed a line that actually contains "travel".
    // An omitted answer still counts as not confirmed.
    const TRAVEL_WORD = /\btravel\b/i;
    const modelTravelAnswer = extraction.hasTravelLineItem;
    const quotedTravel = TRAVEL_WORD.test(extraction.travelLineAsPrinted || '');
    if (hasUsableText) {
      extraction.hasTravelLineItem = TRAVEL_WORD.test(invoicePageIndices.map(i => texts[i]).join(' '));
      extraction.travelCheckSource = 'text';
    } else {
      extraction.hasTravelLineItem = modelTravelAnswer === true || quotedTravel;
      extraction.travelCheckSource = 'vision';
    }
    console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] travel check (${extraction.travelCheckSource}): model=${modelTravelAnswer === undefined ? 'OMITTED' : modelTravelAnswer} quoted=${JSON.stringify(extraction.travelLineAsPrinted || '')} -> ${extraction.hasTravelLineItem}`);

    console.log(`[TAX-EXTRACT ${reqId} job=${jobNumber || "unknown"}] FINAL result: ${JSON.stringify({ ...baseResult, invoicePageFound: true, ...extraction })}`);
    res.json({ ...baseResult, invoicePageFound: true, ...extraction });
  } catch (err) {
    console.error('Client invoice extraction failed:', err.message);
    res.status(err.status || 500).json({ error: err.status ? err.message : ('Extraction failed: ' + err.message) });
  }
});

// ============ Hiring: Document Field Extraction ============
// Accepts either a PDF (sent to Claude natively as a document block, which
// reads both a real text layer and a scanned/flat PDF) or plain text
// (for docx files, which aren't a Claude-native document type -- the
// frontend extracts their text client-side via mammoth.js first).
app.post('/api/admin/hiring/extract-fields', requireAuth, async (req, res) => {
  const { pdfBase64, text, fileName } = req.body || {};
  if (!pdfBase64 && !text) {
    return res.status(400).json({ error: 'Provide either pdfBase64 or text.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Hiring field extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Extraction is not configured on the server yet.' });
  }
  try {
    const content = pdfBase64
      ? [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 } }]
      : [{ type: 'text', text }];
    content.push({ type: 'text', text: `This is an onboarding document${fileName ? ` named "${fileName}"` : ''} a new hire at a moving/junk removal company must fill in and, if applicable, sign. Identify every blank the new hire themself must fill in, and whether they need to sign it.` });

    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 4096,
        tools: [EXTRACT_HIRING_DOCUMENT_FIELDS_TOOL],
        tool_choice: { type: 'tool', name: 'extract_hiring_document_fields' },
        messages: [{ role: 'user', content }]
      })
    });
    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Hiring field extraction call failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }
    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_hiring_document_fields');
    if (!toolUseBlock) {
      console.error('Hiring field extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    const result = toolUseBlock.input || {};
    // Belt-and-suspenders: never trust the model's type/canonicalKey pairing
    // blindly for the sensitive types -- if it labels something ssn/
    // account_number/routing_number but hands it a non-matching or missing
    // canonical key, correct the canonical key so downstream masking still
    // applies correctly regardless of the model's own consistency.
    const TYPE_TO_CANONICAL = { ssn: 'ssn', account_number: 'account_number', routing_number: 'routing_number' };
    const fields = (Array.isArray(result.fields) ? result.fields : []).map((f, i) => {
      const fixedCanonical = TYPE_TO_CANONICAL[f.type] || f.canonicalKey || null;
      const cleanOptions = Array.isArray(f.options)
        ? f.options.map(o => String(o || '').slice(0, 300)).filter(Boolean).slice(0, 20)
        : [];
      // A select field with no usable options is broken, not a dropdown
      // worth showing -- falls back to a plain text field instead.
      const isValidSelect = f.type === 'select' && cleanOptions.length > 0;
      const type = HIRING_SENSITIVE_FIELD_TYPES.has(f.type) || ['text','date','phone','email','address','checkbox','number'].includes(f.type)
        ? f.type
        : (isValidSelect ? 'select' : 'text');
      return {
        id: 'fld_' + i + '_' + Math.random().toString(36).slice(2, 8),
        label: String(f.label || '').slice(0, 200),
        type,
        ...(type === 'select' ? { options: cleanOptions } : {}),
        canonicalKey: HIRING_CANONICAL_FIELD_KEYS.includes(fixedCanonical) ? fixedCanonical : null,
        required: f.required !== false
      };
    });
    res.json({ requiresSignature: !!result.requiresSignature, fields });
  } catch (err) {
    console.error('Hiring field extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Hiring: Candidates & Public Onboarding Flow ============
const HIRING_LINK_VALID_DAYS = 14; // longer than Damage Claims' 7 -- gathering bank/ID info can take a new hire longer
const HIRING_CANDIDATES_KEY = 'hiring-candidates';
const HIRING_DOCUMENTS_KEY = 'hiring-documents';

function isHiringLinkExpired(candidate) {
  if (!candidate.tokenCreatedAt) return false;
  const ageMs = Date.now() - new Date(candidate.tokenCreatedAt).getTime();
  return ageMs > HIRING_LINK_VALID_DAYS * 24 * 60 * 60 * 1000;
}

// Last 4 only, consistent regardless of the original value's length -- a
// masked view is what every admin sees by default; only the explicit,
// logged reveal endpoint below ever returns the real value.
function maskHiringValue(value) {
  const s = String(value || '');
  if (s.length <= 4) return '\u2022'.repeat(s.length);
  return '\u2022'.repeat(s.length - 4) + s.slice(-4);
}
const HIRING_SENSITIVE_TYPES = new Set(['ssn', 'account_number', 'routing_number']);

async function getHiringDocumentsList() {
  const raw = await redis.get(HIRING_DOCUMENTS_KEY);
  return raw ? JSON.parse(raw) : [];
}

function maskCandidateForAdmin(candidate, documents) {
  // Builds a type lookup across every document's extracted fields (shared
  // canonical fields carry one type; document-specific fields are looked
  // up per document) so masking is correct regardless of which field or
  // document a value came from.
  const typeByCanonicalKey = {};
  const typeByDocField = {}; // `${documentId}:${fieldId}` -> type
  (documents || []).forEach(doc => {
    (doc.fields || []).forEach(f => {
      if (f.canonicalKey) typeByCanonicalKey[f.canonicalKey] = f.type;
      typeByDocField[`${doc.id}:${f.id}`] = f.type;
    });
  });

  const maskedShared = {};
  Object.keys(candidate.sharedFieldValues || {}).forEach(key => {
    const value = candidate.sharedFieldValues[key];
    maskedShared[key] = HIRING_SENSITIVE_TYPES.has(typeByCanonicalKey[key]) ? maskHiringValue(value) : value;
  });

  const maskedDocProgress = {};
  Object.keys(candidate.documentProgress || {}).forEach(docId => {
    const prog = candidate.documentProgress[docId] || {};
    const maskedFields = {};
    Object.keys(prog.fieldValues || {}).forEach(fieldId => {
      const value = prog.fieldValues[fieldId];
      const type = typeByDocField[`${docId}:${fieldId}`];
      maskedFields[fieldId] = HIRING_SENSITIVE_TYPES.has(type) ? maskHiringValue(value) : value;
    });
    maskedDocProgress[docId] = { ...prog, fieldValues: maskedFields };
  });

  return { ...candidate, sharedFieldValues: maskedShared, documentProgress: maskedDocProgress };
}

app.get('/api/admin/hiring/candidates', requireAuth, async (req, res) => {
  try {
    const [candidatesRaw, documents] = await Promise.all([redis.get(HIRING_CANDIDATES_KEY), getHiringDocumentsList()]);
    const candidates = candidatesRaw ? JSON.parse(candidatesRaw) : [];
    res.json({ candidates: candidates.map(c => maskCandidateForAdmin(c, documents)) });
  } catch (err) {
    console.error('GET /api/admin/hiring/candidates failed:', err.message);
    res.status(500).json({ error: 'Could not load candidates.' });
  }
});

app.post('/api/admin/hiring/candidates', requireAuth, async (req, res) => {
  const { firstName, lastName, email, startingPay, startingDate, positionTitle } = req.body || {};
  if (!firstName || !lastName || !email || !startingDate) {
    return res.status(400).json({ error: 'First name, last name, email, and start date are required.' });
  }
  try {
    const raw = await redis.get(HIRING_CANDIDATES_KEY);
    const candidates = raw ? JSON.parse(raw) : [];
    const now = new Date().toISOString();
    const candidate = {
      id: 'cand_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      firstName: String(firstName).trim().slice(0, 100),
      lastName: String(lastName).trim().slice(0, 100),
      email: String(email).trim().slice(0, 200),
      startingPay: startingPay || '',
      startingDate: String(startingDate).slice(0, 10),
      positionTitle: (positionTitle || 'General Laborer').slice(0, 100),
      createdAt: now,
      createdBy: req.userEmail || '',
      token: crypto.randomBytes(32).toString('hex'),
      tokenCreatedAt: now,
      status: 'draft',
      sharedFieldValues: {},
      documentProgress: {},
      sentAt: null,
      completedAt: null
    };
    candidates.push(candidate);
    await redis.set(HIRING_CANDIDATES_KEY, JSON.stringify(candidates));
    res.json({ candidate });
  } catch (err) {
    console.error('POST /api/admin/hiring/candidates failed:', err.message);
    res.status(500).json({ error: 'Could not create this candidate.' });
  }
});

// Marks a candidate as sent, and (re)issues a fresh link -- called right
// before the admin's mailto: link opens, same "generate link, admin's own
// email client sends it" pattern Damage Claims already uses. Re-sending
// later (link expired, or a typo in the email) issues a new token and
// resets the expiry window, without touching anything the candidate has
// already filled in.
app.post('/api/admin/hiring/candidates/:id/send', requireAuth, async (req, res) => {
  try {
    const raw = await redis.get(HIRING_CANDIDATES_KEY);
    const candidates = raw ? JSON.parse(raw) : [];
    const candidate = candidates.find(c => c.id === req.params.id);
    if (!candidate) return res.status(404).json({ error: 'Candidate not found.' });
    const now = new Date().toISOString();
    candidate.token = crypto.randomBytes(32).toString('hex');
    candidate.tokenCreatedAt = now;
    candidate.sentAt = now;
    if (candidate.status === 'draft') candidate.status = 'sent';
    await redis.set(HIRING_CANDIDATES_KEY, JSON.stringify(candidates));
    res.json({ token: candidate.token });
  } catch (err) {
    console.error('POST /api/admin/hiring/candidates/:id/send failed:', err.message);
    res.status(500).json({ error: 'Could not prepare this link.' });
  }
});

app.delete('/api/admin/hiring/candidates/:id', requireAuth, async (req, res) => {
  try {
    const raw = await redis.get(HIRING_CANDIDATES_KEY);
    const candidates = raw ? JSON.parse(raw) : [];
    const filtered = candidates.filter(c => c.id !== req.params.id);
    await redis.set(HIRING_CANDIDATES_KEY, JSON.stringify(filtered));
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/admin/hiring/candidates/:id failed:', err.message);
    res.status(500).json({ error: 'Could not remove this candidate.' });
  }
});

// Reveals one field's true value. Not re-gated by PIN server-side -- same
// established pattern as every other PIN-protected action in this app
// (the frontend verifies via /api/verify-override-pin first, then calls
// this). What this endpoint alone provides is the audit trail: every
// reveal is logged, regardless of where the request came from.
app.post('/api/admin/hiring/candidates/:id/reveal', requireAuth, async (req, res) => {
  const { scope, documentId, fieldKey } = req.body || {}; // scope: 'shared' | 'document'
  if (!fieldKey || (scope === 'document' && !documentId)) {
    return res.status(400).json({ error: 'fieldKey (and documentId, for a document-specific field) is required.' });
  }
  try {
    const raw = await redis.get(HIRING_CANDIDATES_KEY);
    const candidates = raw ? JSON.parse(raw) : [];
    const candidate = candidates.find(c => c.id === req.params.id);
    if (!candidate) return res.status(404).json({ error: 'Candidate not found.' });

    const value = scope === 'document'
      ? ((candidate.documentProgress[documentId] || {}).fieldValues || {})[fieldKey]
      : (candidate.sharedFieldValues || {})[fieldKey];

    const logRaw = await redis.get('hiring-reveal-log');
    const log = logRaw ? JSON.parse(logRaw) : [];
    log.push({
      candidateId: candidate.id, candidateName: `${candidate.firstName} ${candidate.lastName}`,
      scope, documentId: documentId || null, fieldKey,
      revealedBy: req.userEmail || '', revealedAt: new Date().toISOString()
    });
    await redis.set('hiring-reveal-log', JSON.stringify(log.slice(-1000))); // capped -- an audit trail, not an unbounded log

    res.json({ value: value || '' });
  } catch (err) {
    console.error('POST /api/admin/hiring/candidates/:id/reveal failed:', err.message);
    res.status(500).json({ error: 'Could not reveal this value.' });
  }
});

// ---- Public onboarding flow -- no login, reached only via the unique link ----

// The candidate's own token is the only authorization here -- same as
// every other endpoint in this flow -- but it's still scoped to a
// specific document that's actually part of THIS candidate's package,
// rather than trusting any fileKey the client might send.
app.get('/api/hiring/package/:token/document/:documentId/file', async (req, res) => {
  try {
    const [candidatesRaw, documents] = await Promise.all([redis.get(HIRING_CANDIDATES_KEY), getHiringDocumentsList()]);
    const candidates = candidatesRaw ? JSON.parse(candidatesRaw) : [];
    const candidate = candidates.find(c => c.token === req.params.token);
    if (!candidate) return res.status(404).json({ error: 'This link could not be found.' });
    if (isHiringLinkExpired(candidate)) return res.status(410).json({ error: 'This link has expired.', expired: true });

    const doc = documents.find(d => d.id === req.params.documentId);
    if (!doc || !doc.fileKey) return res.status(404).json({ error: 'This document could not be found.' });
    const fileRaw = await redis.get(doc.fileKey);
    if (!fileRaw) return res.status(404).json({ error: 'This document\u2019s file could not be found.' });
    res.json({ dataUri: JSON.parse(fileRaw) });
  } catch (err) {
    console.error('GET /api/hiring/package/:token/document/:documentId/file failed:', err.message);
    res.status(500).json({ error: 'Could not load this document.' });
  }
});

app.get('/api/hiring/package/:token', async (req, res) => {
  try {
    const [candidatesRaw, documents] = await Promise.all([redis.get(HIRING_CANDIDATES_KEY), getHiringDocumentsList()]);
    const candidates = candidatesRaw ? JSON.parse(candidatesRaw) : [];
    const candidate = candidates.find(c => c.token === req.params.token);
    if (!candidate) return res.json({ found: false });
    if (isHiringLinkExpired(candidate)) return res.json({ found: false, expired: true });

    // This is the candidate's own in-progress data, in their own active
    // session -- not masked, the same way a web form doesn't mask what you
    // just typed into it.
    res.json({
      found: true,
      firstName: candidate.firstName, lastName: candidate.lastName,
      startingDate: candidate.startingDate, startingPay: candidate.startingPay,
      positionTitle: candidate.positionTitle,
      status: candidate.status,
      sharedFieldValues: candidate.sharedFieldValues || {},
      documentProgress: candidate.documentProgress || {},
      documents: documents
        .slice().sort((a, b) => (a.order || 0) - (b.order || 0))
        .map(d => ({ id: d.id, name: d.name, fileName: d.fileName, fields: d.fields || [], requiresSignature: !!d.requiresSignature }))
    });
  } catch (err) {
    console.error('GET /api/hiring/package/:token failed:', err.message);
    res.status(500).json({ error: 'Could not load this link.' });
  }
});

async function loadCandidateByToken(token) {
  const raw = await redis.get(HIRING_CANDIDATES_KEY);
  const candidates = raw ? JSON.parse(raw) : [];
  const candidate = candidates.find(c => c.token === token);
  return { candidates, candidate };
}

// Saved progressively as the new hire moves through each document -- so
// leaving and coming back (this needs to work well on a phone, where
// getting interrupted mid-form is routine) never loses what they already
// entered. sharedFieldValues are merged in, not replaced, since different
// documents contribute different shared fields over time.
app.post('/api/hiring/package/:token/save', async (req, res) => {
  const { documentId, fieldValues, sharedFieldValues } = req.body || {};
  try {
    const { candidates, candidate } = await loadCandidateByToken(req.params.token);
    if (!candidate) return res.status(404).json({ error: 'This link could not be found.' });
    if (isHiringLinkExpired(candidate)) return res.status(410).json({ error: 'This link has expired. Please contact us for a new one.', expired: true });
    if (candidate.status === 'completed') return res.status(409).json({ error: 'This onboarding package has already been submitted.' });

    if (sharedFieldValues && typeof sharedFieldValues === 'object') {
      candidate.sharedFieldValues = { ...(candidate.sharedFieldValues || {}), ...sharedFieldValues };
    }
    if (documentId && fieldValues && typeof fieldValues === 'object') {
      candidate.documentProgress = candidate.documentProgress || {};
      const existing = candidate.documentProgress[documentId] || { fieldValues: {} };
      candidate.documentProgress[documentId] = { ...existing, fieldValues: { ...existing.fieldValues, ...fieldValues } };
    }
    if (candidate.status === 'sent') candidate.status = 'in_progress';
    await redis.set(HIRING_CANDIDATES_KEY, JSON.stringify(candidates));
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/hiring/package/:token/save failed:', err.message);
    res.status(500).json({ error: 'Could not save your progress \u2014 please check your connection and try again.' });
  }
});

app.post('/api/hiring/package/:token/signature', async (req, res) => {
  const { documentId, signatureDataUri } = req.body || {};
  if (!documentId || typeof signatureDataUri !== 'string' || !signatureDataUri.startsWith('data:image/')) {
    return res.status(400).json({ error: 'A signature image and document are required.' });
  }
  try {
    const { candidates, candidate } = await loadCandidateByToken(req.params.token);
    if (!candidate) return res.status(404).json({ error: 'This link could not be found.' });
    if (isHiringLinkExpired(candidate)) return res.status(410).json({ error: 'This link has expired. Please contact us for a new one.', expired: true });
    if (candidate.status === 'completed') return res.status(409).json({ error: 'This onboarding package has already been submitted.' });

    const signatureKey = `hiring-signature-${candidate.id}-${documentId}`;
    await redis.set(signatureKey, JSON.stringify(signatureDataUri));
    candidate.documentProgress = candidate.documentProgress || {};
    const existing = candidate.documentProgress[documentId] || { fieldValues: {} };
    candidate.documentProgress[documentId] = { ...existing, signatureKey, completedAt: new Date().toISOString() };
    if (candidate.status === 'sent') candidate.status = 'in_progress';
    await redis.set(HIRING_CANDIDATES_KEY, JSON.stringify(candidates));
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/hiring/package/:token/signature failed:', err.message);
    res.status(500).json({ error: 'Could not save your signature \u2014 please check your connection and try again.' });
  }
});

app.post('/api/hiring/package/:token/submit', async (req, res) => {
  try {
    const { candidates, candidate } = await loadCandidateByToken(req.params.token);
    if (!candidate) return res.status(404).json({ error: 'This link could not be found.' });
    if (isHiringLinkExpired(candidate)) return res.status(410).json({ error: 'This link has expired. Please contact us for a new one.', expired: true });
    if (candidate.status === 'completed') return res.json({ ok: true }); // already done -- idempotent, not an error

    const documents = await getHiringDocumentsList();
    const missing = [];
    documents.forEach(doc => {
      const prog = (candidate.documentProgress || {})[doc.id] || { fieldValues: {} };
      (doc.fields || []).forEach(f => {
        if (!f.required) return;
        const value = f.canonicalKey ? (candidate.sharedFieldValues || {})[f.canonicalKey] : (prog.fieldValues || {})[f.id];
        if (value === undefined || value === null || String(value).trim() === '') missing.push(`${doc.name}: ${f.label}`);
      });
      if (doc.requiresSignature && !prog.signatureKey) missing.push(`${doc.name}: signature`);
    });
    if (missing.length > 0) {
      return res.status(400).json({ error: 'A few things still need to be filled in before this can be submitted.', missing });
    }

    candidate.status = 'completed';
    candidate.completedAt = new Date().toISOString();
    await redis.set(HIRING_CANDIDATES_KEY, JSON.stringify(candidates));
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/hiring/package/:token/submit failed:', err.message);
    res.status(500).json({ error: 'Could not submit \u2014 please check your connection and try again.' });
  }
});

// ============ Monthly Financials: Extraction ============
// One uploaded file = one month's financial statement (a P&L/income
// statement export, typically from accounting software). Unlike the
// invoice extraction above, there's no multi-page paperwork bundle to
// search through -- the whole file IS the statement -- so this skips the
// page-classification step entirely and reads straight through.
const EXTRACT_MONTHLY_FINANCIALS_TOOL = {
  name: 'extract_monthly_financials',
  description: 'Extract monthly summary financial figures (Total Revenue, Total Hunk Team Payroll Cost, Gross Profit, Operating Profit, EBIT, Owner Wages, Net Income, and Total Equity from the Balance Sheet) from a financial statement or P&L/Balance Sheet report for a single month -- built to handle multi-page management reports (e.g. Fathom-style "Monthly Performance Report" PDFs) that repeat the same line item across several tables and several months\u2019 columns.',
  input_schema: {
    type: 'object',
    properties: {
      periodFound: { type: 'boolean', description: 'True if this document is a financial statement/P&L/income statement showing figures for a single, identifiable period. False if this document has no such financial statement content at all -- in that case every dollar field below must be 0 and confident must be false.' },
      month: { type: 'string', description: 'The single month this statement covers, in YYYY-MM format. On a multi-page management report, this is almost always stated once, clearly, on the cover page or in the document title (e.g. "Monthly Performance Report ... August 2026", or a header reading "For the Month Ended July 31, 2026") -- that cover-page/title date is the ONLY acceptable source for this field. CRITICAL: the rest of the document will mention many OTHER months too -- "Last Month" columns, a "YTD" column, and especially a long trailing table near the END of the document listing a full 12 months side by side (e.g. Sep 2025 through Aug 2026 all in one wide table). None of those are the reporting month, even though one of them will coincidentally match it. If you cannot find a clear cover-page or title date, do not guess based on a month seen elsewhere in the document -- leave this as an empty string instead, since a wrong guess here is worse than admitting the month couldn\u2019t be determined.' },
      periodAsPrinted: { type: 'string', description: 'The exact period/date text as printed on the document\u2019s cover page or title, verbatim, e.g. "July 2026" or "07/01/2026 through 07/31/2026" -- the same source the month field above was read from, never a date pulled from a trailing multi-month table. Empty string if no such header text is found.' },
      revenue: { type: 'number', description: 'Total revenue for the reporting month specifically, in dollars, read from a line labeled "Total Revenue" or a plain "Revenue" total row (not a subcategory like "Move Job Revenue" or "Junk Job Revenue"). A report with a "Financial Summary" and/or "P&L Financial Summary" section usually states this cleanly near the top -- use the reporting month\u2019s own column there, not a "Last Month"/prior-month column, not a "YTD" column, and not a repeated appearance of the same row further down in a longer table covering many months at once. Never estimate, calculate, or sum this yourself from individual income lines. Report 0 if revenueLineAsPrinted is empty.' },
      revenueLineAsPrinted: { type: 'string', description: 'The complete text of the line the revenue figure was read from, exactly as printed, including enough surrounding text (e.g. a nearby column header) to show which month\u2019s figure this is. Literal transcription only, not a summary. Empty string if no such line exists; in that case revenue must be 0.' },
      labor: { type: 'number', description: 'Total labor/payroll cost for the reporting month, read from the line labeled "Total Hunk Team Payroll Cost" or "Total Hunk Team Payroll Costs" -- this is a SUBTOTAL, usually appearing inside a "Cost of Goods Sold" section after several individual sub-lines (things like Regular Wages, Overtime Wages, Bonuses & Commissions, Payroll Taxes, Payroll Processing) -- use that subtotal, never one individual sub-line and never sum them yourself. Do not confuse this with a differently-named payroll line elsewhere in the report, such as "Total Office Staff Payroll Expenses" (office/management staff, not the Hunk Team) -- that is a different line entirely. If the exact label "Total Hunk Team Payroll Cost(s)" truly isn\u2019t present anywhere, fall back to "Total Labor" or "Payroll Expenses" instead. Report 0 if laborLineAsPrinted is empty.' },
      laborLineAsPrinted: { type: 'string', description: 'The complete text of the line the labor/payroll figure was read from, exactly as printed (the label may be visually truncated with an ellipsis, e.g. "Total Hunk Team Payroll Co\u2026" -- that is still the right line, transcribe it as printed). Empty string if no such line exists; in that case labor must be 0.' },
      grossProfit: { type: 'number', description: 'Gross profit for the reporting month, read ONLY from a line explicitly labeled "Gross Profit" (or "Gross Margin") -- use the reporting month\u2019s own column, not a prior-month or YTD column even on the same row. Never calculate this yourself as Revenue minus Labor or minus COGS -- report 0 if no such explicitly labeled line is present, even if it seems computable from other figures on the page.' },
      grossProfitLineAsPrinted: { type: 'string', description: 'The complete text of the line the gross profit figure was read from, exactly as printed. Empty string if no such line exists; in that case grossProfit must be 0.' },
      operatingProfit: { type: 'number', description: 'Operating profit for the reporting month, read ONLY from a line explicitly labeled "Operating Profit" -- this is a distinct summary line, usually appearing below "Expenses" and above any "Other Income"/"Other Expenses" section, in the same "Financial Summary" or "P&L Financial Summary" table as Revenue and Gross Profit. Never confuse this with Gross Profit, EBIT, or Net Income -- they are different figures even though all four can appear close together in the same table. Never calculate this yourself as Gross Profit minus Expenses -- report 0 if no such explicitly labeled line is present. Use the reporting month\u2019s own column, not a prior-month or YTD column.' },
      operatingProfitLineAsPrinted: { type: 'string', description: 'The complete text of the line the operating profit figure was read from, exactly as printed. Empty string if no such line exists; in that case operatingProfit must be 0.' },
      ebit: { type: 'number', description: 'EBIT (Earnings Before Interest and Taxes) for the reporting month, read from a line labeled exactly "EBIT" if one is present anywhere on the page (a "P&L Financial Summary"-style section often states it this way, cleanly, as its own row). If no line says "EBIT" but one says "Earnings Before Interest & Tax" (the same metric spelled out, sometimes appearing in a more detailed section further down the report), that is an acceptable substitute and the same figure -- use it. This is NOT the same figure as EBITDA (which also adds back depreciation and amortization) -- if the only labeled line on the page says "EBITDA" rather than one of the two labels above, that is a different metric and must NOT be reported here; report 0 instead. Use the reporting month\u2019s own column, not a prior-month or YTD column. Never calculate, estimate, or derive this yourself from other figures on the page.' },
      ebitLineAsPrinted: { type: 'string', description: 'The complete text of the line the EBIT figure was read from, exactly as printed -- whichever of "EBIT" or "Earnings Before Interest & Tax" was actually used. Empty string if no such line exists (including if the only such line says EBITDA instead); in that case ebit must be 0.' },
      ownerWages: { type: 'number', description: 'Owner compensation for the reporting month, read from a line labeled something like "Owner Wages", "Owner\u2019s Draw", "Officer Compensation", or "Owner Salary". On a longer management report this often sits inside an "Other Expenses" section well below the main summary, separate from and not to be confused with any office/operations staff payroll line (a manager\u2019s wages are a different person from the owner). Use the reporting month\u2019s own column. Report 0 if ownerWagesLineAsPrinted is empty.' },
      ownerWagesLineAsPrinted: { type: 'string', description: 'The complete text of the line the owner wages figure was read from, exactly as printed. Empty string if no such line exists; in that case ownerWages must be 0.' },
      netIncome: { type: 'number', description: 'Net income for the reporting month specifically -- typically the final bottom-line figure on a P&L, labeled "Net Income", "Net Profit", or "Net Ordinary Income". This exact label often repeats more than once in a longer report (once in a monthly summary table, again in a year-to-date column on the very same row, and again inside a many-months trailing table near the end that sums a full year) -- these can be very different numbers under the identical label. Use ONLY the figure in the reporting month\u2019s own column of the main monthly summary table, never a YTD total and never a figure from a multi-month trailing table. Report 0 if netIncomeLineAsPrinted is empty.' },
      netIncomeLineAsPrinted: { type: 'string', description: 'The complete text of the line the net income figure was read from, exactly as printed, including enough surrounding text (e.g. a nearby column header) to show this is the reporting month\u2019s own figure and not a YTD or trailing-table total. Empty string if no such line exists; in that case netIncome must be 0.' },
      totalEquity: { type: 'number', description: 'Total equity as of the end of the reporting month, in dollars, read from a "Balance Sheet" or "Balance Sheet Detailed" section -- a completely different statement from the Income Statement/P&L that the other fields above come from, usually appearing later in the document. Read ONLY from a line explicitly labeled "Total Equity" (it typically appears as the last line of an "EQUITY" section, just above a "Total Liabilities & Equity" line that should equal Total Assets). Do NOT confuse this with "Total Other Equity", a smaller sub-total that often appears just one or two lines above it in the same section -- that is a different, smaller figure, not the one wanted here. Unlike the P&L fields above, this is a point-in-time balance, not a monthly flow -- use the reporting month\u2019s own column (usually the first/leftmost dollar column in that table). Never calculate this yourself as Total Assets minus Total Liabilities -- report 0 if no explicitly labeled "Total Equity" line is present.' },
      totalEquityLineAsPrinted: { type: 'string', description: 'The complete text of the line the total equity figure was read from, exactly as printed. Empty string if no such line exists; in that case totalEquity must be 0.' },
      confident: { type: 'boolean', description: 'True only if periodFound is true, the month/period was clearly identifiable, AND at least Revenue and Net Income were both read clearly from explicitly labeled lines for the correct reporting month specifically (not a YTD or other-month figure mistaken for it). False otherwise, including whenever periodFound is false or the month couldn\u2019t be determined.' }
    },
    required: ['periodFound', 'month', 'revenue', 'labor', 'grossProfit', 'operatingProfit', 'ebit', 'ownerWages', 'netIncome', 'totalEquity', 'confident']
  }
};

app.post('/api/admin/extract-monthly-financials', requireAuth, async (req, res) => {
  const { images, pageTexts } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 80) {
    return res.status(400).json({ error: 'Please split this into files of 80 pages or fewer.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Monthly financials extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Extraction is not configured on the server yet.' });
  }

  try {
    const reqId = Math.random().toString(36).slice(2, 8);
    const imageBlocks = images.map(dataUri => {
      const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(dataUri || '');
      if (!match) return null;
      return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
    }).filter(Boolean);
    if (imageBlocks.length === 0) {
      return res.status(400).json({ error: 'No valid images were provided.' });
    }

    const texts = Array.isArray(pageTexts) ? pageTexts.map(t => (typeof t === 'string' ? t : '')) : [];
    const combinedTextLength = texts.reduce((sum, t) => sum + t.length, 0);
    const hasUsableText = texts.length === imageBlocks.length && combinedTextLength > 50;
    console.log(`[MONTHLY-FIN-EXTRACT ${reqId}] start: pages=${imageBlocks.length} pageTextsProvided=${texts.length} combinedTextLength=${combinedTextLength} mode=${hasUsableText ? 'TEXT' : 'VISION'}`);
    if (hasUsableText) {
      texts.forEach((t, i) => console.log(`[MONTHLY-FIN-EXTRACT ${reqId}] page ${i} text (${t.length} chars): ${t.slice(0, 500).replace(/\n/g, ' | ')}`));
    }

    const content = hasUsableText
      ? [{ type: 'text', text: texts.map((t, i) => `--- PAGE ${i} ---\n${t}`).join('\n\n') }]
      : imageBlocks;

    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2048,
        tools: [EXTRACT_MONTHLY_FINANCIALS_TOOL],
        tool_choice: { type: 'tool', name: 'extract_monthly_financials' },
        messages: [{
          role: 'user',
          content: [
            ...content,
            { type: 'text', text: `${hasUsableText ? 'This is the exact text from' : 'These are'} a financial statement -- possibly a short single-page P&L, or possibly a longer multi-page management report (e.g. a Fathom-style "Monthly Performance Report") -- for a single month, uploaded for a business's monthly financial tracking. First find the reporting month itself -- it is stated clearly, once, on the cover page or in the document title (e.g. "Monthly Performance Report ... August 2026"). Do not pick a month from anywhere else in the document, including a long trailing table further down that lists many months side by side (e.g. the last 12 months) -- if the cover page/title date genuinely can't be found, leave the month blank rather than guessing from one of those other months. Then find Total Revenue, Total Hunk Team Payroll Cost, Gross Profit, Operating Profit, EBIT, Owner Wages, and Net Income -- each ONLY from a line explicitly labeled as such (see each field's own description for the exact labels to look for, including fallback labels and where that line tends to sit in a longer report). If the document also includes a Balance Sheet (a separate statement from the P&L/Income Statement, usually appearing later in the document), also find Total Equity there. IMPORTANT: a longer report typically shows the SAME row label more than once -- once in a compact summary table near the top (this is usually what you want), and again repeated inside a much longer table further down that covers many months side by side (this is usually NOT what you want, since it will contain the reporting month buried among many others, and its own column headers must be checked carefully). When a row appears in more than one place, prefer the earlier, simpler summary table over a later one covering many months at once, and always double-check which month's column you're actually reading from -- never a "Last Month", "YTD", "Budget", or any other month's column, even when it sits right next to the correct one on the same row. Before reporting each dollar figure, transcribe the exact line it was read from, word for word, in its matching "...LineAsPrinted" field -- if you can't point to a specific printed line for one of them, report that figure as 0 and leave its "as printed" field blank rather than guessing or calculating it from other numbers on the page.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error(`Monthly financials extraction ${reqId} failed:`, anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_monthly_financials');
    if (!toolUseBlock) {
      console.error(`Monthly financials extraction ${reqId}: no tool_use block. stop_reason=`, data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    const extraction = toolUseBlock.input;
    console.log(`[MONTHLY-FIN-EXTRACT ${reqId}] step1 RAW extraction (before validation): ${JSON.stringify(extraction)}`);

    if (!extraction.periodFound) {
      return res.json({ periodFound: false, month: '', revenue: 0, labor: 0, grossProfit: 0, operatingProfit: 0, ebit: 0, ownerWages: 0, netIncome: 0, totalEquity: 0, confident: false });
    }

    // Same two-layer grounding as invoice extraction: Layer 1 checks each
    // claimed figure against its own quoted line for self-consistency;
    // Layer 2 (text mode only) checks it against the server's own
    // independently-extracted text -- ground truth the model never
    // authored, catching a figure with zero basis anywhere on the real page.
    const fields = [
      ['revenue', 'revenueLineAsPrinted', 'total\\s*revenue|total\\s*income|total\\s*sales|net\\s*sales|(?<!% of )\\brevenue\\b'],
      ['labor', 'laborLineAsPrinted', 'total\\s*hunk\\s*team\\s*payroll|hunk\\s*team\\s*payroll|total\\s*labor|\\blabor\\b|\\bwages\\b|salaries'],
      ['grossProfit', 'grossProfitLineAsPrinted', 'gross\\s*profit|gross\\s*margin'],
      ['operatingProfit', 'operatingProfitLineAsPrinted', 'operating\\s*profit'],
      ['ebit', 'ebitLineAsPrinted', '\\bebit\\b|earnings\\s*before\\s*interest\\s*(?:&|and)?\\s*tax\\b'],
      ['ownerWages', 'ownerWagesLineAsPrinted', 'owner.{0,10}(wages|draw|salary|compensation)|officer\\s*compensation'],
      ['netIncome', 'netIncomeLineAsPrinted', 'net\\s*income|net\\s*profit|net\\s*ordinary\\s*income'],
      ['totalEquity', 'totalEquityLineAsPrinted', 'total\\s*equity']
    ];
    fields.forEach(([field, printedField, keyword]) => {
      extraction[field] = validateAgainstQuote(extraction[field], extraction[printedField], keyword);
    });
    console.log(`[MONTHLY-FIN-EXTRACT ${reqId}] step2 after layer 1 (quote self-consistency): ${JSON.stringify(Object.fromEntries(fields.map(([f]) => [f, extraction[f]])))}`);

    if (hasUsableText) {
      const sourceText = texts.join(' ').toLowerCase().replace(/\s+/g, ' ').replace(/,/g, '');
      fields.forEach(([field, , keyword]) => {
        extraction[field] = verifyAgainstSourceText(sourceText, extraction[field], keyword);
      });
      console.log(`[MONTHLY-FIN-EXTRACT ${reqId}] step3 after layer 2 (ground-truth text search): ${JSON.stringify(Object.fromEntries(fields.map(([f]) => [f, extraction[f]])))}`);
    }

    // Same reasoning as the invoice endpoint's missing-confident-field fix:
    // the grounding layers above already independently verify every dollar
    // figure, so a model that omits this field entirely shouldn't have an
    // otherwise well-grounded extraction thrown out over it.
    if (extraction.confident === undefined) extraction.confident = true;

    console.log(`[MONTHLY-FIN-EXTRACT ${reqId}] FINAL result: ${JSON.stringify(extraction)}`);
    res.json(extraction);
  } catch (err) {
    console.error('Monthly financials extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// Lets an admin drag-reorder the home screen tiles; everyone sees the same
// resulting order, since this is a shared dashboard layout, not a personal
// preference.
const TILE_ORDER_KEY = 'dashboard-tile-order';

app.get('/api/tile-order', requireAuth, async (req, res) => {
  try {
    const raw = await redis.get(TILE_ORDER_KEY);
    const order = raw ? JSON.parse(raw) : [];
    res.json({ order });
  } catch (err) {
    console.error('Get tile order failed:', err.message);
    res.status(500).json({ error: 'Could not load tile order.' });
  }
});

app.post('/api/admin/tile-order', requireAuth, requireAdmin, async (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order) || !order.every(id => typeof id === 'string')) {
    return res.status(400).json({ error: 'Order must be an array of tile IDs.' });
  }
  try {
    await redis.set(TILE_ORDER_KEY, JSON.stringify(order));
    res.json({ ok: true, order });
  } catch (err) {
    console.error('Save tile order failed:', err.message);
    res.status(500).json({ error: 'Could not save tile order.' });
  }
});

// Employee names (not the financial payroll details) are needed by
// Attendance Tracking and Regulatory Compliance's Drivers section, which
// aren't restricted to admins -- so this computes just the name list from
// the most recent payroll week, without exposing gross pay, taxes, or hours.
// Shared by /api/roster and /api/driver/roster. Looks back across the two
// most recent payroll weeks (not just the latest one) and takes the union
// of everyone who appears in either -- an employee who happened to be off
// the most recent week (and so wasn't paid, and so wasn't in that week's
// export) still shows up as a selectable option everywhere the roster is
// used. Manually-added names (for someone new enough that no payroll run
// has included them yet) are merged in on top of that.
// Order-independent so "Gilbert Holland" and "Holland, Gilbert" compare
// equal regardless of which format a manual roster addition was typed in --
// ADP payroll reports use "Last, First", but a manual entry is easy to type
// as "First Last" instead, and without this the same person shows up twice
// once they actually appear on a payroll report. Mirrors the identical
// nameDedupKey() in the frontend.
function nameDedupKey(name){
  return name.replace(/,/g, ' ').split(/\s+/).filter(Boolean).map(w => w.toLowerCase()).sort().join(' ');
}

function computeRosterNames(weeks, manualAdditions){
  const sorted = [...(weeks || [])].sort((a, b) => (b.weekStart || '').localeCompare(a.weekStart || ''));
  const recentTwo = sorted.slice(0, 2);
  const fromPayroll = recentTwo.flatMap(w => (w.employees || []).map(e => e.name)).filter(Boolean);
  const combined = [...fromPayroll, ...(manualAdditions || [])];
  const seen = new Set();
  const deduped = [];
  combined.forEach(name => {
    const trimmed = (name || '').trim();
    if(!trimmed) return;
    const key = nameDedupKey(trimmed);
    if(seen.has(key)) return;
    seen.add(key);
    deduped.push(trimmed);
  });
  return deduped.sort((a, b) => a.localeCompare(b));
}

app.get('/api/roster', requireAuth, async (req, res) => {
  try {
    const [weeksRaw, manualRaw] = await Promise.all([
      redis.get('labor-weeks'),
      redis.get('roster-manual-additions')
    ]);
    const weeks = weeksRaw ? JSON.parse(weeksRaw) : [];
    const manualAdditions = manualRaw ? JSON.parse(manualRaw) : [];
    const names = computeRosterNames(weeks, manualAdditions);
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

// Splits a full address string into the primary_line/city/state Lob's
// verification endpoint wants. Finds state+zip from the end via regex
// (robust to "City, ST ZIP" vs "City, ST, ZIP" formatting differences),
// then treats whatever's left as "street, city".
function parseAddressForLob(fullAddress){
  const stateZipMatch = fullAddress.match(/,?\s*([A-Za-z]{2})\s*,?\s*(\d{5})(?:-\d{4})?\s*$/);
  if (!stateZipMatch) return null;
  const state = stateZipMatch[1].toUpperCase();
  const remainder = fullAddress.slice(0, stateZipMatch.index).trim().replace(/,\s*$/, '');
  const lastCommaIdx = remainder.lastIndexOf(',');
  if (lastCommaIdx === -1) return null;
  const primaryLine = remainder.slice(0, lastCommaIdx).trim();
  const city = remainder.slice(lastCommaIdx + 1).trim();
  if (!primaryLine || !city) return null;
  return { primaryLine, city, state };
}

function haversineMiles(a, b){
  const R = 3958.8; // Earth's radius in miles
  const dLat = (b.lat - a.lat) * Math.PI / 180;
  const dLng = (b.lng - a.lng) * Math.PI / 180;
  const lat1 = a.lat * Math.PI / 180;
  const lat2 = b.lat * Math.PI / 180;
  const h = Math.sin(dLat/2)**2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng/2)**2;
  return R * 2 * Math.asin(Math.sqrt(h));
}

// Geocodes two addresses via the same Lob US Verification API already used
// for zip lookup (no new service/key needed), then estimates the distance
// between them. Straight-line distance always underestimates real driving
// distance, so a conservative multiplier is applied -- this is meant to
// flag likely long-distance moves for a human to confirm, never to silently
// decide job type on its own.
app.post('/api/estimate-move-distance', requireAuth, async (req, res) => {
  const { originAddress, destAddress } = req.body || {};
  if (!originAddress || !destAddress) {
    return res.status(400).json({ error: 'originAddress and destAddress are required.' });
  }
  const apiKey = process.env.LOB_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'Distance estimate is not configured on the server yet (LOB_API_KEY is missing).' });
  }

  async function geocode(fullAddress){
    const parsed = parseAddressForLob(fullAddress);
    if (!parsed) return null;
    const params = new URLSearchParams({ primary_line: parsed.primaryLine, city: parsed.city, state: parsed.state });
    const lobRes = await fetch('https://api.lob.com/v1/us_verifications', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(apiKey + ':').toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });
    if (!lobRes.ok) return null;
    const data = await lobRes.json();
    const lat = data.components ? data.components.latitude : null;
    const lng = data.components ? data.components.longitude : null;
    if (typeof lat !== 'number' || typeof lng !== 'number') return null;
    return { lat, lng };
  }

  try {
    const [originGeo, destGeo] = await Promise.all([geocode(originAddress), geocode(destAddress)]);
    if (!originGeo || !destGeo) {
      return res.json({ ok: false, reason: 'Could not geocode one or both addresses.' });
    }
    const straightLineMiles = haversineMiles(originGeo, destGeo);
    const estimatedDrivingMiles = straightLineMiles * 1.3; // conservative -- errs toward catching genuinely long moves, not missing them
    res.json({
      ok: true,
      straightLineMiles: Math.round(straightLineMiles * 10) / 10,
      estimatedDrivingMiles: Math.round(estimatedDrivingMiles * 10) / 10
    });
  } catch (err) {
    console.error('Move distance estimate failed:', err.message);
    res.status(500).json({ error: 'Distance estimate failed: ' + err.message });
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

// ============ Insurance: Batch Truck Document Extraction ============
// For a batch of registration/insurance card photos, identifies each
// document's type and VIN so the frontend can match it to the correct
// truck (matching against each truck's VIN, same as Fleet Maintenance
// invoice extraction already does) and route it to the right upload slot.
const EXTRACT_TRUCK_DOCS_TOOL = {
  name: 'extract_truck_docs',
  description: 'For each vehicle registration or insurance card image provided, identify its document type and the vehicle\'s VIN.',
  input_schema: {
    type: 'object',
    properties: {
      documents: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            imageIndex: { type: 'number', description: 'The 0-based index of this image within the batch, in the order the images were provided.' },
            documentType: { type: 'string', enum: ['registration', 'insuranceCard', 'unclear'], description: '"registration" for a vehicle registration document, "insuranceCard" for a proof-of-insurance card, or "unclear" if it does not clearly look like either.' },
            vin: { type: 'string', description: 'The 17-character Vehicle Identification Number as printed on the document, exactly as shown. Empty string if no VIN is visible or legible.' },
            confident: { type: 'boolean', description: 'True if the document type and VIN (if present) were both read clearly. False if the image was blurry, cut off, or ambiguous.' }
          },
          required: ['imageIndex', 'documentType', 'confident']
        }
      }
    },
    required: ['documents']
  }
};

app.post('/api/admin/extract-truck-docs', requireAuth, async (req, res) => {
  const { images } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 20) {
    return res.status(400).json({ error: 'Please upload 20 images or fewer at a time.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Truck doc extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Batch extraction is not configured on the server yet.' });
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

    // Same 5-image batch size as listing extraction -- larger batches were
    // found to make per-image extraction noticeably less reliable.
    const BATCH_SIZE = 5;
    const batches = [];
    for (let i = 0; i < imageBlocks.length; i += BATCH_SIZE) {
      batches.push({ images: imageBlocks.slice(i, i + BATCH_SIZE), offset: i });
    }

    async function runBatch(batch, batchIndex){
      const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 2048,
          tools: [EXTRACT_TRUCK_DOCS_TOOL],
          tool_choice: { type: 'tool', name: 'extract_truck_docs' },
          messages: [{
            role: 'user',
            content: [
              ...batch.images,
              { type: 'text', text: `These are ${batch.images.length} photo(s) of vehicle registration and/or insurance card documents, one document per image, in order. For each image (using its 0-based position in this batch, starting at 0), identify whether it's a registration or an insurance card, and read the VIN printed on it.` }
            ]
          }]
        })
      });

      if (!anthropicRes.ok) {
        const errBody = await anthropicRes.text().catch(() => '');
        console.error(`Truck doc extraction batch ${batchIndex} failed:`, anthropicRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return { error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` };
      }

      const data = await anthropicRes.json();
      const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_truck_docs');
      if (!toolUseBlock) {
        console.error(`Truck doc extraction batch ${batchIndex}: no tool_use block. stop_reason=`, data.stop_reason);
        return { error: 'Could not read a structured response from the extraction service.' };
      }
      const documents = Array.isArray(toolUseBlock.input.documents) ? toolUseBlock.input.documents : [];
      // Re-offset each result's imageIndex from batch-local to global, so the
      // frontend can map results straight back to its original images array.
      const rebased = documents.map(d => ({ ...d, imageIndex: (d.imageIndex || 0) + batch.offset }));
      return { documents: rebased };
    }

    const batchResults = await Promise.all(batches.map((b, i) => runBatch(b, i)));
    const allDocuments = [];
    const batchErrors = [];
    batchResults.forEach(r => {
      if (r.error) batchErrors.push(r.error);
      else allDocuments.push(...r.documents);
    });

    if (allDocuments.length === 0 && batchErrors.length > 0) {
      return res.status(502).json({ error: batchErrors[0] });
    }
    res.json({ documents: allDocuments, partialFailures: batchErrors.length });
  } catch (err) {
    console.error('Truck doc extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Job Paperwork: Batch Work Order Extraction ============
// Reads a batch of HunkWare work order documents (one image per document --
// callers send just the first page, since that's where all the structured
// fields live) and extracts the job details needed to populate Job Data
// Entry and generate the paperwork packet.
//
// Each uploaded file is sent as ONE Claude call with ALL of its pages
// together (not split into fixed-size batches like the other extraction
// endpoints) -- a single uploaded PDF may contain more than one work order
// back to back (e.g. a scanner combining a whole stack into one file), and
// correctly telling where one job ends and the next begins requires seeing
// all of a file's pages at once. Different files are still processed in
// parallel for throughput.
const EXTRACT_WORK_ORDER_TOOL = {
  name: 'extract_work_orders',
  description: 'Extract job details for every distinct work order found across the provided pages.',
  input_schema: {
    type: 'object',
    properties: {
      documents: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            firstPageIndex: { type: 'number', description: 'The 0-based index, among the pages provided in this call, of this work order\u2019s first page.' },
            lastPageIndex: { type: 'number', description: 'The 0-based index, among the pages provided in this call, of this work order\u2019s LAST page (inclusive). Equal to firstPageIndex if it\u2019s a single page. This defines the exact page range that belongs to this specific work order -- do not include pages that belong to a different work order or are blank/unrelated.' },
            jobNumber: { type: 'string', description: 'The Job ID / Job Number as printed on the work order -- look for it regardless of whether the document\u2019s Type field says JOB or ESTIMATE. Estimates carry this field too, even though the move itself isn\u2019t booked yet. Empty string only if genuinely not printed anywhere on the document.' },
            clientName: { type: 'string', description: 'The client\u2019s full name. Empty string if not found.' },
            clientPhone: { type: 'string', description: 'The client\u2019s phone number as printed. Empty string if not found.' },
            clientEmail: { type: 'string', description: 'The client\u2019s email address. Empty string if not found.' },
            originAddress: { type: 'string', description: 'The full pick-up/origin address as one line (street, city, state, zip). Empty string if not found.' },
            destAddress: { type: 'string', description: 'The full destination address as one line (street, city, state, zip). Empty string if not found.' },
            jobDate: { type: 'string', description: 'The scheduled job date in YYYY-MM-DD format. Empty string if not found or not legible.' },
            scheduledHours: { type: 'number', description: 'The scheduled job duration in decimal hours, computed from a "Job Time: START - END" field if present (e.g. "8:00 AM - 3:15 PM" is 7.25). 0 if no job time range is found.' },
            quotedHours: { type: 'number', description: 'The number of hours the move is estimated to last, as stated in the quote/estimate narrative (look for phrasing like "estimated the move to last X hours"). 0 if no such quote narrative is present.' },
            quotedHourlyRate: { type: 'number', description: 'The dollar rate per hour stated in the quote narrative (look for phrasing like "$X per hour for Y HUNKS"). 0 if not present.' },
            quotedCrewSize: { type: 'number', description: 'The number of HUNKS/crew stated alongside the hourly rate in the quote narrative. 0 if not present.' },
            quotedOtherFees: { type: 'number', description: 'Any fixed dollar charge in the quote narrative beyond straight hourly labor (e.g. a "Truck and Travel Fee"). 0 if not present.' },
            serviceType: {
              type: 'string',
              enum: ['move', 'movelabor', 'junkremoval', 'unclear'],
              description: '"move" if this is a full moving service (packing/loading/transporting/unloading household goods). "movelabor" if it\u2019s a labor-only service (e.g. just loading/unloading help, no long-haul transport of goods). "junkremoval" if this is a junk/hauling-away job rather than a household move (this company does both moving and junk removal work orders). "unclear" only if the service type genuinely can\u2019t be determined -- do not guess between the other three if it isn\u2019t reasonably clear.'
            },
            orderType: {
              type: 'string',
              enum: ['job', 'estimate', 'unclear'],
              description: 'Read directly from the work order\u2019s own "Type:" field near the top of the document -- not inferred from anything else on the page. This field is often abbreviated, not spelled out in full: "Type: EST" or "Type: ESTIMATE" both mean "estimate"; "Type: JOB" or any other clear job-type abbreviation means "job". Treat an abbreviation as a confident match to whichever it clearly stands for -- do not return "unclear" just because the word isn\u2019t spelled out in full. "estimate" means this document is only a price estimate that hasn\u2019t been booked as an actual job, and should never get paperwork generated for it. "unclear" only if no such Type field is present or legible at all, or its abbreviation is genuinely ambiguous -- do not guess "job" or "estimate" in that case.'
            },
            estimateSummary: { type: 'string', description: 'If a "Move Factors" or auto-generated quote/estimate narrative section is present (often starting with something like "This is an inventory quote..." and including sentences like "We have estimated the move to last X hours", "$X per hour for Y HUNKS", "The cost for labor... is estimated at $X", "The estimated total cost of this move is $X"), transcribe that narrative text as close to verbatim as possible -- do not summarize or paraphrase it, since exact phrasing and numbers matter. Empty string if no such section is present.' },
            packingMaterials: {
              type: 'array',
              description: 'Any packing materials mentioned in the quote/estimate\u2019s Packing Services section, e.g. a line reading "Pack 5 small boxes" becomes {description: "small boxes", quantity: 5}. This is the quoted/expected quantity, not necessarily what actually gets used on the job. Empty array if no Packing Services materials are mentioned anywhere in the quote.',
              items: {
                type: 'object',
                properties: {
                  description: { type: 'string', description: 'The material name exactly as stated, e.g. "small boxes", "shrink wrap", "wardrobe boxes".' },
                  quantity: { type: 'number', description: 'The quantity stated for this material.' }
                },
                required: ['description', 'quantity']
              }
            },
            confident: { type: 'boolean', description: 'True if the job number, client info, and addresses were all read clearly. False if the image was blurry, cut off, or key fields were ambiguous.' }
          },
          required: ['firstPageIndex', 'lastPageIndex', 'jobNumber', 'clientName', 'originAddress', 'destAddress', 'serviceType', 'orderType', 'confident', 'scheduledHours', 'quotedHours', 'quotedHourlyRate', 'quotedCrewSize', 'quotedOtherFees', 'packingMaterials']
        }
      }
    },
    required: ['documents']
  }
};

app.post('/api/admin/extract-work-orders', requireAuth, async (req, res) => {
  const { files } = req.body || {};
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'At least one file is required.' });
  }
  if (files.length > 10) {
    return res.status(400).json({ error: 'Please upload 10 files or fewer at a time.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Work order extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Batch extraction is not configured on the server yet.' });
  }

  try {
    const parsedFiles = files.map(f => {
      const images = Array.isArray(f && f.images) ? f.images : [];
      const blocks = images.map(dataUri => {
        const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(dataUri || '');
        if (!match) return null;
        return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
      }).filter(Boolean);
      return blocks;
    });
    if (parsedFiles.every(blocks => blocks.length === 0)) {
      return res.status(400).json({ error: 'No valid pages were provided.' });
    }
    const MAX_PAGES_PER_FILE = 80; // Anthropic's API allows up to 100 images per request for this model; 80 leaves comfortable headroom below both that cap and the 32MB total request-size limit
    for (const blocks of parsedFiles) {
      if (blocks.length > MAX_PAGES_PER_FILE) {
        return res.status(400).json({ error: `One of the files has more than ${MAX_PAGES_PER_FILE} pages -- please split it into smaller files.` });
      }
    }

    // One extraction call for a run of pages. Page indices in the reply
    // are relative to this call, so they're shifted by `offset` back to
    // the file's own page numbers.
    async function extractPages(pageBlocks, fileIndex, offset, depth){
      const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          // Every work order in the batch comes back in one reply, so a
          // big day's batch needs room -- 4096 cut off around a dozen
          // jobs and the whole reply came back empty.
          max_tokens: 16000,
          tools: [EXTRACT_WORK_ORDER_TOOL],
          tool_choice: { type: 'tool', name: 'extract_work_orders' },
          messages: [{
            role: 'user',
            content: [
              ...pageBlocks,
              { type: 'text', text: `These are ${pageBlocks.length} page(s) from a single uploaded file, in order (0-based index 0 through ${pageBlocks.length - 1}). This file may contain just ONE work order, or it may contain SEVERAL distinct work orders placed back to back (e.g. a stack of documents scanned into one file) -- each work order typically runs a few pages and often shows a repeated "Page X/Y" footer and reference number that resets or changes at the start of the next one, plus its own Job ID. Find every distinct work order present, extract each one separately, and report the exact page range (first and last page index) each one occupies -- do not merge different jobs together, and do not split one job into more than one entry. Also read the scheduled "Job Time" range (e.g. "8:00 AM - 3:15 PM") and convert it to decimal hours, and separately read the quote/estimate narrative's stated hours, hourly rate, crew size, and any other flat fee -- these two hour figures sometimes disagree (the job may be scheduled for a very different duration than the attached quote assumed), which is exactly what needs to be reported, not reconciled. Also check the quote for a Packing Services line item -- it lists packing materials with a quantity, e.g. "Pack 5 small boxes" -- and report each material and its quantity; leave this empty if the quote has no such line, since not every job includes packing materials.` }
            ]
          }]
        })
      });

      if (!anthropicRes.ok) {
        const errBody = await anthropicRes.text().catch(() => '');
        console.error(`Work order extraction file ${fileIndex} (pages ${offset}-${offset + pageBlocks.length - 1}) failed:`, anthropicRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return { error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` };
      }

      const data = await anthropicRes.json();
      // Still too much for one reply: read each half on its own instead
      // of returning a cut-off (and usually empty) list.
      if (data.stop_reason === 'max_tokens' && pageBlocks.length > 1 && depth < 4) {
        const mid = Math.ceil(pageBlocks.length / 2);
        console.log(`[work-orders] file ${fileIndex}: ${pageBlocks.length} pages too many for one reply \u2014 splitting into ${mid} + ${pageBlocks.length - mid}`);
        const [a, b] = await Promise.all([
          extractPages(pageBlocks.slice(0, mid), fileIndex, offset, depth + 1),
          extractPages(pageBlocks.slice(mid), fileIndex, offset + mid, depth + 1)
        ]);
        if (a.error && b.error) return { error: a.error };
        return { documents: [...(a.documents || []), ...(b.documents || [])], partial: !!(a.error || b.error) };
      }
      const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_work_orders');
      if (!toolUseBlock) {
        console.error(`Work order extraction file ${fileIndex}: no tool_use block. stop_reason=`, data.stop_reason);
        return { error: 'Could not read a structured response from the extraction service.' };
      }
      if (data.stop_reason === 'max_tokens') {
        console.error(`[work-orders] file ${fileIndex}: reply cut off on a single page (pages ${offset}-${offset + pageBlocks.length - 1}).`);
      }
      const documents = (Array.isArray(toolUseBlock.input.documents) ? toolUseBlock.input.documents : []).map(d => ({
        ...d,
        firstPageIndex: (Number(d.firstPageIndex) || 0) + offset,
        lastPageIndex: (Number(d.lastPageIndex ?? d.firstPageIndex) || 0) + offset
      }));
      return { documents };
    }

    // A work order that straddled a split comes back as two pieces with
    // the same job number -- put it back together as one, spanning both
    // pieces' pages, keeping whichever piece read more of its details.
    function mergeSplitWorkOrders(documents){
      const filled = d => Object.values(d).filter(v => v !== '' && v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0)).length;
      const byJob = new Map();
      const out = [];
      documents.forEach(d => {
        const key = String(d.jobNumber || '').trim();
        if (!key) { out.push(d); return; }
        const prev = byJob.get(key);
        if (!prev) { byJob.set(key, d); out.push(d); return; }
        // Start from the piece that read more, then fill any detail it
        // missed from the other piece.
        const [main, other] = filled(d) > filled(prev) ? [d, prev] : [prev, d];
        const isEmpty = v => v === '' || v === null || v === undefined || (Array.isArray(v) && v.length === 0);
        const best = { ...main };
        Object.keys(other).forEach(k => { if (isEmpty(best[k]) && !isEmpty(other[k])) best[k] = other[k]; });
        best.firstPageIndex = Math.min(prev.firstPageIndex, d.firstPageIndex);
        best.lastPageIndex = Math.max(prev.lastPageIndex, d.lastPageIndex);
        out[out.indexOf(prev)] = best;
        byJob.set(key, best);
      });
      return out.sort((x, y) => x.firstPageIndex - y.firstPageIndex);
    }

    async function runFile(pageBlocks, fileIndex){
      if (pageBlocks.length === 0) return { fileIndex, documents: [] };
      const result = await extractPages(pageBlocks, fileIndex, 0, 0);
      if (result.error) return { fileIndex, error: result.error };
      const documents = mergeSplitWorkOrders(result.documents);
      console.log(`[work-orders] file ${fileIndex}: ${pageBlocks.length} pages \u2192 ${documents.length} work order(s)${result.partial ? ' (part of the file failed)' : ''}`);
      return { fileIndex, documents, partial: result.partial };
    }

    const fileResults = await Promise.all(parsedFiles.map((blocks, i) => runFile(blocks, i)));
    const allDocuments = [];
    const fileErrors = [];
    fileResults.forEach(r => {
      if (r.error) fileErrors.push(r.error);
      else {
        if (r.partial) fileErrors.push('Part of a file could not be read.');
        r.documents.forEach(d => allDocuments.push({ ...d, fileIndex: r.fileIndex }));
      }
    });

    if (allDocuments.length === 0 && fileErrors.length > 0) {
      return res.status(502).json({ error: fileErrors[0] });
    }
    res.json({ documents: allDocuments, partialFailures: fileErrors.length });
  } catch (err) {
    console.error('Work order extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });

  }
});

// ============ Completed Paperwork: Batch Job Number Extraction ============
// Reads a batch of scanned completed-paperwork documents and pulls just the
// job number off each one, so the frontend can look it up against the
// existing paperwork-job-archive bridge (same lookup Job Paperwork's manual
// upload already uses) and auto-fill client name/email instead of typing
// them in per scan. Same 5-image batch pattern as the other extraction
// endpoints.
const EXTRACT_JOB_NUMBERS_TOOL = {
  name: 'extract_job_numbers',
  description: 'Extract the job number, client name, and invoice total from a completed moving-job paperwork scan.',
  input_schema: {
    type: 'object',
    properties: {
      jobNumber: { type: 'string', description: 'The job number for this document (often an 8-digit HunkWare job number). It may appear on any page -- check all of them, not just the first. Empty string if not found or not legible on any page.' },
      clientName: { type: 'string', description: 'The client/customer\u2019s name, if visible anywhere on any page (e.g. next to "Name:" on a Bill of Lading or Liability Waiver, or a signature). Empty string if not found.' },
      invoiceTotal: { type: 'number', description: 'The total dollar amount billed/invoiced for this job, if a total appears anywhere on the document (e.g. a line labeled "Total", "Amount Due", "Total Charges", or similar). Use 0 if no such total is visible.' },
      confident: { type: 'boolean', description: 'True if the job number was read clearly. False if every page was too blurry, cut off, or no job number was visible anywhere.' }
    },
    required: ['jobNumber', 'clientName', 'invoiceTotal', 'confident']
  }
};

app.post('/api/admin/extract-job-numbers', requireAuth, async (req, res) => {
  const { files } = req.body || {};
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'At least one document is required.' });
  }
  if (files.length > 20) {
    return res.status(400).json({ error: 'Please upload 20 documents or fewer at a time.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Job number extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Batch extraction is not configured on the server yet.' });
  }

  try {
    const parsedFiles = files.map(f => {
      const imgs = Array.isArray(f.images) ? f.images : [];
      return imgs.map(dataUri => {
        const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(dataUri || '');
        if (!match) return null;
        return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
      }).filter(Boolean);
    });

    // Each uploaded scan is its own model call (not grouped like the work-order
    // batch, since page count varies a lot per completed-paperwork upload) --
    // all of that document's pages go in together, since the job number isn't
    // always on the first page (e.g. when a work order was prepended ahead of
    // the signed Bill of Lading during printing).
    async function runFile(imageBlocks, fileIndex){
      if (imageBlocks.length === 0) {
        return { fileIndex, error: 'No valid images in this document.' };
      }
      const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 1024,
          tools: [EXTRACT_JOB_NUMBERS_TOOL],
          tool_choice: { type: 'tool', name: 'extract_job_numbers' },
          messages: [{
            role: 'user',
            content: [
              ...imageBlocks,
              { type: 'text', text: `These are ${imageBlocks.length} page(s), in order, from a single scanned completed-paperwork document from a moving company (Bill of Lading, Liability Waiver, and related signed forms for one job). Find the job number -- check every page, since it isn't always on the first one (for example, if a copy of the original work order was printed ahead of the signed forms). Also note the client's name if it's visible anywhere, and the invoice/billed total if a total dollar amount appears anywhere on the document.` }
            ]
          }]
        })
      });

      if (!anthropicRes.ok) {
        const errBody = await anthropicRes.text().catch(() => '');
        console.error(`Job number extraction file ${fileIndex} failed:`, anthropicRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return { fileIndex, error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` };
      }

      const data = await anthropicRes.json();
      const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_job_numbers');
      if (!toolUseBlock) {
        console.error(`Job number extraction file ${fileIndex}: no tool_use block. stop_reason=`, data.stop_reason);
        return { fileIndex, error: 'Could not read a structured response from the extraction service.' };
      }
      return { fileIndex, ...toolUseBlock.input };
    }

    const results = await Promise.all(parsedFiles.map((blocks, i) => runFile(blocks, i)));
    const documents = [];
    const fileErrors = [];
    results.forEach(r => {
      if (r.error) fileErrors.push(r.error);
      else documents.push(r);
    });

    if (documents.length === 0 && fileErrors.length > 0) {
      return res.status(502).json({ error: fileErrors[0] });
    }
    res.json({ documents, partialFailures: fileErrors.length });
  } catch (err) {
    console.error('Job number extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});
// ============ Job Paperwork: Corrected Quote Extraction ============
// A single-document read for a replacement/corrected quote the admin
// uploads when a work order's attached quote didn't actually match the
// scheduled job duration. Same numeric fields as the work-order extraction
// (kept as raw numbers so the actual cost math stays deterministic, not
// left to model arithmetic), plus a verbatim narrative transcription when
// the document already reads like a normal HunkWare quote block, since
// that flows straight into the existing estimate-summary parser unchanged.
const EXTRACT_QUOTE_TOOL = {
  name: 'extract_quote',
  description: 'Extract the hours, rate, crew size, and fees from a moving-job quote/estimate document.',
  input_schema: {
    type: 'object',
    properties: {
      quotedHours: { type: 'number', description: 'The number of hours the move is estimated to last, as stated in the document. 0 if not found.' },
      quotedHourlyRate: { type: 'number', description: 'The dollar rate per hour stated in the document. 0 if not found.' },
      quotedCrewSize: { type: 'number', description: 'The number of HUNKS/crew the rate is based on. 0 if not found.' },
      quotedOtherFees: { type: 'number', description: 'Any fixed dollar charge beyond straight hourly labor (e.g. a truck/travel fee). 0 if not found.' },
      narrativeText: { type: 'string', description: 'If the document already contains a HunkWare-style quote narrative (sentences like "We have estimated the move to last X hours", "$X per hour for Y HUNKS", "The cost for labor... is estimated at $X", "The estimated total cost of this move is $X"), transcribe that narrative as close to verbatim as possible. Empty string if the document doesn\u2019t read that way (e.g. it\u2019s a different format entirely).' },
      confident: { type: 'boolean', description: 'True if the key figures (hours, rate) were read clearly.' }
    },
    required: ['quotedHours', 'quotedHourlyRate', 'quotedCrewSize', 'quotedOtherFees', 'narrativeText', 'confident']
  }
};

app.post('/api/admin/extract-quote', requireAuth, async (req, res) => {
  const { image } = req.body || {};
  if (!image) {
    return res.status(400).json({ error: 'An image is required.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Quote extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Extraction is not configured on the server yet.' });
  }

  try {
    const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(image);
    if (!match) {
      return res.status(400).json({ error: 'That doesn\u2019t look like a valid image.' });
    }
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1536,
        tools: [EXTRACT_QUOTE_TOOL],
        tool_choice: { type: 'tool', name: 'extract_quote' },
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } },
            { type: 'text', text: 'This is a corrected/replacement quote for a moving job. Read the estimated hours, hourly rate, crew size, and any flat fees.' }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Quote extraction failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_quote');
    if (!toolUseBlock) {
      console.error('Quote extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Quote extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Materials: Invoice Line-Item Extraction ============
// Reads a supplier invoice (possibly multiple pages) and pulls out each
// line item, so establishing/restocking inventory doesn't mean typing in
// every item and quantity by hand. Prices and quantities come back as raw
// numbers -- if a total needs computing anywhere downstream, that stays
// deterministic arithmetic on the frontend, not model output.
const EXTRACT_INVOICE_ITEMS_TOOL = {
  name: 'extract_invoice_items',
  description: 'Extract each line item from a supplier invoice for moving/packing supplies.',
  input_schema: {
    type: 'object',
    properties: {
      items: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            supplierItemNumber: { type: 'string', description: 'The supplier\u2019s item/SKU number for this line. Empty string if this invoice doesn\u2019t show one.' },
            description: { type: 'string', description: 'The item description as printed on the invoice.' },
            priceEach: { type: 'number', description: 'The unit price for one of this item. 0 if not shown (e.g. only a line total is given).' },
            quantity: { type: 'number', description: 'The quantity of this item on this invoice.' }
          },
          required: ['supplierItemNumber', 'description', 'priceEach', 'quantity']
        }
      },
      confident: { type: 'boolean', description: 'True if the line items were read clearly. False if the invoice was too blurry, cut off, or didn\u2019t look like an itemized invoice.' }
    },
    required: ['items', 'confident']
  }
};

app.post('/api/admin/extract-invoice-items', requireAuth, async (req, res) => {
  const { images } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 80) {
    return res.status(400).json({ error: 'Please split this into invoices of 80 pages or fewer.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Invoice extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Extraction is not configured on the server yet.' });
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
        tools: [EXTRACT_INVOICE_ITEMS_TOOL],
        tool_choice: { type: 'tool', name: 'extract_invoice_items' },
        messages: [{
          role: 'user',
          content: [
            ...imageBlocks,
            { type: 'text', text: `These are ${imageBlocks.length} page(s) of a single supplier invoice for moving/packing supplies. Find every line item -- item number, description, unit price, and quantity -- across all pages.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Invoice extraction failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_invoice_items');
    if (!toolUseBlock) {
      console.error('Invoice extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Invoice extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Labor Cost: Revenue Extraction ============
// ADP Payroll Detail wages/taxes/OT/employee data are already parsed
// directly from the .xlsx export -- structured spreadsheet parsing is more
// reliable than AI extraction for that. Revenue comes from HunkWare
// instead, which has no equivalent structured export, so this fills that
// one remaining gap from a screenshot of the HunkWare revenue report.
const EXTRACT_REVENUE_TOOL = {
  name: 'extract_revenue',
  description: 'Extract the total weekly revenue figure from a HunkWare revenue report screenshot.',
  input_schema: {
    type: 'object',
    properties: {
      totalRevenue: { type: 'number', description: 'The total revenue figure for the period shown, in dollars, as a plain number (no currency symbol or commas). Sum multiple line items if the screenshot shows a list rather than a single total.' },
      periodLabel: { type: 'string', description: 'Any date range or period label visible in the screenshot, e.g. "Aug 17 - Aug 23, 2026". Empty string if none is visible.' },
      confident: { type: 'boolean', description: 'True if a single, clear revenue total was found. False if the screenshot was ambiguous, cut off, showed multiple unrelated periods, or no clear total was visible.' }
    },
    required: ['totalRevenue', 'confident']
  }
};

app.post('/api/admin/extract-revenue', requireAuth, async (req, res) => {
  const { images } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 5) {
    return res.status(400).json({ error: 'Please upload 5 images or fewer.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Revenue extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Screenshot extraction is not configured on the server yet.' });
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

    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [EXTRACT_REVENUE_TOOL],
        tool_choice: { type: 'tool', name: 'extract_revenue' },
        messages: [{
          role: 'user',
          content: [
            ...imageBlocks,
            { type: 'text', text: `This is a screenshot (or a few screenshots) of a HunkWare weekly revenue report for a moving/junk removal company. Find the total revenue figure for the period shown. If the screenshot shows a list of individual jobs rather than one combined total, sum them yourself. If it clearly is not a revenue report, or no total can be determined, set confident to false.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Revenue extraction request failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_revenue');
    if (!toolUseBlock) {
      console.error('Revenue extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Revenue extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Fleet Maintenance: Invoice Extraction ============
// Reads a maintenance invoice (photo or first page of a PDF, already
// rendered client-side to an image) and pulls out the service date,
// odometer reading, and a short description, so the admin isn't
// retyping what's already sitting right there on the receipt.
const EXTRACT_INVOICE_TOOL = {
  name: 'extract_invoice',
  description: 'Extract structured maintenance details from a vehicle service invoice or receipt.',
  input_schema: {
    type: 'object',
    properties: {
      date: { type: 'string', description: 'Date of service in YYYY-MM-DD format, or empty string if not legible.' },
      description: { type: 'string', description: 'A brief (one sentence) summary of the service or repair work described on the invoice, e.g. "Oil change and tire rotation" or "Replaced rear brake pads".' },
      mileage: { type: 'number', description: 'Odometer reading in miles if printed on the invoice. Omit this field entirely if no mileage is visible -- do not guess.' },
      vin: { type: 'string', description: 'The 17-character Vehicle Identification Number if printed on the invoice, exactly as shown. Omit this field entirely if no VIN is visible -- do not guess.' },
      confident: { type: 'boolean', description: 'True if this clearly looks like a vehicle service invoice/receipt with at least a date and description found. False if the image is unreadable or does not look like a service invoice.' }
    },
    required: ['description', 'confident']
  }
};

app.post('/api/admin/extract-invoice', requireAuth, async (req, res) => {
  const { image } = req.body || {};
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Invoice extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Invoice extraction is not configured on the server yet.' });
  }
  const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(image || '');
  if (!match) {
    return res.status(400).json({ error: 'A valid image is required.' });
  }

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [EXTRACT_INVOICE_TOOL],
        tool_choice: { type: 'tool', name: 'extract_invoice' },
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } },
            { type: 'text', text: `This is a photo or scan of a vehicle maintenance/repair invoice or receipt. Extract the service date, a brief description of the work performed, the odometer/mileage reading if printed on it, and the vehicle's VIN if printed on it (often labeled "VIN" near the vehicle description). Do not extract cost or price figures.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Invoice extraction request failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_invoice');
    if (!toolUseBlock) {
      console.error('Invoice extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Invoice extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Compliance: DOT Inspection / Incident / Violation Document Extraction ============
// Same pattern as extract-invoice above: a photographed/scanned document,
// read by Claude, with a confidence flag so the admin can tell when to
// trust the auto-fill versus fill the form in by hand.
const EXTRACT_DOT_INSPECTION_TOOL = {
  name: 'extract_dot_inspection',
  description: 'Extract structured details from a DOT roadside inspection report.',
  input_schema: {
    type: 'object',
    properties: {
      date: { type: 'string', description: 'Date of the inspection in YYYY-MM-DD format, or empty string if not legible.' },
      result: { type: 'string', enum: ['pass', 'pass-defects', 'oos'], description: 'Overall result: "pass" (no defects noted), "pass-defects" (passed but defects were noted), or "oos" (vehicle or driver placed out of service). Omit this field entirely if the result cannot be determined.' },
      location: { type: 'string', description: 'Inspection location and/or inspecting officer/agency name if shown, e.g. "I-20 Weigh Station, Augusta GA" or the inspector\u2019s name.' },
      notes: { type: 'string', description: 'A brief summary of any defects, violations, or notes listed on the report. Empty string if none.' },
      confident: { type: 'boolean', description: 'True if this clearly looks like a DOT/roadside inspection report. False if the image is unreadable or does not look like one.' }
    },
    required: ['confident']
  }
};

app.post('/api/admin/extract-dot-inspection', requireAuth, async (req, res) => {
  const { image } = req.body || {};
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('DOT inspection extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Document extraction is not configured on the server yet.' });
  }
  const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(image || '');
  if (!match) {
    return res.status(400).json({ error: 'A valid image is required.' });
  }

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [EXTRACT_DOT_INSPECTION_TOOL],
        tool_choice: { type: 'tool', name: 'extract_dot_inspection' },
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } },
            { type: 'text', text: `This is a photo or scan of a DOT roadside vehicle inspection report. Extract the inspection date, the overall result, the location/inspector, and a brief note on any defects or violations listed.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('DOT inspection extraction request failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_dot_inspection');
    if (!toolUseBlock) {
      console.error('DOT inspection extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('DOT inspection extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

const EXTRACT_INCIDENT_TOOL = {
  name: 'extract_incident',
  description: 'Extract structured details from a vehicle safety incident report, accident report, or police report.',
  input_schema: {
    type: 'object',
    properties: {
      date: { type: 'string', description: 'Date of the incident in YYYY-MM-DD format, or empty string if not legible.' },
      severity: { type: 'string', enum: ['minor', 'moderate', 'severe'], description: 'Your best assessment of severity based on the described damage/injuries: "minor" (little to no damage, no injuries), "moderate" (notable vehicle damage, no serious injuries), or "severe" (significant damage and/or injuries). Omit this field entirely if severity cannot reasonably be assessed.' },
      description: { type: 'string', description: 'A brief (one to two sentence) summary of what happened.' },
      confident: { type: 'boolean', description: 'True if this clearly looks like an incident/accident report describing a vehicle-related event. False if the image is unreadable or does not look like one.' }
    },
    required: ['description', 'confident']
  }
};

app.post('/api/admin/extract-incident', requireAuth, async (req, res) => {
  const { image } = req.body || {};
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Incident extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Document extraction is not configured on the server yet.' });
  }
  const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(image || '');
  if (!match) {
    return res.status(400).json({ error: 'A valid image is required.' });
  }

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [EXTRACT_INCIDENT_TOOL],
        tool_choice: { type: 'tool', name: 'extract_incident' },
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } },
            { type: 'text', text: `This is a photo or scan of a vehicle safety incident, accident, or police report. Extract the date of the incident, your best assessment of severity, and a brief summary of what happened.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Incident extraction request failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_incident');
    if (!toolUseBlock) {
      console.error('Incident extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Incident extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

const EXTRACT_VIOLATION_TOOL = {
  name: 'extract_violation',
  description: 'Extract structured details from a traffic citation, moving violation notice, or compliance violation document.',
  input_schema: {
    type: 'object',
    properties: {
      date: { type: 'string', description: 'Date of the violation/citation in YYYY-MM-DD format, or empty string if not legible.' },
      status: { type: 'string', enum: ['open', 'resolved'], description: 'Whether the violation appears already resolved/paid/dismissed (based on any stamps, notes, or paid indicators visible) versus still open. Default to "open" if there is no clear indication either way.' },
      description: { type: 'string', description: 'A brief summary of the violation, e.g. "Speeding 15 over posted limit on I-20" or "Expired vehicle registration tag".' },
      confident: { type: 'boolean', description: 'True if this clearly looks like a traffic citation or violation notice. False if the image is unreadable or does not look like one.' }
    },
    required: ['description', 'confident']
  }
};

app.post('/api/admin/extract-violation', requireAuth, async (req, res) => {
  const { image } = req.body || {};
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Violation extraction requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Document extraction is not configured on the server yet.' });
  }
  const match = /^data:(image\/[a-zA-Z]+);base64,(.+)$/.exec(image || '');
  if (!match) {
    return res.status(400).json({ error: 'A valid image is required.' });
  }

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        tools: [EXTRACT_VIOLATION_TOOL],
        tool_choice: { type: 'tool', name: 'extract_violation' },
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } },
            { type: 'text', text: `This is a photo or scan of a traffic citation, moving violation notice, or compliance violation document. Extract the date, whether it appears open or already resolved, and a brief summary of the violation.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Violation extraction request failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_violation');
    if (!toolUseBlock) {
      console.error('Violation extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Violation extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Captain Metrics: Paperwork Completeness ============
// Estimates what share of a completed-paperwork upload's blank
// signature/initial/written-response fields appear filled in by hand. This
// is a fuzzier visual task than the other extraction endpoints (detecting
// handwriting presence, not reading printed text), so it uses Sonnet rather
// than Haiku for better visual judgment. Explicitly an estimate, not a
// precise audit -- the response includes a confidence flag and a list of
// which fields looked blank so a human can spot-check.
const ASSESS_COMPLETENESS_TOOL = {
  name: 'assess_completeness',
  description: 'Assess how many of the REQUIRED blank signature, initials, or written-response fields on this moving-company paperwork document appear to have been filled in by hand.',
  input_schema: {
    type: 'object',
    properties: {
      totalFieldsFound: { type: 'number', description: 'Total count of REQUIRED blank-line fields across the document meant for a signature, initials, date written by hand, or other short handwritten response. Do not count printed/pre-filled text or checkboxes. Do not count anything from an Addendum to Cost Estimate or Pre-existing Damages page, and do not count the signature/initial lines under valuation options on the Shipper Declaration of Value that were NOT the one selected -- see the exclusion rules.' },
      fieldsCompleted: { type: 'number', description: 'Of those REQUIRED fields only, how many appear to actually have handwriting, a signature, initials, or a mark present -- as opposed to being visibly blank.' },
      incompleteFields: {
        type: 'array',
        items: { type: 'string' },
        description: 'Brief plain-language description of each REQUIRED field that appears blank, e.g. "Client signature on page 2", "Captain initials next to Item 4". Never include a field excluded by the exclusion rules. Empty array if everything required appears complete.'
      },
      excludedNote: { type: 'string', description: 'Brief note on what was excluded and why, if anything (e.g. "Skipped Pre-existing Damages page (not required this job); only Option 2(a) counted on Declaration of Value"). Empty string if nothing was excluded.' },
      confident: { type: 'boolean', description: 'True if the document was legible enough to make this assessment. False if too blurry, cut off, poorly lit, or doesn\u2019t look like a moving/paperwork document.' }
    },
    required: ['totalFieldsFound', 'fieldsCompleted', 'confident']
  }
};

app.post('/api/admin/assess-completeness', requireAuth, async (req, res) => {
  const { images } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 10) {
    return res.status(400).json({ error: 'Please limit to 10 pages per assessment.' });
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('Completeness assessment requested but ANTHROPIC_API_KEY is not set on this service.');
    return res.status(500).json({ error: 'Completeness assessment is not configured on the server yet.' });
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

    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 1536,
        tools: [ASSESS_COMPLETENESS_TOOL],
        tool_choice: { type: 'tool', name: 'assess_completeness' },
        messages: [{
          role: 'user',
          content: [
            ...imageBlocks,
            { type: 'text', text: `This is completed paperwork (Bill of Lading, Liability Waiver, Declaration of Value, Addendum to Cost Estimate, Pre-existing Damages, or similar) for a moving/junk-removal job -- possibly multiple pages. Find every blank-line field meant for a signature, initials, or other short handwritten response (not printed text, not checkboxes), and assess whether each one appears to actually have handwriting present or still looks blank. Look carefully -- pen marks can be faint, and photos may have shadows or glare.

Two exceptions -- exclude these from totalFieldsFound entirely (not counted as blank OR complete):
1. The Addendum to Cost Estimate and Pre-existing Damages pages are not required on every job. If either page type appears in this set, skip it completely -- don't count any of its fields either way.
2. The Shipper Declaration of Value offers three mutually-exclusive valuation options (Option 1, Option 2(a), Option 2(b)). Only the signature/initial line under whichever option was actually selected (marked, circled, or checked) counts as required -- the other two options' lines are supposed to stay blank and must never be counted as incomplete.` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Completeness assessment request failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Assessment failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'assess_completeness');
    if (!toolUseBlock) {
      console.error('Completeness assessment: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the assessment service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Completeness assessment failed:', err.message);
    res.status(500).json({ error: 'Assessment failed: ' + err.message });
  }
});

const SQUARE_JOB_NUMBER_RE = /\b\d{8}\b/;
// Checks reference_id before note: reference_id is Square's dedicated field
// for associating a payment with an external system's record (an 8-digit
// HunkWare job number here), and -- if the checkout flow sets it
// automatically -- is far more reliable than a free-text note that depends
// on whoever's taking the payment remembering to type the job number in.
function extractSquareJobNumber(payment) {
  const refMatch = (payment.reference_id || '').match(SQUARE_JOB_NUMBER_RE);
  if (refMatch) return refMatch[0];
  const noteMatch = (payment.note || '').match(SQUARE_JOB_NUMBER_RE);
  return noteMatch ? noteMatch[0] : null;
}

// Fallback for payments where extractSquareJobNumber found nothing: the
// Order linked via payment.order_id has its own, separate reference_id
// field. Adding a tip via a terminal's tip-collection screen appears to
// finalize the Payment through a step that doesn't carry over whatever was
// set on the Payment directly, while the original Order (created before
// the tip step) still has the job number Square-side. Returns a Map of
// order_id -> jobNumber for every order that actually had one, so callers
// can look up by the order_id already on hand.
async function fetchJobNumbersFromOrders(orderIds, token) {
  const found = new Map();       // order_id -> jobNumber, for orders that had one
  const fetchedOrderIds = new Set(); // order_id -> successfully retrieved, whether or not it had a reference_id
  const uniqueIds = [...new Set(orderIds)].filter(Boolean);
  if (uniqueIds.length === 0) return { found, fetchedOrderIds };
  try {
    for (let i = 0; i < uniqueIds.length; i += 100) { // BatchRetrieveOrders caps at 100 IDs per call
      const chunk = uniqueIds.slice(i, i + 100);
      const orderRes = await fetch('https://connect.squareup.com/v2/orders/batch-retrieve', {
        method: 'POST',
        headers: {
          'Square-Version': '2026-07-15',
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ order_ids: chunk })
      });
      if (!orderRes.ok) {
        console.error('Square order batch-retrieve failed:', orderRes.status, await orderRes.text().catch(() => ''));
        continue; // one failed chunk shouldn't block job numbers found from other chunks
      }
      const orderData = await orderRes.json();
      (orderData.orders || []).forEach(o => {
        fetchedOrderIds.add(o.id);
        const refMatch = (o.reference_id || '').match(SQUARE_JOB_NUMBER_RE);
        if (refMatch) {
          found.set(o.id, refMatch[0]);
          return;
        }
        // No reference_id -- check each line item's name and note, since a
        // custom (non-catalog) line item is often just named or noted with
        // the job number directly at checkout.
        for (const item of (o.line_items || [])) {
          const nameMatch = (item.name || '').match(SQUARE_JOB_NUMBER_RE);
          if (nameMatch) { found.set(o.id, nameMatch[0]); return; }
          const itemNoteMatch = (item.note || '').match(SQUARE_JOB_NUMBER_RE);
          if (itemNoteMatch) { found.set(o.id, itemNoteMatch[0]); return; }
        }
      });
    }
  } catch (err) {
    console.error('Square order lookup failed:', err.message);
  }
  return { found, fetchedOrderIds };
}

// ============ Square: Tip Allocation ============
// Pulls recent Square payments, filters to ones with a tip, and extracts the
// 8-digit job number the crew enters in the payment note at checkout. This
// only ever reads payment data -- it never creates, modifies, refunds, or
// voids anything in Square.
app.get('/api/square-tips', requireAuth, async (req, res) => {
  const token = process.env.SQUARE_ACCESS_TOKEN;
  const locationId = process.env.SQUARE_LOCATION_ID;
  if (!token || !locationId) {
    console.error('Square tips requested but SQUARE_ACCESS_TOKEN/SQUARE_LOCATION_ID is not set.');
    return res.status(500).json({ error: 'Square is not configured on the server yet.' });
  }
  const days = Math.min(Math.max(parseInt(req.query.days) || 60, 1), 365);
  const beginTime = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  try {
    const allPayments = [];
    let cursor = null;
    let pageCount = 0;
    do {
      const params = new URLSearchParams({
        location_id: locationId,
        begin_time: beginTime,
        sort_order: 'DESC'
      });
      if (cursor) params.set('cursor', cursor);

      const sqRes = await fetch(`https://connect.squareup.com/v2/payments?${params.toString()}`, {
        headers: {
          'Square-Version': '2026-07-15',
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      if (!sqRes.ok) {
        const errBody = await sqRes.text().catch(() => '');
        console.error('Square API request failed:', sqRes.status, errBody);
        let detail = '';
        try { detail = ((JSON.parse(errBody).errors || [])[0] || {}).detail || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return res.status(502).json({ error: `Square request failed (HTTP ${sqRes.status})${detail ? ': ' + detail : ''}` });
      }
      const data = await sqRes.json();
      allPayments.push(...(data.payments || []));
      cursor = data.cursor || null;
      pageCount++;
    } while (cursor && pageCount < 20); // safety cap against runaway pagination

    const withTips = allPayments
      // Only COMPLETED payments actually earned revenue -- a connectivity
      // glitch during checkout can leave a FAILED or CANCELED attempt in
      // Square's records (with the tip already entered) alongside the
      // successful retry. Square's own dashboard only shows COMPLETED
      // payments, so this keeps the two views consistent.
      .filter(p => p.status === 'COMPLETED' && p.tip_money && p.tip_money.amount > 0)
      .map(p => {
        const note = p.note || '';
        const jobNumber = extractSquareJobNumber(p);
        const card = p.card_details && p.card_details.card ? p.card_details.card : null;
        return {
          id: p.id,
          date: (p.created_at || '').slice(0, 10),
          tipAmount: p.tip_money.amount / 100,
          totalAmount: p.total_money ? p.total_money.amount / 100 : null,
          note,
          jobNumber,
          orderId: p.order_id || null,
          receiptNumber: p.receipt_number || null,
          cardBrand: card ? card.card_brand : null,
          last4: card ? card.last_4 : null
        };
      });

    // Tips added via a terminal's tip-collection screen tend to finalize
    // the Payment separately from the Order that originally carried the
    // job number, so the Payment's own note/reference_id often comes back
    // empty for exactly these -- falling back to the linked Order's own
    // reference_id recovers the rest.
    const stillMissing = withTips.filter(p => !p.jobNumber && p.orderId);
    if (stillMissing.length > 0) {
      const { found, fetchedOrderIds } = await fetchJobNumbersFromOrders(stillMissing.map(p => p.orderId), token);
      stillMissing.forEach(p => {
        const jobNumber = found.get(p.orderId);
        if (jobNumber) {
          p.jobNumber = jobNumber;
        } else if (fetchedOrderIds.has(p.orderId)) {
          p.debugReason = 'Linked order has no reference_id or line item note with a job number';
        } else {
          p.debugReason = 'Could not retrieve the linked order from Square';
        }
      });
    }
    withTips.forEach(p => {
      if (!p.jobNumber && !p.orderId) p.debugReason = 'Payment has no linked order to check';
      delete p.orderId; // internal only, not part of the response shape
    });

    // Safety net: if the same job number shows an identical tip amount on
    // the same day more than once, it's almost certainly an accidental
    // duplicate charge rather than two real, separate payments (a deposit
    // and a final payment differ in amount and/or date). Keep the first,
    // drop the rest, and log it so it stays auditable rather than silently
    // vanishing.
    const seenDupeKeys = new Set();
    const deduped = [];
    withTips.forEach(p => {
      if (p.jobNumber) {
        const dupeKey = `${p.jobNumber}|${p.date}|${p.tipAmount}`;
        if (seenDupeKeys.has(dupeKey)) {
          console.warn(`Square tips: dropped likely duplicate payment ${p.id} -- job ${p.jobNumber}, ${p.date}, $${p.tipAmount} already seen.`);
          return;
        }
        seenDupeKeys.add(dupeKey);
      }
      deduped.push(p);
    });

    res.json({ payments: deduped });
  } catch (err) {
    console.error('Square tips fetch failed:', err.message);
    res.status(500).json({ error: 'Could not reach Square: ' + err.message });
  }
});

// Every completed payment (not just tipped ones) for Manager Review's Credit
// Card Transactions tab. Read-only, same as the tips endpoint above -- never
// creates, modifies, refunds, or voids anything in Square.
app.get('/api/square-transactions', requireAuth, async (req, res) => {
  const token = process.env.SQUARE_ACCESS_TOKEN;
  const locationId = process.env.SQUARE_LOCATION_ID;
  if (!token || !locationId) {
    console.error('Square transactions requested but SQUARE_ACCESS_TOKEN/SQUARE_LOCATION_ID is not set.');
    return res.status(500).json({ error: 'Square is not configured on the server yet.' });
  }
  const days = Math.min(Math.max(parseInt(req.query.days) || 60, 1), 365);
  const beginTime = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  try {
    const allPayments = [];
    let cursor = null;
    let pageCount = 0;
    do {
      const params = new URLSearchParams({
        location_id: locationId,
        begin_time: beginTime,
        sort_order: 'DESC'
      });
      if (cursor) params.set('cursor', cursor);

      const sqRes = await fetch(`https://connect.squareup.com/v2/payments?${params.toString()}`, {
        headers: {
          'Square-Version': '2026-07-15',
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      if (!sqRes.ok) {
        const errBody = await sqRes.text().catch(() => '');
        console.error('Square API request failed:', sqRes.status, errBody);
        let detail = '';
        try { detail = ((JSON.parse(errBody).errors || [])[0] || {}).detail || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return res.status(502).json({ error: `Square request failed (HTTP ${sqRes.status})${detail ? ': ' + detail : ''}` });
      }
      const data = await sqRes.json();
      allPayments.push(...(data.payments || []));
      cursor = data.cursor || null;
      pageCount++;
    } while (cursor && pageCount < 20);

    // Square's own dashboard only shows COMPLETED payments, so this keeps
    // this view consistent with what a manager sees there.
    const transactions = allPayments
      .filter(p => p.status === 'COMPLETED')
      .map(p => {
        const note = p.note || '';
        const jobNumber = extractSquareJobNumber(p);
        const card = p.card_details && p.card_details.card ? p.card_details.card : null;
        return {
          id: p.id,
          date: (p.created_at || '').slice(0, 10),
          totalAmount: p.total_money ? p.total_money.amount / 100 : null,
          tipAmount: p.tip_money ? p.tip_money.amount / 100 : 0,
          note,
          jobNumber,
          orderId: p.order_id || null,
          receiptNumber: p.receipt_number || null,
          cardBrand: card ? card.card_brand : null,
          last4: card ? card.last_4 : null
        };
      });

    // Same Orders fallback as the tips endpoint above -- tipped
    // transactions are exactly the ones whose Payment-level note/reference_id
    // tends to come back empty, since the tip step finalizes the Payment
    // separately from the Order that originally carried the job number.
    const stillMissingTx = transactions.filter(t => !t.jobNumber && t.orderId);
    if (stillMissingTx.length > 0) {
      const { found, fetchedOrderIds } = await fetchJobNumbersFromOrders(stillMissingTx.map(t => t.orderId), token);
      stillMissingTx.forEach(t => {
        const jobNumber = found.get(t.orderId);
        if (jobNumber) {
          t.jobNumber = jobNumber;
        } else if (fetchedOrderIds.has(t.orderId)) {
          t.debugReason = 'Linked order has no reference_id or line item note with a job number';
        } else {
          t.debugReason = 'Could not retrieve the linked order from Square';
        }
      });
    }
    transactions.forEach(t => {
      if (!t.jobNumber && !t.orderId) t.debugReason = 'Payment has no linked order to check';
      delete t.orderId;
    });

    res.json({ transactions });
  } catch (err) {
    console.error('Square transactions fetch failed:', err.message);
    res.status(500).json({ error: 'Could not reach Square: ' + err.message });
  }
});

// ============ Motive: Truck Locations ============
// Pulls current GPS locations for every company vehicle from Motive's
// fleet API. Read-only -- never creates, updates, or dispatches anything
// in Motive.
// Shared by both the admin (/api/motive-locations) and driver
// (/api/driver/motive-locations) endpoints below -- same underlying data,
// but each endpoint gated by its own, separate auth check so a driver
// session can never be used against any admin-only endpoint, and vice
// versa. Returns { trucks } on success, or { error, status } on failure so
// each caller can respond in its own route.
async function fetchMotiveTruckLocations() {
  const apiKey = process.env.MOTIVE_API_KEY;
  if (!apiKey) {
    console.error('Motive locations requested but MOTIVE_API_KEY is not set.');
    return { error: 'Motive is not configured on the server yet.', status: 500 };
  }

  try {
    const allVehicles = [];
    const perPage = 50;
    let pageNo = 1;
    let hasMore = true;
    while (hasMore && pageNo <= 10) { // safety cap against runaway pagination
      const params = new URLSearchParams({ per_page: String(perPage), page_no: String(pageNo) });
      const mvRes = await fetch(`https://api.gomotive.com/v3/vehicle_locations?${params.toString()}`, {
        headers: {
          'X-Api-Key': apiKey, // Motive's own docs: simple API keys go in this header, NOT Authorization: Bearer
          'X-Metric-Units': 'false', // request speed in mph, not kph
          'Content-Type': 'application/json'
        }
      });
      if (!mvRes.ok) {
        const errBody = await mvRes.text().catch(() => '');
        console.error('Motive API request failed:', mvRes.status, errBody);
        let detail = '';
        try { detail = JSON.parse(errBody).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return { error: `Motive request failed (HTTP ${mvRes.status})${detail ? ': ' + detail : ''}`, status: 502 };
      }
      const data = await mvRes.json();
      const vehicles = data.vehicles || [];
      allVehicles.push(...vehicles);
      hasMore = vehicles.length === perPage; // a full page means there could be more
      pageNo++;
    }

    const trucks = allVehicles
      .map(v => v.vehicle || v) // Motive wraps each entry as { vehicle: {...} }
      .filter(v => v.current_location && typeof v.current_location.lat === 'number' && typeof v.current_location.lon === 'number')
      .map(v => {
        const loc = v.current_location;
        return {
          id: v.id,
          number: v.number || String(v.id),
          make: v.make || null,
          model: v.model || null,
          lat: loc.lat,
          lon: loc.lon,
          locatedAt: loc.located_at || null,
          address: loc.current_location || null,
          city: loc.city || null,
          state: loc.state || null,
          speed: typeof loc.kph === 'number' ? loc.kph : null,
          vehicleState: loc.vehicle_state || null
        };
      });

    return { trucks };
  } catch (err) {
    console.error('Motive locations fetch failed:', err.message);
    return { error: 'Could not reach Motive: ' + err.message, status: 500 };
  }
}

app.get('/api/motive-locations', requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-store'); // live GPS data -- never serve a stale/cached copy
  const result = await fetchMotiveTruckLocations();
  if (result.error) return res.status(result.status).json({ error: result.error });
  res.json({ trucks: result.trucks });
});

// Same data as above, but gated by requireDriverAuth instead of requireAuth
// -- a driver's shared-code session can never satisfy the admin auth check
// (separate Redis namespace entirely), so this exists specifically to let
// the Driver Portal show live truck locations without weakening that
// isolation.
app.get('/api/driver/motive-locations', requireDriverAuth, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const result = await fetchMotiveTruckLocations();
  if (result.error) return res.status(result.status).json({ error: result.error });
  res.json({ trucks: result.trucks });
});

app.get('/api/data/:key', requireAuth, async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) return res.status(400).json({ error: 'Unknown key.' });
  if (!(await checkAdminOnlyKey(req, res, key))) return;
  try {
    const value = await redis.get(key);
    let parsed;
    try { parsed = value === null ? null : JSON.parse(value); }
    catch (parseErr) {
      // Weight ticket photos saved before the fix above were stored as a
      // bare data URI rather than JSON -- hand those back as-is.
      if (typeof value === 'string' && value.startsWith('data:')) parsed = value;
      else throw parseErr;
    }
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
    if (key === 'labor-weeks' || key === 'compliance-drivers' || key === 'roster-manual-additions') {
      await rebuildDriverAuthLookup();
    }
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
    if (key === 'labor-weeks' || key === 'compliance-drivers' || key === 'roster-manual-additions') {
      await rebuildDriverAuthLookup();
    }
    res.json({ key, ok: true });
  } catch (err) {
    console.error(`DELETE /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage delete failed.' });
  }
});

// ============ Damage Claim: public, token-scoped client upload ============
// Deliberately NOT behind requireAuth or requireDriverAuth -- the client has
// no dashboard credentials at all. Each claim gets its own long, random
// token (never a shared code), so one client's link can never touch another
// client's claim. This is the only pair of routes in the whole app meant to
// be reachable by someone who has never logged in.
const DAMAGE_CLAIMS_KEY = 'damage-claims';
const MAX_CLAIM_PHOTOS_PER_SUBMISSION = 15;
const MAX_CLAIM_PHOTO_DATA_URI_LENGTH = 8 * 1024 * 1024; // ~8MB encoded, well under the global 15mb body limit even with several photos
const CLAIM_LINK_VALID_DAYS = 7;

// The 7-day window runs from the most recent time the email was sent --
// resending a claim's email gives the client a fresh 7 days on the same
// link (linkIssuedAt), falling back to when the claim was created.
function isClaimLinkExpired(claim) {
  const issuedAt = claim.linkIssuedAt || claim.createdAt;
  if (!issuedAt) return false;
  const ageMs = Date.now() - new Date(issuedAt).getTime();
  return ageMs > CLAIM_LINK_VALID_DAYS * 24 * 60 * 60 * 1000;
}

app.get('/api/claim/:token', async (req, res) => {
  try {
    const raw = await redis.get(DAMAGE_CLAIMS_KEY);
    const claims = raw ? JSON.parse(raw) : [];
    const claim = claims.find(c => c.token === req.params.token);
    if (!claim) return res.json({ found: false });
    if (isClaimLinkExpired(claim)) return res.json({ found: false, expired: true });
    // Minimal exposure -- just enough to greet the client and confirm the
    // link is for their job, nothing else about the claim or the account.
    res.json({ found: true, jobNumber: claim.jobNumber, clientName: claim.clientName || '' });
  } catch (err) {
    console.error('GET /api/claim/:token failed:', err.message);
    res.status(500).json({ error: 'Could not load this link.' });
  }
});

app.post('/api/claim/:token/photos', async (req, res) => {
  const { photos } = req.body || {};
  if (!Array.isArray(photos) || photos.length === 0) {
    return res.status(400).json({ error: 'No photos were included.' });
  }
  if (photos.length > MAX_CLAIM_PHOTOS_PER_SUBMISSION) {
    return res.status(400).json({ error: `Please upload ${MAX_CLAIM_PHOTOS_PER_SUBMISSION} photos or fewer at a time.` });
  }
  for (const p of photos) {
    if (!p || typeof p.dataUri !== 'string' || !p.dataUri.startsWith('data:image/')) {
      return res.status(400).json({ error: 'One of those files doesn\u2019t look like a photo.' });
    }
    if (p.dataUri.length > MAX_CLAIM_PHOTO_DATA_URI_LENGTH) {
      return res.status(400).json({ error: 'One of those photos is too large. Please use a smaller photo.' });
    }
  }
  try {
    const raw = await redis.get(DAMAGE_CLAIMS_KEY);
    const claims = raw ? JSON.parse(raw) : [];
    const claim = claims.find(c => c.token === req.params.token);
    if (!claim) return res.status(404).json({ error: 'This link could not be found.' });
    if (isClaimLinkExpired(claim)) return res.status(410).json({ error: 'This link has expired. Links are valid for 7 days \u2014 please contact us for a new one.', expired: true });

    const now = new Date().toISOString();
    claim.photos = claim.photos || [];
    for (const p of photos) {
      const photoId = crypto.randomBytes(8).toString('hex');
      await redis.set(`damage-claim-photo-${claim.id}-${photoId}`, JSON.stringify(p.dataUri));
      claim.photos.push({ id: photoId, filename: p.filename || 'photo.jpg', uploadedAt: now });
    }
    // Preserves the first-upload timestamp even if the client comes back
    // later and adds more -- that's what actually drives the admin alert.
    if (!claim.photosUploadedAt) claim.photosUploadedAt = now;

    await redis.set(DAMAGE_CLAIMS_KEY, JSON.stringify(claims));
    res.json({ ok: true, count: photos.length });
  } catch (err) {
    console.error('POST /api/claim/:token/photos failed:', err.message);
    res.status(500).json({ error: 'Could not save those photos \u2014 check your connection and try again.' });
  }
});

const PORT = process.env.PORT || 3000;

// Temporary diagnostic endpoint -- groups every Redis key by a normalized
// prefix (trailing IDs/timestamps stripped) and sums actual memory usage
// per group, so the real biggest consumers can be identified directly
// instead of guessed at from code structure. Read-only; deletes nothing.
app.get('/api/admin/storage-audit', requireAuth, async (req, res) => {
  try {
    const groups = {}; // normalized prefix -> { count, bytes }
    let cursor = '0';
    let totalBytes = 0;
    let totalKeys = 0;
    do {
      const [nextCursor, keys] = await redis.scan(cursor, 'COUNT', 500);
      cursor = nextCursor;
      for (const key of keys) {
        let bytes = 0;
        try {
          bytes = await redis.memory('USAGE', key);
          bytes = typeof bytes === 'number' ? bytes : 0;
        } catch (e) {
          // MEMORY USAGE unsupported on this Redis build -- fall back to
          // raw string length as a reasonable approximation.
          try { bytes = await redis.strlen(key); } catch (e2) { bytes = 0; }
        }
        // Strip a trailing id/timestamp/hash-looking segment so keys like
        // "paperwork-upload-upload_123_456" and "compliance-eod-photo-eod_1"
        // roll up into one group instead of one row per record.
        const normalized = key.replace(/[-_](?:[A-Za-z0-9]{6,}|\d+)$/, '').replace(/[-_](?:[A-Za-z0-9]{6,}|\d+)$/, '');
        if (!groups[normalized]) groups[normalized] = { count: 0, bytes: 0 };
        groups[normalized].count++;
        groups[normalized].bytes += bytes;
        totalBytes += bytes;
        totalKeys++;
      }
    } while (cursor !== '0');

    const breakdown = Object.entries(groups)
      .map(([prefix, v]) => ({ prefix, count: v.count, bytes: v.bytes, mb: +(v.bytes / (1024*1024)).toFixed(2) }))
      .sort((a, b) => b.bytes - a.bytes);

    // Growth analysis: unlike the breakdown above (a snapshot), this looks
    // at the two categories that grow continuously and can't be pruned
    // below their legal floor -- Move paperwork (180 days) and PTI/EOD
    // photos (90 days, longer if an issue is still open). Real record
    // dates and measured per-record sizes, not an estimate.
    async function analyzeGrowth(listKey, dateField, blobKeyFn, retentionDays){
      const list = await redis.get(listKey);
      const records = list ? JSON.parse(list) : [];
      const withDates = records.filter(r => r[dateField]);
      if (withDates.length < 2) return { recordCount: records.length, insufficientData: true };

      let totalBytes = 0;
      for (const r of records) {
        const blobKey = blobKeyFn(r);
        if (!blobKey) continue;
        try {
          const b = await redis.memory('USAGE', blobKey);
          if (typeof b === 'number') totalBytes += b;
        } catch (e) { /* record may have no photo/file -- skip */ }
      }

      const dates = withDates.map(r => new Date(r[dateField]).getTime()).filter(t => !isNaN(t));
      const oldest = Math.min(...dates);
      const newest = Math.max(...dates);
      const daySpan = Math.max(1, (newest - oldest) / (1000*60*60*24));

      const bytesPerDay = totalBytes / daySpan;
      const recordsPerDay = records.length / daySpan;
      const steadyStateBytes = bytesPerDay * retentionDays;

      return {
        recordCount: records.length,
        currentBytes: totalBytes,
        currentMB: +(totalBytes / (1024*1024)).toFixed(2),
        daySpanObserved: +daySpan.toFixed(1),
        mbPerDay: +(bytesPerDay / (1024*1024)).toFixed(3),
        recordsPerDay: +recordsPerDay.toFixed(2),
        retentionDays,
        projectedSteadyStateMB: +(steadyStateBytes / (1024*1024)).toFixed(1)
      };
    }

    const paperworkGrowth = await analyzeGrowth(
      'paperwork-uploads', 'uploadedAt',
      r => 'paperwork-upload-' + r.id,
      180
    );
    const eodGrowth = await analyzeGrowth(
      'compliance-eod-inspections', 'date',
      r => r.backPhotoKey || null,
      90
    );
    const ptiGrowth = await analyzeGrowth(
      'compliance-pretrip-inspections', 'date',
      r => r.backPhotoKey || null,
      90
    );

    res.json({
      totalKeys,
      totalBytes,
      totalMB: +(totalBytes / (1024*1024)).toFixed(2),
      breakdown,
      growth: {
        paperworkUploads: paperworkGrowth,
        eodPhotos: eodGrowth,
        ptiPhotos: ptiGrowth
      }
    });
  } catch (err) {
    console.error('Storage audit failed:', err.message);
    res.status(500).json({ error: 'Storage audit failed: ' + err.message });
  }
});

app.listen(PORT, async () => {
  console.log(`${LOCATION.name} dashboard backend listening on port ${PORT}`);
  console.log(process.env.LOB_API_KEY
    ? `LOB_API_KEY is set (starts with "${process.env.LOB_API_KEY.slice(0, 5)}...")`
    : 'LOB_API_KEY is NOT set \u2014 zip lookup will not work until it is added.');
  console.log(process.env.ANTHROPIC_API_KEY
    ? `ANTHROPIC_API_KEY is set (starts with "${process.env.ANTHROPIC_API_KEY.slice(0, 8)}...")`
    : 'ANTHROPIC_API_KEY is NOT set \u2014 screenshot address extraction will not work until it is added.');
  console.log((process.env.SQUARE_ACCESS_TOKEN && process.env.SQUARE_LOCATION_ID)
    ? `SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID are set (location starts with "${process.env.SQUARE_LOCATION_ID.slice(0, 4)}...")`
    : 'SQUARE_ACCESS_TOKEN and/or SQUARE_LOCATION_ID is NOT set \u2014 tip allocation will not work until both are added.');
  console.log(process.env.MOTIVE_API_KEY
    ? `MOTIVE_API_KEY is set (starts with "${process.env.MOTIVE_API_KEY.slice(0, 6)}...")`
    : 'MOTIVE_API_KEY is NOT set \u2014 truck locations will not work until it is added.');
  await ensureUsersSeeded();
  // Always re-sync the driver login lookup against current payroll and
  // Compliance-tile data on boot -- not just on the next write to either
  // source. Without this, a deploy that changes the matching rules (e.g.
  // adding the active-driver cross-check) would leave whatever the OLD
  // rules had already computed sitting untouched in Redis until someone
  // happened to re-save one of the two source keys.
  await rebuildDriverAuthLookup();
});
