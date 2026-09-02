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
  'damage-claims'
]);
const ALLOWED_KEY_PREFIXES = ['fleet-invoice-', 'paperwork-job-link-', 'paperwork-upload-', 'compliance-doc-', 'settings-config-doc-', 'marketing-material-doc-', 'compliance-pti-photo-', 'compliance-eod-photo-', 'damage-claim-photo-'];

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
app.get('/api/driver/roster', requireDriverAuth, async (req, res) => {
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
  const { truckId, truckNickname, driverName, date, odometer, checklist, additionalNotes, backPhoto } = req.body || {};
  if (!truckId || !driverName || !Array.isArray(checklist) || checklist.length === 0) {
    return res.status(400).json({ error: 'Truck, driver name, and checklist are required.' });
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
app.get('/api/driver/materials-items', requireDriverAuth, async (req, res) => {
  try {
    const raw = await redis.get('materials-items');
    const items = raw ? JSON.parse(raw) : [];
    res.json({ items: items.map(i => ({ id: i.id, supplierItemNumber: i.supplierItemNumber, description: i.description, nickname: i.nickname })) });
  } catch (err) {
    console.error('Driver materials list failed:', err.message);
    res.status(500).json({ error: 'Could not load materials.' });
  }
});

// Lets the driver portal check -- before a driver fills out the whole
// Pre-Trip Inspection form -- whether today's Materials Checkout is already
// on file, so it can redirect them proactively instead of only rejecting
// the PTI submission afterward. The actual enforcement lives in
// /api/driver/pretrip itself; this is just for a better prompt.
app.get('/api/driver/materials-checkout-status', requireDriverAuth, async (req, res) => {
  const driverName = (req.query.driverName || '').toString().trim();
  const date = (req.query.date || new Date().toISOString().slice(0, 10)).toString();
  if (!driverName) return res.status(400).json({ error: 'Driver name is required.' });
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

app.post('/api/driver/materials-checkout', requireDriverAuth, async (req, res) => {
  const { driverName, jobNumbers, items, date } = req.body || {};
  if (!driverName || typeof driverName !== 'string') {
    return res.status(400).json({ error: 'Driver name is required.' });
  }
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

app.post('/api/driver/eod-inspection', requireDriverAuth, async (req, res) => {
  const { truckId, truckNickname, driverName, date, jobNumbers, returnedItems, backPhoto, additionalNotes } = req.body || {};
  if (!truckId || !driverName) {
    return res.status(400).json({ error: 'Truck and driver name are required.' });
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
      submittedAt: new Date().toISOString()
    });

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

// Captain leaderboard for the driver portal. Computes rankings server-side
// from the same admin-side records Captain Metrics uses, and returns only
// the aggregated results -- drivers never get raw access to
// compliance-pretrip-inspections, paperwork-job-archive, or paperwork-uploads
// directly (those stay behind requireAuth, not requireDriverAuth).
//
// Response shape is a generic list of categories so new metrics can be added
// here later without the driver-portal frontend needing any changes -- it
// just renders whatever categories come back.
app.get('/api/driver/leaderboard', requireDriverAuth, async (req, res) => {
  try {
    const [archiveRaw, ptiRaw, uploadsRaw, eodRaw] = await Promise.all([
      redis.get('paperwork-job-archive'),
      redis.get('compliance-pretrip-inspections'),
      redis.get('paperwork-uploads'),
      redis.get('compliance-eod-inspections')
    ]);
    const archive = archiveRaw ? JSON.parse(archiveRaw) : [];
    const ptiRecords = ptiRaw ? JSON.parse(ptiRaw) : [];
    const uploads = uploadsRaw ? JSON.parse(uploadsRaw) : [];
    const eodRecords = eodRaw ? JSON.parse(eodRaw) : [];

    const categories = [];

    // ---- Pre-Trip Inspection Compliance, last 30 complete days ----
    const today = new Date();
    const todayStr = today.toISOString().slice(0, 10);
    const windowStart = new Date(today);
    windowStart.setDate(windowStart.getDate() - 30);
    const windowStartStr = windowStart.toISOString().slice(0, 10);

    const relevantJobs = archive.filter(j =>
      j.captainName && j.assignmentDate &&
      j.assignmentDate < todayStr && j.assignmentDate >= windowStartStr
    );
    const assignedDaysByCaptain = {}; // captain -> Set of days assigned
    relevantJobs.forEach(j => {
      if (!assignedDaysByCaptain[j.captainName]) assignedDaysByCaptain[j.captainName] = new Set();
      assignedDaysByCaptain[j.captainName].add(j.assignmentDate);
    });
    const ptiEntries = Object.keys(assignedDaysByCaptain).map(captain => {
      const days = [...assignedDaysByCaptain[captain]];
      const compliantDays = days.filter(day => ptiRecords.some(p => p.driverName === captain && p.date === day)).length;
      return {
        name: captain,
        value: days.length > 0 ? Math.round((compliantDays / days.length) * 100) : 0,
        detail: `${compliantDays} of ${days.length} day${days.length === 1 ? '' : 's'}`
      };
    }).sort((a, b) => b.value - a.value);
    if (ptiEntries.length > 0) {
      categories.push({ key: 'pretrip', title: 'Pre-Trip Inspection Compliance', entries: ptiEntries });
    }

    // ---- End of Day Inspection Compliance, same day-window as Pre-Trip ----
    // Only counts days that already have a Pre-Trip Inspection on file --
    // a day nobody started with a PTI has nothing to "end" for compliance
    // purposes here.
    const eodEntries = Object.keys(assignedDaysByCaptain).map(captain => {
      const ptiDays = [...assignedDaysByCaptain[captain]].filter(day => ptiRecords.some(p => p.driverName === captain && p.date === day));
      const compliantDays = ptiDays.filter(day => eodRecords.some(e => e.driverName === captain && e.date === day)).length;
      return {
        name: captain,
        value: ptiDays.length > 0 ? Math.round((compliantDays / ptiDays.length) * 100) : 0,
        detail: `${compliantDays} of ${ptiDays.length} day${ptiDays.length === 1 ? '' : 's'}`
      };
    }).filter(e => e.detail !== '0 of 0 days').sort((a, b) => b.value - a.value);
    if (eodEntries.length > 0) {
      categories.push({ key: 'eod', title: 'End of Day Inspection Compliance', entries: eodEntries });
    }

    // ---- Completed Paperwork Quality, uploads from the last 30 days ----
    const captainByJob = {};
    archive.forEach(j => { if (j.jobNumber && j.captainName) captainByJob[j.jobNumber] = j.captainName; });
    const windowStartIso = windowStart.toISOString();
    const recentAssessed = uploads.filter(u =>
      typeof u.completenessPercent === 'number' && u.uploadedAt && u.uploadedAt >= windowStartIso
    );
    const byCaptainCompleteness = {};
    recentAssessed.forEach(u => {
      const captain = captainByJob[u.jobNumber];
      if (!captain) return; // no Captain on file for this job -- excluded from the leaderboard, not attributable
      if (!byCaptainCompleteness[captain]) byCaptainCompleteness[captain] = [];
      byCaptainCompleteness[captain].push(u.completenessPercent);
    });
    const qualityEntries = Object.keys(byCaptainCompleteness).map(captain => {
      const scores = byCaptainCompleteness[captain];
      const avg = scores.reduce((s, v) => s + v, 0) / scores.length;
      return { name: captain, value: Math.round(avg), detail: `${scores.length} job${scores.length === 1 ? '' : 's'}` };
    }).sort((a, b) => b.value - a.value);
    if (qualityEntries.length > 0) {
      categories.push({ key: 'completeness', title: 'Completed Paperwork Quality', entries: qualityEntries });
    }

    res.json({ categories });
  } catch (err) {
    console.error('Driver leaderboard fetch failed:', err.message);
    res.status(500).json({ error: 'Could not load leaderboard.' });
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
    emailBodyTemplate: 'Hi there,\n\nWe\u2019re sorry to hear about the damage during your recent move. To help us process your claim quickly, please upload photos of the damage using the secure link below:\n\n{{link}}\n\nOnce we receive your photos, our team will review your claim and follow up with next steps.\n\nThank you for your patience.\n\n- The College Hunks Team'
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
const EXTRACT_CLIENT_INVOICE_TOOL = {
  name: 'extract_client_invoice',
  description: 'Extract the balance due and billed line items from a HunkWare completed job invoice.',
  input_schema: {
    type: 'object',
    properties: {
      balanceDue: { type: 'number', description: 'The Balance Due amount shown on the invoice, in dollars (e.g. 0, 42.50). If the invoice shows the balance is fully paid / $0.00, report 0.' },
      lineItems: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            description: { type: 'string', description: 'The line item description exactly as printed, e.g. "Small Box", "Shrink Wrap".' },
            quantity: { type: 'number', description: 'The quantity billed for this line.' }
          },
          required: ['description', 'quantity']
        },
        description: 'Every billed line item that looks like a packing/moving material (boxes, tape, wrap, etc.) -- not labor, mileage, or other service fees.'
      },
      confident: { type: 'boolean', description: 'True if the Balance Due and line items were read clearly. False if the invoice was blurry, cut off, or the Balance Due wasn\u2019t clearly shown.' }
    },
    required: ['balanceDue', 'lineItems', 'confident']
  }
};

app.post('/api/admin/extract-client-invoice', requireAuth, async (req, res) => {
  const { images } = req.body || {};
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'At least one image is required.' });
  }
  if (images.length > 24) {
    return res.status(400).json({ error: 'Please split this into invoices of 24 pages or fewer.' });
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
        max_tokens: 2048,
        tools: [EXTRACT_CLIENT_INVOICE_TOOL],
        tool_choice: { type: 'tool', name: 'extract_client_invoice' },
        messages: [{
          role: 'user',
          content: [
            ...imageBlocks,
            { type: 'text', text: `These are ${imageBlocks.length} page(s) of a HunkWare completed job invoice for a moving/junk removal client. Find the Balance Due amount, and every billed packing/moving material line item (boxes, tape, wrap, etc. -- not labor or mileage).` }
          ]
        }]
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.text().catch(() => '');
      console.error('Client invoice extraction failed:', anthropicRes.status, errBody);
      let detail = '';
      try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
      return res.status(502).json({ error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` });
    }

    const data = await anthropicRes.json();
    const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_client_invoice');
    if (!toolUseBlock) {
      console.error('Client invoice extraction: no tool_use block. stop_reason=', data.stop_reason);
      return res.status(502).json({ error: 'Could not read a structured response from the extraction service.' });
    }
    res.json(toolUseBlock.input);
  } catch (err) {
    console.error('Client invoice extraction failed:', err.message);
    res.status(500).json({ error: 'Extraction failed: ' + err.message });
  }
});

// ============ Dashboard Tile Order ============
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
function computeRosterNames(weeks, manualAdditions){
  const sorted = [...(weeks || [])].sort((a, b) => (b.weekStart || '').localeCompare(a.weekStart || ''));
  const recentTwo = sorted.slice(0, 2);
  const fromPayroll = recentTwo.flatMap(w => (w.employees || []).map(e => e.name)).filter(Boolean);
  const combined = [...fromPayroll, ...(manualAdditions || [])];
  const seen = new Set();
  const deduped = [];
  combined.forEach(name => {
    const key = name.trim().toLowerCase();
    if(!key || seen.has(key)) return;
    seen.add(key);
    deduped.push(name.trim());
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
            jobNumber: { type: 'string', description: 'The Job ID / Job Number as printed on the work order. Empty string if not found.' },
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
              description: 'Read directly from the work order\u2019s own "Type:" field near the top of the document (e.g. "Type: JOB" or "Type: ESTIMATE") -- not inferred from anything else on the page. "estimate" means this document is only a price estimate that hasn\u2019t been booked as an actual job, and should never get paperwork generated for it. "unclear" if no such Type field is present or legible -- do not guess "job" or "estimate" without seeing that field.'
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
    const MAX_PAGES_PER_FILE = 24; // roomy enough for ~8 combined work orders at ~3 pages each
    for (const blocks of parsedFiles) {
      if (blocks.length > MAX_PAGES_PER_FILE) {
        return res.status(400).json({ error: `One of the files has more than ${MAX_PAGES_PER_FILE} pages -- please split it into smaller files.` });
      }
    }

    async function runFile(pageBlocks, fileIndex){
      if (pageBlocks.length === 0) return { fileIndex, documents: [] };
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
        console.error(`Work order extraction file ${fileIndex} failed:`, anthropicRes.status, errBody);
        let detail = '';
        try { detail = (JSON.parse(errBody).error || {}).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return { fileIndex, error: `Extraction failed (HTTP ${anthropicRes.status})${detail ? ': ' + detail : ''}` };
      }

      const data = await anthropicRes.json();
      const toolUseBlock = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'extract_work_orders');
      if (!toolUseBlock) {
        console.error(`Work order extraction file ${fileIndex}: no tool_use block. stop_reason=`, data.stop_reason);
        return { fileIndex, error: 'Could not read a structured response from the extraction service.' };
      }
      const documents = Array.isArray(toolUseBlock.input.documents) ? toolUseBlock.input.documents : [];
      return { fileIndex, documents };
    }

    const fileResults = await Promise.all(parsedFiles.map((blocks, i) => runFile(blocks, i)));
    const allDocuments = [];
    const fileErrors = [];
    fileResults.forEach(r => {
      if (r.error) fileErrors.push(r.error);
      else r.documents.forEach(d => allDocuments.push({ ...d, fileIndex: r.fileIndex }));
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
  description: 'Extract the job number and client name from a completed moving-job paperwork scan.',
  input_schema: {
    type: 'object',
    properties: {
      jobNumber: { type: 'string', description: 'The job number for this document (often an 8-digit HunkWare job number). It may appear on any page -- check all of them, not just the first. Empty string if not found or not legible on any page.' },
      clientName: { type: 'string', description: 'The client/customer\u2019s name, if visible anywhere on any page (e.g. next to "Name:" on a Bill of Lading or Liability Waiver, or a signature). Empty string if not found.' },
      confident: { type: 'boolean', description: 'True if the job number was read clearly. False if every page was too blurry, cut off, or no job number was visible anywhere.' }
    },
    required: ['jobNumber', 'clientName', 'confident']
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
              { type: 'text', text: `These are ${imageBlocks.length} page(s), in order, from a single scanned completed-paperwork document from a moving company (Bill of Lading, Liability Waiver, and related signed forms for one job). Find the job number -- check every page, since it isn't always on the first one (for example, if a copy of the original work order was printed ahead of the signed forms). Also note the client's name if it's visible anywhere.` }
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
  if (images.length > 24) {
    return res.status(400).json({ error: 'Please split this into invoices of 24 pages or fewer.' });
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

    const JOB_NUMBER_RE = /\b\d{8}\b/;
    const withTips = allPayments
      // Only COMPLETED payments actually earned revenue -- a connectivity
      // glitch during checkout can leave a FAILED or CANCELED attempt in
      // Square's records (with the tip already entered) alongside the
      // successful retry. Square's own dashboard only shows COMPLETED
      // payments, so this keeps the two views consistent.
      .filter(p => p.status === 'COMPLETED' && p.tip_money && p.tip_money.amount > 0)
      .map(p => {
        const note = p.note || '';
        const match = note.match(JOB_NUMBER_RE);
        const card = p.card_details && p.card_details.card ? p.card_details.card : null;
        return {
          id: p.id,
          date: (p.created_at || '').slice(0, 10),
          tipAmount: p.tip_money.amount / 100,
          totalAmount: p.total_money ? p.total_money.amount / 100 : null,
          note,
          jobNumber: match ? match[0] : null,
          receiptNumber: p.receipt_number || null,
          cardBrand: card ? card.card_brand : null,
          last4: card ? card.last_4 : null
        };
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

// ============ Motive: Truck Locations ============
// Pulls current GPS locations for every company vehicle from Motive's
// fleet API. Read-only -- never creates, updates, or dispatches anything
// in Motive.
app.get('/api/motive-locations', requireAuth, async (req, res) => {
  const apiKey = process.env.MOTIVE_API_KEY;
  if (!apiKey) {
    console.error('Motive locations requested but MOTIVE_API_KEY is not set.');
    return res.status(500).json({ error: 'Motive is not configured on the server yet.' });
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
          'Authorization': `Bearer ${apiKey}`,
          'X-Metric-Units': 'false', // request speed in mph, not kph
          'Content-Type': 'application/json'
        }
      });
      if (!mvRes.ok) {
        const errBody = await mvRes.text().catch(() => '');
        console.error('Motive API request failed:', mvRes.status, errBody);
        let detail = '';
        try { detail = JSON.parse(errBody).message || ''; } catch (e) { detail = errBody.slice(0, 200); }
        return res.status(502).json({ error: `Motive request failed (HTTP ${mvRes.status})${detail ? ': ' + detail : ''}` });
      }
      const data = await mvRes.json();
      const vehicles = data.vehicles || [];
      allVehicles.push(...vehicles);
      hasMore = vehicles.length === perPage; // a full page means there could be more
      pageNo++;
    }

    const trucks = allVehicles
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

    res.json({ trucks });
  } catch (err) {
    console.error('Motive locations fetch failed:', err.message);
    res.status(500).json({ error: 'Could not reach Motive: ' + err.message });
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

// ============ Damage Claim: public, token-scoped client upload ============
// Deliberately NOT behind requireAuth or requireDriverAuth -- the client has
// no dashboard credentials at all. Each claim gets its own long, random
// token (never a shared code), so one client's link can never touch another
// client's claim. This is the only pair of routes in the whole app meant to
// be reachable by someone who has never logged in.
const DAMAGE_CLAIMS_KEY = 'damage-claims';
const MAX_CLAIM_PHOTOS_PER_SUBMISSION = 15;
const MAX_CLAIM_PHOTO_DATA_URI_LENGTH = 8 * 1024 * 1024; // ~8MB encoded, well under the global 15mb body limit even with several photos

app.get('/api/claim/:token', async (req, res) => {
  try {
    const raw = await redis.get(DAMAGE_CLAIMS_KEY);
    const claims = raw ? JSON.parse(raw) : [];
    const claim = claims.find(c => c.token === req.params.token);
    if (!claim) return res.json({ found: false });
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
    if (!claim) return res.status(404).json({ error: 'This link could not be found or may have expired.' });

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
app.listen(PORT, async () => {
  console.log(`Henson dashboard backend listening on port ${PORT}`);
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
});
