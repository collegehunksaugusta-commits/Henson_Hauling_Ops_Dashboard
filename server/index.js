const express = require('express');
const cors = require('cors');
const Redis = require('ioredis');

const app = express();
app.use(express.json({ limit: '15mb' }));

// Allow requests from the dashboard's static site. Kept permissive since this
// is an internal two-person tool with no sensitive/financial data beyond
// client contact info and payroll aggregates already visible in the app.
app.use(cors());

const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_KEY_VALUE_URL;
if (!REDIS_URL) {
  console.error('FATAL: No REDIS_URL / RENDER_KEY_VALUE_URL environment variable set.');
  process.exit(1);
}
const redis = new Redis(REDIS_URL);

redis.on('error', (err) => {
  console.error('Redis connection error:', err.message);
});

// Whitelist of allowed keys -- prevents arbitrary key injection from the client.
const ALLOWED_KEYS = new Set([
  'labor-weeks',
  'ldEstimateClients',
  'labor-employee-rates',
  'labor-last-admin-gross',
  'fleet-trucks',
  'fleet-maintenance-logs',
  'paperwork-signed-records',
  'attendance-records',
  'paperwork-uploads'
]);
// Invoice files and other growing per-item data get their own key per parent
// record (e.g. fleet-invoice-<logId>) so a growing library never bloats one blob.
const ALLOWED_KEY_PREFIXES = ['fleet-invoice-', 'paperwork-job-link-', 'paperwork-upload-'];

function isAllowedKey(key) {
  if (ALLOWED_KEYS.has(key)) return true;
  return ALLOWED_KEY_PREFIXES.some(prefix => key.startsWith(prefix));
}

app.get('/health', async (req, res) => {
  try {
    await redis.ping();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/data/:key', async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) {
    return res.status(400).json({ error: 'Unknown key.' });
  }
  try {
    const value = await redis.get(key);
    res.json({ key, value: value === null ? null : JSON.parse(value) });
  } catch (err) {
    console.error(`GET /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage read failed.' });
  }
});

app.put('/api/data/:key', async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) {
    return res.status(400).json({ error: 'Unknown key.' });
  }
  try {
    const serialized = JSON.stringify(req.body.value);
    await redis.set(key, serialized);
    res.json({ key, ok: true });
  } catch (err) {
    console.error(`PUT /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage write failed.' });
  }
});

app.delete('/api/data/:key', async (req, res) => {
  const { key } = req.params;
  if (!isAllowedKey(key)) {
    return res.status(400).json({ error: 'Unknown key.' });
  }
  try {
    await redis.del(key);
    res.json({ key, ok: true });
  } catch (err) {
    console.error(`DELETE /api/data/${key} failed:`, err.message);
    res.status(500).json({ error: 'Storage delete failed.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Henson dashboard backend listening on port ${PORT}`);
});
