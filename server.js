'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 8080;
const DAYLOG_PASSWORD = process.env.DAYLOG_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || (process.env.WEBSITE_SITE_NAME ? '/home/data/daylog' : path.join(__dirname, 'data'));
const DATA_FILE = process.env.DATA_FILE || path.join(DATA_DIR, 'appointments.json');
const DAYLOG_TIMEZONE = process.env.DAYLOG_TIMEZONE || 'America/Los_Angeles';
const RETENTION_BACKUPS = process.env.RETENTION_BACKUPS !== 'false';
const COOKIE_NAME = 'daylog_session';
const COOKIE_MAX_AGE_MS = 12 * 60 * 60 * 1000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ appointments: [], updatedAt: null, retention: { timeZone: DAYLOG_TIMEZONE } }, null, 2));

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '8mb' }));
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const ALLOWED_IPS = String(process.env.ALLOWED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
function ipToLong(ip) {
  const clean = String(ip || '').replace(/^::ffff:/, '').trim();
  const parts = clean.split('.').map(n => Number(n));
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}
function matchesCidr(ip, rule) {
  const cleanRule = String(rule || '').trim();
  if (!cleanRule) return false;
  const client = ipToLong(ip);
  if (client === null) return false;
  if (!cleanRule.includes('/')) return client === ipToLong(cleanRule);
  const [baseIp, bitsRaw] = cleanRule.split('/');
  const base = ipToLong(baseIp);
  const bits = Number(bitsRaw);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (client & mask) === (base & mask);
}
function clientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return (forwarded || req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}
function requireAllowedIp(req, res, next) {
  if (!ALLOWED_IPS.length) return next();
  const ip = clientIp(req);
  if (ALLOWED_IPS.some(rule => matchesCidr(ip, rule))) return next();
  if (req.path === '/healthz') return res.status(403).json({ ok: false, error: 'ip_not_allowed', ip });
  return res.status(403).type('html').send('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access restricted</title><style>body{font-family:Inter,Segoe UI,system-ui,sans-serif;background:#f6faf9;display:grid;place-items:center;min-height:100vh;color:#12242f}.card{max-width:520px;background:#fff;border:1px solid #dbeae7;border-radius:24px;padding:28px;box-shadow:0 18px 48px rgba(33,73,87,.12)}h1{margin:0 0 8px}p{color:#607583;line-height:1.5}.ip{font-family:ui-monospace,Consolas,monospace;background:#f0f7f5;border-radius:10px;padding:8px 10px;display:inline-block}</style></head><body><main class="card"><h1>Access restricted</h1><p>This workspace is limited to approved clinic/VPN networks.</p><p>Detected IP: <span class="ip">' + ip + '</span></p></main></body></html>');
}
app.use(requireAllowedIp);

const loginLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false });

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function makeSession() {
  const payload = Buffer.from(JSON.stringify({ iat: Date.now(), nonce: crypto.randomBytes(12).toString('hex') })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function isValidSession(token) {
  if (!token || !token.includes('.')) return false;
  const [payload, sig] = token.split('.');
  if (!safeEqual(sign(payload), sig)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return Date.now() - Number(data.iat || 0) < COOKIE_MAX_AGE_MS;
  } catch {
    return false;
  }
}

function requireAuth(req, res, next) {
  if (!DAYLOG_PASSWORD) {
    return res.status(503).send('DAYLOG_PASSWORD is not configured in Azure App Settings.');
  }
  if (isValidSession(req.cookies[COOKIE_NAME])) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'locked' });
  return res.redirect('/login');
}

function readStore() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { appointments: [], updatedAt: null };
  }
}

function localISODate(date = new Date(), timeZone = DAYLOG_TIMEZONE) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(date).reduce((acc, part) => {
    if (part.type !== 'literal') acc[part.type] = part.value;
    return acc;
  }, {});
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function backupStore(store, reason) {
  if (!RETENTION_BACKUPS) return null;
  const backupName = `appointments-${reason}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  fs.writeFileSync(path.join(DATA_DIR, backupName), JSON.stringify(store, null, 2));
  return backupName;
}

function applyRetention(store, options = {}) {
  const today = localISODate();
  const appointments = Array.isArray(store.appointments) ? store.appointments : [];
  const kept = appointments.filter(item => {
    const date = String(item && item.date ? item.date : '').slice(0, 10);
    // Keep undated rows instead of deleting them silently. Staff can correct or clear them.
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return true;
    // This keeps today and future dates, so tomorrow can be preloaded before midnight.
    return date >= today;
  });
  const removed = appointments.length - kept.length;
  if (!removed && store.retention && store.retention.today === today) return { store, changed: false, removed: 0 };

  const next = {
    ...store,
    appointments: kept,
    retention: {
      ...(store.retention || {}),
      today,
      timeZone: DAYLOG_TIMEZONE,
      keepRule: 'keeps today and future appointments; removes past-dated appointments after local midnight',
      lastCheckedAt: new Date().toISOString(),
      lastRemovedCount: removed
    }
  };
  if (removed && options.backupBeforePurge) {
    next.retention.lastPurgeBackup = backupStore(store, 'pre-purge');
  }
  return { store: next, changed: true, removed };
}

function writeRawStore(clean) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(clean, null, 2));
  fs.renameSync(tmp, DATA_FILE);
  return clean;
}

function itemKey(item) {
  return String((item && (item.uid || item.id)) || '').trim();
}

function newerOrEqual(incoming, existing) {
  const inc = Date.parse(incoming && incoming.lastUpdated || '') || 0;
  const old = Date.parse(existing && existing.lastUpdated || '') || 0;
  return inc >= old;
}

function mergeAppointments(incomingAppointments) {
  const current = readCurrentStore();
  const byKey = new Map();
  const push = (item) => {
    const key = itemKey(item);
    if (!key) return;
    byKey.set(key, item);
  };
  (Array.isArray(current.appointments) ? current.appointments : []).forEach(push);

  for (const incoming of incomingAppointments) {
    const key = itemKey(incoming);
    if (!key) continue;
    const existing = byKey.get(key);
    if (!existing || newerOrEqual(incoming, existing)) {
      byKey.set(key, { ...(existing || {}), ...incoming });
    }
  }
  return [...byKey.values()];
}

function writeStore(payload) {
  const incomingRows = Array.isArray(payload.appointments) ? payload.appointments : [];
  const incoming = {
    appointments: mergeAppointments(incomingRows),
    updatedAt: new Date().toISOString(),
    retention: {
      timeZone: DAYLOG_TIMEZONE,
      today: localISODate(),
      keepRule: 'keeps today and future appointments; removes past-dated appointments after local midnight'
    }
  };
  const { store: clean } = applyRetention(incoming, { backupBeforePurge: false });
  return writeRawStore(clean);
}

function readCurrentStore() {
  const store = readStore();
  const { store: retained, changed } = applyRetention(store, { backupBeforePurge: true });
  if (changed) return writeRawStore({ ...retained, updatedAt: store.updatedAt || null });
  return retained;
}

function purgePastAppointments() {
  const store = readStore();
  const { store: retained, changed, removed } = applyRetention(store, { backupBeforePurge: true });
  if (changed) {
    writeRawStore({ ...retained, updatedAt: store.updatedAt || null });
    if (removed) console.log(`Retention purge removed ${removed} past appointment(s). Keeping ${retained.appointments.length}.`);
  }
}

app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.get('/login', (req, res) => {
  if (isValidSession(req.cookies[COOKIE_NAME])) return res.redirect('/');
  res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unlock Day Log</title><style>
    :root{font-family:Inter,Segoe UI,system-ui,sans-serif;color:#12242f;background:#f4fbfa}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at top left,#dff7ef,transparent 35%),linear-gradient(135deg,#f8ffff,#eef8f6)}.card{width:min(430px,92vw);background:#fff;border:1px solid #dbeae7;border-radius:28px;box-shadow:0 20px 50px rgba(33,73,87,.12);padding:30px}.brand{display:inline-flex;gap:10px;align-items:center;background:#eaf7f4;border:1px solid #c8ddd8;border-radius:999px;padding:8px 12px;color:#0a6d67;font-weight:800;font-size:13px}h1{font-size:28px;margin:18px 0 8px}.muted{color:#607583;line-height:1.45}label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:800;color:#607583;margin:22px 0 8px}input{width:100%;padding:14px 15px;border:1px solid #c8ddd8;border-radius:16px;font:inherit;outline:none}input:focus{border-color:#0f8f83;box-shadow:0 0 0 4px #dff7ef}button{margin-top:16px;width:100%;border:0;border-radius:16px;background:#0f8f83;color:white;font-weight:900;padding:14px;cursor:pointer;font:inherit}.warn{background:#fff7e8;border:1px solid #f3d19b;border-radius:16px;padding:12px;margin-top:16px;color:#8a5200;font-size:13px}.err{background:#fff0f0;border:1px solid #ffd0d0;color:#a22;margin-top:14px;padding:10px;border-radius:14px;font-weight:700}</style></head><body><main class="card"><span class="brand">🔒 Restricted clinic workspace</span><h1>Unlock Day Log</h1><p class="muted">Enter the shared workspace password. Network access can be limited with ALLOWED_IPS. Add the clinic/VPN public IP as a CIDR value like 203.0.113.10/32.</p>${req.query.error ? '<div class="err">Incorrect password. Try again.</div>' : ''}<form method="post" action="/login"><label>Password</label><input name="password" type="password" autocomplete="current-password" autofocus required><button>Unlock workspace</button></form><div class="warn">Do not use this for PHI until password, allowed IPs, and persistent storage are configured.</div></main></body></html>`);
});

app.post('/login', loginLimiter, (req, res) => {
  if (!DAYLOG_PASSWORD) return res.status(503).send('DAYLOG_PASSWORD is not configured.');
  if (!safeEqual(req.body.password, DAYLOG_PASSWORD)) return res.redirect('/login?error=1');
  res.cookie(COOKIE_NAME, makeSession(), { httpOnly: true, secure: req.secure || req.headers['x-forwarded-proto'] === 'https', sameSite: 'lax', maxAge: COOKIE_MAX_AGE_MS });
  res.redirect('/');
});

app.get('/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/login');
});

app.get('/api/appointments', requireAuth, (_req, res) => res.json(readCurrentStore()));
app.put('/api/appointments', requireAuth, (req, res) => res.json(writeStore(req.body || {})));
app.post('/api/backup', requireAuth, (_req, res) => {
  const store = readCurrentStore();
  const backupName = `appointments-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  fs.writeFileSync(path.join(DATA_DIR, backupName), JSON.stringify(store, null, 2));
  res.json({ ok: true, backupName });
});

app.post('/api/clear', requireAuth, (_req, res) => {
  const store = readCurrentStore();
  const backupName = backupStore(store, 'manual-clear');
  const clean = writeRawStore({
    appointments: [],
    updatedAt: new Date().toISOString(),
    retention: {
      timeZone: DAYLOG_TIMEZONE,
      today: localISODate(),
      keepRule: 'manual clear performed by an authenticated workspace session',
      lastPurgeBackup: backupName
    }
  });
  res.json(clean);
});

app.use(requireAuth, express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

purgePastAppointments();
setInterval(purgePastAppointments, 5 * 60 * 1000);

app.listen(PORT, () => console.log(`In-Person Day Log listening on ${PORT}`));
