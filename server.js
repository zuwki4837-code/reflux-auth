const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------
const app = express();
const upload = multer(); // multipart/form-data parser

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from ./wwwroot
app.use(express.static(path.join(__dirname, 'wwwroot')));

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const DATABASE_DIR = process.env.DATABASE_DIR || __dirname;
const dbPath = path.join(DATABASE_DIR, 'auth.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    ownerid TEXT UNIQUE,
    secret TEXT,
    version TEXT,
    paused INTEGER DEFAULT 0,
    created_at TEXT,
    admin_key TEXT
  );

  CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER,
    key TEXT UNIQUE,
    duration_days INTEGER,
    level INTEGER DEFAULT 1,
    hwid TEXT,
    used_by TEXT,
    status TEXT DEFAULT 'unused',
    note TEXT,
    created_at TEXT,
    used_at TEXT,
    expires_at TEXT,
    email TEXT,
    discord TEXT,
    last_ip TEXT
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER,
    username TEXT,
    password_hash TEXT,
    hwid TEXT,
    subscription_level INTEGER DEFAULT 1,
    created_at TEXT,
    expires_at TEXT,
    banned INTEGER DEFAULT 0,
    last_login TEXT,
    ip TEXT,
    email TEXT,
    discord TEXT,
    UNIQUE(app_id, username)
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER,
    session_id TEXT UNIQUE,
    created_at TEXT,
    ip TEXT
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER,
    event TEXT,
    username TEXT,
    details TEXT,
    ip TEXT,
    created_at TEXT
  );
`);

// Seed default application
db.prepare(`
  INSERT OR IGNORE INTO applications (name, ownerid, secret, version, paused, created_at, admin_key)
  VALUES ('plasma.lol', '7zmx6hWXmd', '22c3837291affbeb7b26947e768fe7b77938695c3df1b0ba521f96546abda53d', '1.0', 0, datetime('now'), 'zuwki-admin')
`).run();

// Load admin key from DB
let currentAdminKey = (() => {
  const row = db.prepare('SELECT admin_key FROM applications WHERE name = ?').get('plasma.lol');
  return row ? row.admin_key : 'zuwki-admin';
})();

const ADMIN_PIN = '0909';

// ---------------------------------------------------------------------------
// HMAC-SHA256 response signing middleware for /api/1.2/
// ---------------------------------------------------------------------------
const HMAC_SECRET = '22c3837291affbeb7b26947e768fe7b77938695c3df1b0ba521f96546abda53d';

app.use('/api/1.2/', (req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    const bodyStr = JSON.stringify(body);
    const signature = crypto
      .createHmac('sha256', HMAC_SECRET)
      .update(bodyStr)
      .digest('hex');
    res.set('X-Signature', signature);
    return originalJson(body);
  };
  next();
});

// Redirect / to /index.html
app.get('/', (req, res) => {
  res.redirect('/index.html');
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip;
}

function checkAdminKey(req) {
  return req.headers['x-admin-key'] === currentAdminKey;
}

function generateLicenseKey(prefix) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const segment = () => {
    let s = '';
    for (let i = 0; i < 5; i++) {
      s += chars[Math.floor(Math.random() * chars.length)];
    }
    return s;
  };
  const key = `${segment()}-${segment()}-${segment()}-${segment()}`;
  return prefix ? `${prefix}-${key}` : key;
}

function addDays(dateStr, days) {
  const d = new Date(dateStr);
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function nowISO() {
  return new Date().toISOString();
}

function isExpired(expiresAt) {
  if (!expiresAt) return false;
  return new Date(expiresAt) < new Date();
}

function timeLeftSeconds(expiresAt) {
  if (!expiresAt) return 0;
  const diff = new Date(expiresAt).getTime() - Date.now();
  return Math.max(0, Math.floor(diff / 1000));
}

// ---------------------------------------------------------------------------
// CLIENT API – POST /api/1.2/
// ---------------------------------------------------------------------------
app.post('/api/1.2/', upload.none(), (req, res) => {
  const {
    type,
    name,
    ownerid,
    ver,
    sessionid,
    key,
    hwid,
    username,
    pass,
    email,
    discord,
  } = req.body || {};

  const clientIp = getClientIp(req);
  const appName = name || 'plasma.lol';

  // Lookup application
  const application = db.prepare('SELECT * FROM applications WHERE name = ?').get(appName);
  if (!application) {
    return res.json({ success: false, message: 'Application not found' });
  }
  if (application.paused) {
    return res.json({ success: false, message: 'Application is paused' });
  }

  // -----------------------------------------------------------------------
  // type == 'init'
  // -----------------------------------------------------------------------
  if (type === 'init') {
    if (ownerid !== application.ownerid) {
      return res.json({ success: false, message: 'Invalid owner ID' });
    }

    const sessionId = crypto.randomUUID();
    db.prepare('INSERT INTO sessions (app_id, session_id, created_at, ip) VALUES (?, ?, ?, ?)').run(
      application.id,
      sessionId,
      nowISO(),
      clientIp
    );

    db.prepare('INSERT INTO logs (app_id, event, username, details, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      application.id,
      'init',
      null,
      'Session initialized',
      clientIp,
      nowISO()
    );

    const numUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE app_id = ?').get(application.id).c;
    const numKeys = db.prepare('SELECT COUNT(*) as c FROM licenses WHERE app_id = ?').get(application.id).c;

    return res.json({
      success: true,
      sessionid: sessionId,
      message: 'Initialized successfully',
      appinfo: {
        version: application.version,
        numUsers,
        numKeys,
      },
    });
  }

  // -----------------------------------------------------------------------
  // Session verification for all other types
  // -----------------------------------------------------------------------
  if (!sessionid) {
    return res.json({ success: false, message: 'Session ID is required' });
  }

  const session = db.prepare('SELECT * FROM sessions WHERE session_id = ? AND app_id = ?').get(sessionid, application.id);
  if (!session) {
    return res.json({ success: false, message: 'Invalid session' });
  }

  // -----------------------------------------------------------------------
  // type == 'license'
  // -----------------------------------------------------------------------
  if (type === 'license') {
    if (!key || !hwid) {
      return res.json({ success: false, message: 'License key and HWID are required' });
    }

    const license = db.prepare('SELECT * FROM licenses WHERE key = ? AND app_id = ?').get(key, application.id);
    if (!license) {
      return res.json({ success: false, message: 'Invalid license key' });
    }

    if (license.status === 'banned') {
      return res.json({ success: false, message: 'License is banned' });
    }

    if (license.status === 'expired') {
      return res.json({ success: false, message: 'License has expired' });
    }

    if (license.status === 'unused') {
      // Activate
      const now = nowISO();
      const expiresAt = addDays(now, license.duration_days);

      db.prepare(`
        UPDATE licenses SET status = 'used', used_by = 'anonymous', hwid = ?, used_at = ?, expires_at = ?,
        email = COALESCE(?, email), discord = COALESCE(?, discord), last_ip = ?
        WHERE id = ?
      `).run(hwid, now, expiresAt, email || null, discord || null, clientIp, license.id);

      db.prepare('INSERT INTO logs (app_id, event, username, details, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
        application.id,
        'license_activate',
        'anonymous',
        `License ${key} activated`,
        clientIp,
        nowISO()
      );

      return res.json({ success: true, message: 'License activated successfully' });
    }

    if (license.status === 'used') {
      // Check expiry
      if (isExpired(license.expires_at)) {
        db.prepare("UPDATE licenses SET status = 'expired' WHERE id = ?").run(license.id);
        return res.json({ success: false, message: 'License has expired' });
      }

      // Check HWID lock
      if (license.hwid && license.hwid !== hwid) {
        return res.json({ success: false, message: 'HWID mismatch. License is locked to another device.' });
      }

      // Update metadata
      db.prepare(`
        UPDATE licenses SET email = COALESCE(?, email), discord = COALESCE(?, discord), last_ip = ?
        WHERE id = ?
      `).run(email || null, discord || null, clientIp, license.id);

      return res.json({ success: true, message: 'License is valid' });
    }

    return res.json({ success: false, message: 'Unknown license status' });
  }

  // -----------------------------------------------------------------------
  // type == 'register'
  // -----------------------------------------------------------------------
  if (type === 'register') {
    if (!username || !pass || !key || !hwid) {
      return res.json({ success: false, message: 'Username, password, license key, and HWID are required' });
    }

    // Check username not taken
    const existingUser = db.prepare('SELECT id FROM users WHERE app_id = ? AND username = ?').get(application.id, username);
    if (existingUser) {
      return res.json({ success: false, message: 'Username already taken' });
    }

    // Verify license
    const license = db.prepare('SELECT * FROM licenses WHERE key = ? AND app_id = ?').get(key, application.id);
    if (!license) {
      return res.json({ success: false, message: 'Invalid license key' });
    }
    if (license.status !== 'unused') {
      return res.json({ success: false, message: 'License has already been used' });
    }

    // Hash password
    const passwordHash = bcrypt.hashSync(pass, 10);
    const now = nowISO();
    const expiresAt = addDays(now, license.duration_days);

    // Insert user
    db.prepare(`
      INSERT INTO users (app_id, username, password_hash, hwid, subscription_level, created_at, expires_at, banned, last_login, ip, email, discord)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
    `).run(application.id, username, passwordHash, hwid, license.level, now, expiresAt, now, clientIp, email || null, discord || null);

    // Update license
    db.prepare(`
      UPDATE licenses SET status = 'used', used_by = ?, hwid = ?, used_at = ?, expires_at = ?,
      email = COALESCE(?, email), discord = COALESCE(?, discord), last_ip = ?
      WHERE id = ?
    `).run(username, hwid, now, expiresAt, email || null, discord || null, clientIp, license.id);

    db.prepare('INSERT INTO logs (app_id, event, username, details, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      application.id,
      'register',
      username,
      `User registered with key ${key}`,
      clientIp,
      nowISO()
    );

    return res.json({ success: true, message: 'Registered successfully' });
  }

  // -----------------------------------------------------------------------
  // type == 'login'
  // -----------------------------------------------------------------------
  if (type === 'login') {
    if (!username || !pass || !hwid) {
      return res.json({ success: false, message: 'Username, password, and HWID are required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE app_id = ? AND username = ?').get(application.id, username);
    if (!user) {
      return res.json({ success: false, message: 'Invalid username or password' });
    }

    if (user.banned) {
      return res.json({ success: false, message: 'User is banned' });
    }

    // Verify password
    const passwordValid = bcrypt.compareSync(pass, user.password_hash);
    if (!passwordValid) {
      return res.json({ success: false, message: 'Invalid username or password' });
    }

    // Check expiry
    if (isExpired(user.expires_at)) {
      return res.json({ success: false, message: 'Subscription has expired' });
    }

    // HWID lock logic
    if (user.hwid && user.hwid !== hwid) {
      return res.json({ success: false, message: 'HWID mismatch. Account is locked to another device.' });
    }

    // Set HWID if empty
    if (!user.hwid) {
      db.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hwid, user.id);
    }

    // Update last login, ip, email, discord
    db.prepare(`
      UPDATE users SET last_login = ?, ip = ?, email = COALESCE(?, email), discord = COALESCE(?, discord)
      WHERE id = ?
    `).run(nowISO(), clientIp, email || null, discord || null, user.id);

    db.prepare('INSERT INTO logs (app_id, event, username, details, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      application.id,
      'login',
      username,
      'User logged in',
      clientIp,
      nowISO()
    );

    const expiryStr = user.expires_at || '';
    const timeleft = timeLeftSeconds(user.expires_at);

    return res.json({
      success: true,
      message: 'Logged in successfully',
      info: {
        username: user.username,
        subscriptions: [
          {
            subscription: 'default',
            expiry: expiryStr,
            timeleft,
          },
        ],
      },
    });
  }

  // -----------------------------------------------------------------------
  // type == 'reset_hwid'
  // -----------------------------------------------------------------------
  if (type === 'reset_hwid') {
    if (!key) {
      return res.json({ success: false, message: 'License key is required' });
    }

    const license = db.prepare('SELECT * FROM licenses WHERE key = ? AND app_id = ?').get(key, application.id);
    if (!license) {
      return res.json({ success: false, message: 'Invalid license key' });
    }

    if (license.status === 'banned') {
      return res.json({ success: false, message: 'License is banned' });
    }

    db.prepare('UPDATE licenses SET hwid = NULL WHERE id = ?').run(license.id);

    db.prepare('INSERT INTO logs (app_id, event, username, details, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      application.id,
      'reset_hwid',
      license.used_by,
      `HWID reset for license ${key}`,
      clientIp,
      nowISO()
    );

    return res.json({ success: true, message: 'HWID has been reset' });
  }

  return res.json({ success: false, message: `Unknown request type: ${type}` });
});

// ---------------------------------------------------------------------------
// ADMIN API
// ---------------------------------------------------------------------------

// POST /api/admin/auth
app.post('/api/admin/auth', (req, res) => {
  const { password } = req.body || {};
  if (password === currentAdminKey) {
    return res.json({ success: true, message: 'Authenticated' });
  }
  return res.status(401).json({ success: false, message: 'Invalid admin key' });
});

// Admin key guard middleware helper — used inline below
function adminGuard(req, res) {
  if (!checkAdminKey(req)) {
    res.status(401).json({ success: false, message: 'Unauthorized' });
    return false;
  }
  return true;
}

// GET /api/admin/stats
app.get('/api/admin/stats', (req, res) => {
  if (!adminGuard(req, res)) return;

  const app_row = db.prepare('SELECT id FROM applications WHERE name = ?').get('plasma.lol');
  const appId = app_row ? app_row.id : 0;

  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE app_id = ?').get(appId).c;
  const totalLicenses = db.prepare('SELECT COUNT(*) as c FROM licenses WHERE app_id = ?').get(appId).c;
  const activeLicenses = db.prepare("SELECT COUNT(*) as c FROM licenses WHERE app_id = ? AND status = 'used'").get(appId).c;
  const unusedLicenses = db.prepare("SELECT COUNT(*) as c FROM licenses WHERE app_id = ? AND status = 'unused'").get(appId).c;
  const recentLogins = db.prepare("SELECT * FROM logs WHERE app_id = ? AND (event = 'login' OR event = 'license_login') ORDER BY id DESC LIMIT 10").all(appId);

  return res.json({
    success: true,
    stats: {
      totalUsers,
      totalLicenses,
      activeLicenses,
      unusedLicenses,
      recentLogins,
    },
  });
});

// GET /api/admin/settings
app.get('/api/admin/settings', (req, res) => {
  if (!adminGuard(req, res)) return;

  const application = db.prepare('SELECT * FROM applications WHERE name = ?').get('plasma.lol');
  if (!application) {
    return res.json({ success: false, message: 'Application not found' });
  }

  return res.json({
    success: true,
    settings: {
      id: application.id,
      name: application.name,
      ownerid: application.ownerid,
      secret: application.secret,
      version: application.version,
      paused: application.paused,
      created_at: application.created_at,
    },
  });
});

// POST /api/admin/settings/pause
app.post('/api/admin/settings/pause', (req, res) => {
  if (!adminGuard(req, res)) return;

  const application = db.prepare('SELECT * FROM applications WHERE name = ?').get('plasma.lol');
  if (!application) {
    return res.json({ success: false, message: 'Application not found' });
  }

  const newPaused = application.paused ? 0 : 1;
  db.prepare('UPDATE applications SET paused = ? WHERE id = ?').run(newPaused, application.id);

  return res.json({ success: true, paused: !!newPaused, message: newPaused ? 'Application paused' : 'Application resumed' });
});

// POST /api/admin/settings/refresh-secret
app.post('/api/admin/settings/refresh-secret', (req, res) => {
  if (!adminGuard(req, res)) return;

  const newSecret = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE applications SET secret = ? WHERE name = ?').run(newSecret, 'plasma.lol');

  return res.json({ success: true, secret: newSecret, message: 'Secret refreshed' });
});

// POST /api/admin/settings/change-key
app.post('/api/admin/settings/change-key', (req, res) => {
  if (!adminGuard(req, res)) return;

  const { newKey, pin } = req.body || {};
  if (pin !== ADMIN_PIN) {
    return res.status(403).json({ success: false, message: 'Invalid PIN' });
  }
  if (!newKey || newKey.length < 1) {
    return res.json({ success: false, message: 'New key is required' });
  }

  db.prepare('UPDATE applications SET admin_key = ? WHERE name = ?').run(newKey, 'plasma.lol');
  currentAdminKey = newKey;

  return res.json({ success: true, message: 'Admin key updated' });
});

// GET /api/admin/licenses
app.get('/api/admin/licenses', (req, res) => {
  if (!adminGuard(req, res)) return;

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.max(1, Math.min(100, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;

  const app_row = db.prepare('SELECT id FROM applications WHERE name = ?').get('plasma.lol');
  const appId = app_row ? app_row.id : 0;

  const total = db.prepare('SELECT COUNT(*) as c FROM licenses WHERE app_id = ?').get(appId).c;
  const licenses = db.prepare('SELECT * FROM licenses WHERE app_id = ? ORDER BY id DESC LIMIT ? OFFSET ?').all(appId, limit, offset);

  return res.json({ success: true, licenses, total, page, limit });
});

// POST /api/admin/licenses/generate
app.post('/api/admin/licenses/generate', (req, res) => {
  if (!adminGuard(req, res)) return;

  const { count, duration_days, level, prefix, note } = req.body || {};
  const genCount = Math.max(1, Math.min(500, parseInt(count) || 1));
  const durationDays = parseInt(duration_days) || 30;
  const licenseLevel = parseInt(level) || 1;

  const app_row = db.prepare('SELECT id FROM applications WHERE name = ?').get('plasma.lol');
  const appId = app_row ? app_row.id : 0;

  const insertStmt = db.prepare(`
    INSERT INTO licenses (app_id, key, duration_days, level, status, note, created_at)
    VALUES (?, ?, ?, ?, 'unused', ?, ?)
  `);

  const keys = [];
  const now = nowISO();

  const insertMany = db.transaction(() => {
    for (let i = 0; i < genCount; i++) {
      const licenseKey = generateLicenseKey(prefix || '');
      insertStmt.run(appId, licenseKey, durationDays, licenseLevel, note || null, now);
      keys.push(licenseKey);
    }
  });
  insertMany();

  return res.json({ success: true, keys, count: keys.length, message: `${keys.length} license(s) generated` });
});

// DELETE /api/admin/licenses/:id
app.delete('/api/admin/licenses/:id', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare('DELETE FROM licenses WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'License not found' });
  }
  return res.json({ success: true, message: 'License deleted' });
});

// POST /api/admin/licenses/:id/ban
app.post('/api/admin/licenses/:id/ban', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare("UPDATE licenses SET status = 'banned' WHERE id = ?").run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'License not found' });
  }
  return res.json({ success: true, message: 'License banned' });
});

// POST /api/admin/licenses/:id/unban
app.post('/api/admin/licenses/:id/unban', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(id);
  if (!license) {
    return res.json({ success: false, message: 'License not found' });
  }

  const newStatus = license.used_at ? 'used' : 'unused';
  db.prepare('UPDATE licenses SET status = ? WHERE id = ?').run(newStatus, id);

  return res.json({ success: true, message: `License unbanned (status: ${newStatus})` });
});

// POST /api/admin/licenses/:id/reset-hwid
app.post('/api/admin/licenses/:id/reset-hwid', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare('UPDATE licenses SET hwid = NULL WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'License not found' });
  }
  return res.json({ success: true, message: 'HWID reset' });
});

// GET /api/admin/users
app.get('/api/admin/users', (req, res) => {
  if (!adminGuard(req, res)) return;

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.max(1, Math.min(100, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;

  const app_row = db.prepare('SELECT id FROM applications WHERE name = ?').get('plasma.lol');
  const appId = app_row ? app_row.id : 0;

  const total = db.prepare('SELECT COUNT(*) as c FROM users WHERE app_id = ?').get(appId).c;
  const users = db.prepare('SELECT id, app_id, username, hwid, subscription_level, created_at, expires_at, banned, last_login, ip, email, discord FROM users WHERE app_id = ? ORDER BY id DESC LIMIT ? OFFSET ?').all(appId, limit, offset);

  return res.json({ success: true, users, total, page, limit });
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'User not found' });
  }
  return res.json({ success: true, message: 'User deleted' });
});

// POST /api/admin/users/:id/ban
app.post('/api/admin/users/:id/ban', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare('UPDATE users SET banned = 1 WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'User not found' });
  }
  return res.json({ success: true, message: 'User banned' });
});

// POST /api/admin/users/:id/unban
app.post('/api/admin/users/:id/unban', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare('UPDATE users SET banned = 0 WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'User not found' });
  }
  return res.json({ success: true, message: 'User unbanned' });
});

// POST /api/admin/users/:id/reset-hwid
app.post('/api/admin/users/:id/reset-hwid', (req, res) => {
  if (!adminGuard(req, res)) return;

  const id = parseInt(req.params.id);
  const result = db.prepare('UPDATE users SET hwid = NULL WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.json({ success: false, message: 'User not found' });
  }
  return res.json({ success: true, message: 'User HWID reset' });
});

// GET /api/admin/logs
app.get('/api/admin/logs', (req, res) => {
  if (!adminGuard(req, res)) return;

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.max(1, Math.min(100, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;
  const eventFilter = req.query.event || null;

  const app_row = db.prepare('SELECT id FROM applications WHERE name = ?').get('plasma.lol');
  const appId = app_row ? app_row.id : 0;

  let total, logs;
  if (eventFilter) {
    total = db.prepare('SELECT COUNT(*) as c FROM logs WHERE app_id = ? AND event = ?').get(appId, eventFilter).c;
    logs = db.prepare('SELECT * FROM logs WHERE app_id = ? AND event = ? ORDER BY id DESC LIMIT ? OFFSET ?').all(appId, eventFilter, limit, offset);
  } else {
    total = db.prepare('SELECT COUNT(*) as c FROM logs WHERE app_id = ?').get(appId).c;
    logs = db.prepare('SELECT * FROM logs WHERE app_id = ? ORDER BY id DESC LIMIT ? OFFSET ?').all(appId, limit, offset);
  }

  return res.json({ success: true, logs, total, page, limit });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`[STARTUP] Listening on port ${port}`);
});
