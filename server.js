'use strict';

const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.db');
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB per file
const SALT_ROUNDS = 10;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Initialize SQLite database
const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    pin_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    uploaded_at INTEGER NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );
`);

// Multer storage: files stored as <uuid>.<ext>
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
});

// ── Rate limiters ────────────────────────────────────────────────────────────
// Strict limit for account creation / login (prevent brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

// General API limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

if (!process.env.SESSION_SECRET) {
  console.warn(
    '[warn] SESSION_SECRET env var is not set. Sessions will be invalidated on restart. ' +
    'Set SESSION_SECRET to a long random string for persistent sessions.'
  );
}
app.use(
  session({
    secret: process.env.SESSION_SECRET || uuidv4(),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: IS_PRODUCTION,
    },
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// ── CSRF protection ──────────────────────────────────────────────────────────
// Double-submit cookie pattern: the server generates a per-session token that
// the client must echo back in the X-CSRF-Token request header.
// Cross-origin pages cannot read this token, so forged requests will be rejected.

function generateCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = uuidv4();
  }
  return req.session.csrfToken;
}

// Endpoint the SPA calls to obtain its CSRF token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req) });
});

function csrfGuard(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Forbidden: invalid CSRF token' });
  }
  next();
}

// ── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.accountId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// ── API Routes ───────────────────────────────────────────────────────────────

// Create anonymous account → returns { accountId, pin }
app.post('/api/account/create', authLimiter, csrfGuard, async (req, res) => {
  try {
    const pin = String(Math.floor(100000 + Math.random() * 900000)); // 6-digit PIN
    const pinHash = await bcrypt.hash(pin, SALT_ROUNDS);
    const accountId = uuidv4();
    db.prepare('INSERT INTO accounts (id, pin_hash, created_at) VALUES (?, ?, ?)').run(
      accountId,
      pinHash,
      Date.now()
    );
    req.session.accountId = accountId;
    res.json({ accountId, pin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Login with PIN → sets session
app.post('/api/account/login', authLimiter, csrfGuard, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN is required' });

    // Validate format before hitting the database
    if (!/^\d{6}$/.test(String(pin))) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Try to find a matching account by iterating (small personal-use table)
    const accounts = db.prepare('SELECT id, pin_hash FROM accounts').all();
    for (const account of accounts) {
      const match = await bcrypt.compare(String(pin), account.pin_hash);
      if (match) {
        req.session.accountId = account.id;
        return res.json({ accountId: account.id });
      }
    }
    res.status(401).json({ error: 'Invalid PIN' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/account/logout', csrfGuard, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Get current session info
app.get('/api/account/me', apiLimiter, requireAuth, (req, res) => {
  res.json({ accountId: req.session.accountId });
});

// List files for the authenticated account
app.get('/api/files', apiLimiter, requireAuth, (req, res) => {
  const files = db
    .prepare(
      'SELECT id, original_name, size, mime_type, uploaded_at FROM files WHERE account_id = ? ORDER BY uploaded_at DESC'
    )
    .all(req.session.accountId);
  res.json(files);
});

// Upload file(s)
app.post('/api/files/upload', apiLimiter, csrfGuard, requireAuth, upload.array('files', 20), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }
  const insertFile = db.prepare(
    'INSERT INTO files (id, account_id, original_name, stored_name, size, mime_type, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  const inserted = [];
  for (const f of req.files) {
    const fileId = uuidv4();
    insertFile.run(
      fileId,
      req.session.accountId,
      f.originalname,
      f.filename,
      f.size,
      f.mimetype,
      Date.now()
    );
    inserted.push({ id: fileId, original_name: f.originalname, size: f.size });
  }
  res.json(inserted);
});

// Download a file
app.get('/api/files/:id/download', apiLimiter, requireAuth, (req, res) => {
  const file = db
    .prepare('SELECT * FROM files WHERE id = ? AND account_id = ?')
    .get(req.params.id, req.session.accountId);
  if (!file) return res.status(404).json({ error: 'File not found' });

  const filePath = path.join(UPLOAD_DIR, file.stored_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found on disk' });

  res.download(filePath, file.original_name);
});

// Delete a single file
app.delete('/api/files/:id', apiLimiter, csrfGuard, requireAuth, (req, res) => {
  const file = db
    .prepare('SELECT * FROM files WHERE id = ? AND account_id = ?')
    .get(req.params.id, req.session.accountId);
  if (!file) return res.status(404).json({ error: 'File not found' });

  const filePath = path.join(UPLOAD_DIR, file.stored_name);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
  res.json({ ok: true });
});

// Delete account (and all its files)
app.delete('/api/account', apiLimiter, csrfGuard, requireAuth, (req, res) => {
  const accountId = req.session.accountId;
  const files = db.prepare('SELECT stored_name FROM files WHERE account_id = ?').all(accountId);
  for (const f of files) {
    const fp = path.join(UPLOAD_DIR, f.stored_name);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
  db.prepare('DELETE FROM files WHERE account_id = ?').run(accountId);
  db.prepare('DELETE FROM accounts WHERE id = ?').run(accountId);
  req.session.destroy(() => res.json({ ok: true }));
});

// ── Start server ─────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Personal File Uploader running at http://localhost:${PORT}`);
  });
}

module.exports = app;

