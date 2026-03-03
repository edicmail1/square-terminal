require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// ── Config ───────────────────────────────────────────────────────────────────
const RENDER_API_TOKEN  = process.env.RENDER_API_TOKEN;
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID;
const APP_PASSWORD      = process.env.APP_PASSWORD || 'changeme';
const BASE_URL          = process.env.BASE_URL || 'https://square-terminal.onrender.com';

// JWT secret — persistent, generated once, stored in env
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '12h';

// AES-256 encryption key for tokens — MUST be 32 bytes hex (64 chars)
// If not set, generate one and log a warning
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || (() => {
  const key = crypto.randomBytes(32).toString('hex');
  console.warn('⚠️  ENCRYPTION_KEY not set! Generated temporary key. Set ENCRYPTION_KEY env var for persistence.');
  return key;
})();

// Square OAuth app credentials
const SQ_CLIENT_ID     = process.env.SQ_CLIENT_ID || '';
const SQ_CLIENT_SECRET = process.env.SQ_CLIENT_SECRET || '';
const SQ_OAUTH_SCOPES  = 'PAYMENTS_READ PAYMENTS_WRITE MERCHANT_PROFILE_READ ORDERS_READ ORDERS_WRITE';

// Rate limiting config
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MINUTES = 15;

// ── AES-256 Encryption ──────────────────────────────────────────────────────
function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  if (!encryptedText) return '';
  // Handle unencrypted legacy tokens (they start with 'EAAl' etc.)
  if (!encryptedText.includes(':') || encryptedText.startsWith('EAAl') || encryptedText.startsWith('EAAA')) {
    return encryptedText;
  }
  try {
    const [ivHex, encrypted] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    // If decryption fails, return as-is (might be plaintext legacy token)
    console.warn('Decryption failed, returning raw value');
    return encryptedText;
  }
}

// ── SQLite Database ─────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'terminal.db');
const dbDir = path.dirname(DB_PATH);
require('fs').mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    access_token TEXT NOT NULL DEFAULT '',
    application_id TEXT NOT NULL DEFAULT '',
    location_id TEXT NOT NULL DEFAULT '',
    max_amount REAL,
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
    note TEXT DEFAULT '',
    buyer_email TEXT DEFAULT '',
    location_id TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    url TEXT DEFAULT '',
    error TEXT DEFAULT '',
    receipt_url TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    profile_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    ip TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_transactions_profile ON transactions(profile_id);
  CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`);

// Clean up expired sessions periodically
function cleanupExpiredSessions() {
  db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  db.prepare("DELETE FROM oauth_states WHERE created_at < datetime('now', '-1 hour')").run();
  db.prepare("DELETE FROM login_attempts WHERE locked_until < datetime('now')").run();
}
setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // every hour
cleanupExpiredSessions();

// ── DB Helpers ──────────────────────────────────────────────────────────────
const dbAll = (sql, params = []) => db.prepare(sql).all(...(Array.isArray(params) ? params : [params]));
const dbGet = (sql, params = []) => db.prepare(sql).get(...(Array.isArray(params) ? params : [params]));
const dbRun = (sql, params = []) => db.prepare(sql).run(...(Array.isArray(params) ? params : [params]));

// ── Migration from PROFILES_JSON ────────────────────────────────────────────
function migrateFromEnv() {
  const existing = dbGet("SELECT COUNT(*) as count FROM profiles");
  if (existing.count > 0) return; // Already migrated

  const raw = process.env.PROFILES_JSON;
  if (!raw) {
    // Create default profile from individual env vars
    const accessToken = process.env.SQUARE_ACCESS_TOKEN || '';
    const applicationId = process.env.SQUARE_APPLICATION_ID || '';
    const locationId = process.env.SQUARE_LOCATION_ID || '';
    if (accessToken || applicationId) {
      dbRun(
        `INSERT INTO profiles (id, name, access_token, application_id, location_id, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
        [uuidv4(), 'Default', encrypt(accessToken), applicationId, locationId]
      );
      console.log('✅ Created default profile from env vars');
    }
    return;
  }

  try {
    const store = JSON.parse(raw);
    const profiles = store.profiles || [];
    const activeId = store.activeId;

    const insertProfile = db.prepare(
      `INSERT INTO profiles (id, name, access_token, application_id, location_id, max_amount, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    const insertTx = db.prepare(
      `INSERT OR IGNORE INTO transactions (id, profile_id, type, amount, currency, note, buyer_email, location_id, status, url, error, receipt_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const migrate = db.transaction(() => {
      for (const p of profiles) {
        insertProfile.run(
          p.id, p.name, encrypt(p.accessToken || ''),
          p.applicationId || '', p.locationId || '',
          p.maxAmount || null, p.id === activeId ? 1 : 0
        );

        for (const tx of (p.transactions || [])) {
          insertTx.run(
            tx.id || uuidv4(), p.id, tx.type || 'unknown',
            tx.amount || 0, tx.currency || 'USD',
            tx.note || '', tx.buyerEmail || '',
            tx.locationId || '', tx.status || '',
            tx.url || '', tx.error || '',
            tx.receiptUrl || '', tx.createdAt || new Date().toISOString()
          );
        }
      }
    });

    migrate();
    console.log(`✅ Migrated ${profiles.length} profiles from PROFILES_JSON`);
  } catch (e) {
    console.error('❌ Migration failed:', e.message);
  }
}

migrateFromEnv();

// ── Profile Helpers ─────────────────────────────────────────────────────────
function getActiveProfile() {
  return dbGet("SELECT * FROM profiles WHERE is_active = 1") || dbGet("SELECT * FROM profiles LIMIT 1");
}

function getProfileById(id) {
  return dbGet("SELECT * FROM profiles WHERE id = ?", [id]);
}

function getAllProfiles() {
  return dbAll("SELECT * FROM profiles ORDER BY is_active DESC, created_at ASC");
}

function getDecryptedToken(profile) {
  return decrypt(profile.access_token);
}

function createSquareClient(profile) {
  return new Client({
    accessToken: getDecryptedToken(profile),
    environment: Environment.Production,
  });
}

let squareClient = (() => {
  const p = getActiveProfile();
  return p ? createSquareClient(p) : null;
})();

function maskToken(t) {
  const raw = decrypt(t);
  if (!raw || raw.length < 8) return '••••••••';
  return raw.slice(0, 4) + '••••••••' + raw.slice(-4);
}

function addTransaction(profileId, tx) {
  dbRun(
    `INSERT INTO transactions (id, profile_id, type, amount, currency, note, buyer_email, location_id, status, url, error, receipt_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      tx.id || uuidv4(), profileId, tx.type || 'unknown',
      tx.amount || 0, tx.currency || 'USD',
      tx.note || '', tx.buyerEmail || '',
      tx.locationId || '', tx.status || '',
      tx.url || '', tx.error || '',
      tx.receiptUrl || '', tx.createdAt || new Date().toISOString(),
    ]
  );
}

// ── JWT Auth ────────────────────────────────────────────────────────────────
function createJWT() {
  return jwt.sign({ role: 'admin', iat: Math.floor(Date.now() / 1000) }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const token = req.cookies?.session || req.headers['x-session-token'];
  if (token && verifyJWT(token)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Rate Limiting ───────────────────────────────────────────────────────────
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
}

function checkRateLimit(ip) {
  const row = dbGet("SELECT * FROM login_attempts WHERE ip = ?", [ip]);
  if (!row) return { allowed: true, remaining: LOGIN_MAX_ATTEMPTS };

  // Check if locked
  if (row.locked_until) {
    const lockExpiry = new Date(row.locked_until + 'Z');
    if (lockExpiry > new Date()) {
      const minutesLeft = Math.ceil((lockExpiry - new Date()) / 60000);
      return { allowed: false, remaining: 0, minutesLeft };
    }
    // Lock expired, reset
    dbRun("DELETE FROM login_attempts WHERE ip = ?", [ip]);
    return { allowed: true, remaining: LOGIN_MAX_ATTEMPTS };
  }

  return { allowed: true, remaining: LOGIN_MAX_ATTEMPTS - row.attempts };
}

function recordFailedLogin(ip) {
  const row = dbGet("SELECT * FROM login_attempts WHERE ip = ?", [ip]);
  if (!row) {
    dbRun("INSERT INTO login_attempts (ip, attempts, updated_at) VALUES (?, 1, datetime('now'))", [ip]);
    return LOGIN_MAX_ATTEMPTS - 1;
  }

  const newAttempts = row.attempts + 1;
  if (newAttempts >= LOGIN_MAX_ATTEMPTS) {
    dbRun(
      "UPDATE login_attempts SET attempts = ?, locked_until = datetime('now', '+' || ? || ' minutes'), updated_at = datetime('now') WHERE ip = ?",
      [newAttempts, LOGIN_LOCKOUT_MINUTES, ip]
    );
    return 0;
  }

  dbRun("UPDATE login_attempts SET attempts = ?, updated_at = datetime('now') WHERE ip = ?", [newAttempts, ip]);
  return LOGIN_MAX_ATTEMPTS - newAttempts;
}

function clearLoginAttempts(ip) {
  dbRun("DELETE FROM login_attempts WHERE ip = ?", [ip]);
}

// ── Square API helpers ──────────────────────────────────────────────────────
function squareRequest(method, accessToken, apiPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'connect.squareup.com',
      path: apiPath, method,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Square-Version': '2025-01-23',
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const squareGet  = (t, p)    => squareRequest('GET',  t, p, null);
const squarePost = (t, p, b) => squareRequest('POST', t, p, b);

// ── Square Token Validation Wrapper ─────────────────────────────────────────
// Wraps Square API calls to detect expired/invalid tokens and return clear errors
async function safeSquareCall(profile, apiCall) {
  try {
    const result = await apiCall(getDecryptedToken(profile));

    if (result.status === 401) {
      // Mark profile as having token issues
      return {
        status: 401,
        body: {
          errors: [{
            category: 'AUTHENTICATION_ERROR',
            code: 'UNAUTHORIZED',
            detail: `Токен для "${profile.name}" истёк или недействителен. Обновите Access Token в настройках.`,
          }],
        },
        tokenExpired: true,
        profileId: profile.id,
        profileName: profile.name,
      };
    }

    if (result.status === 403) {
      return {
        status: 403,
        body: {
          errors: [{
            category: 'AUTHORIZATION_ERROR',
            code: 'FORBIDDEN',
            detail: `Токен для "${profile.name}" не имеет необходимых permissions. Проверьте настройки приложения в Square Developer Dashboard.`,
          }],
        },
        tokenExpired: false,
      };
    }

    return result;
  } catch (e) {
    return { status: 500, body: { errors: [{ detail: e.message }] } };
  }
}

// ── Login ────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const ip = getClientIP(req);
  const rateCheck = checkRateLimit(ip);

  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: `Слишком много попыток. Попробуйте через ${rateCheck.minutesLeft} мин.`,
      lockedMinutes: rateCheck.minutesLeft,
    });
  }

  const { password } = req.body;
  if (password !== APP_PASSWORD) {
    const remaining = recordFailedLogin(ip);
    const msg = remaining > 0
      ? `Неверный пароль. Осталось попыток: ${remaining}`
      : `Аккаунт заблокирован на ${LOGIN_LOCKOUT_MINUTES} минут`;
    return res.status(401).json({ error: msg, remaining });
  }

  clearLoginAttempts(ip);
  const token = createJWT();
  res.cookie('session', token, { httpOnly: true, maxAge: 12 * 60 * 60 * 1000, sameSite: 'strict' });
  res.json({ success: true, token });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ success: true });
});

app.get('/api/auth-status', (req, res) => {
  const token = req.cookies?.session || req.headers['x-session-token'];
  res.json({ authenticated: !!verifyJWT(token) });
});

// ── Square OAuth ─────────────────────────────────────────────────────────────
app.get('/auth/square', requireAuth, (req, res) => {
  if (!SQ_CLIENT_ID) return res.status(400).send('SQ_CLIENT_ID not configured');
  const state = crypto.randomBytes(16).toString('hex');
  const profileName = req.query.name || 'New Business';

  // Store in DB instead of memory
  dbRun("INSERT INTO oauth_states (state, profile_name) VALUES (?, ?)", [state, profileName]);

  const params = new URLSearchParams({
    client_id: SQ_CLIENT_ID,
    scope: SQ_OAUTH_SCOPES,
    state,
    redirect_uri: `${BASE_URL}/auth/callback`,
    session: 'false',
  });
  res.redirect(`https://connect.squareup.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.redirect('/?oauth=error&msg=' + encodeURIComponent(error));

  // Look up state in DB
  const stateData = dbGet("SELECT * FROM oauth_states WHERE state = ?", [state]);
  if (!stateData) return res.redirect('/?oauth=error&msg=invalid_state');
  dbRun("DELETE FROM oauth_states WHERE state = ?", [state]);

  try {
    const body = JSON.stringify({
      client_id: SQ_CLIENT_ID,
      client_secret: SQ_CLIENT_SECRET,
      code,
      redirect_uri: `${BASE_URL}/auth/callback`,
      grant_type: 'authorization_code',
    });

    const result = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'connect.squareup.com',
        path: '/oauth2/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Square-Version': '2025-01-23',
          'Content-Length': Buffer.byteLength(body),
        },
      }, res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });

    if (result.status !== 200) {
      return res.redirect('/?oauth=error&msg=' + encodeURIComponent(result.body?.message || 'Token exchange failed'));
    }

    const { access_token } = result.body;

    const [merchantRes, locRes] = await Promise.all([
      squareGet(access_token, '/v2/merchants/me'),
      squareGet(access_token, '/v2/locations'),
    ]);

    const merchant  = merchantRes.body?.merchant || {};
    const locations = locRes.body?.locations || [];
    const firstLoc  = locations.find(l => l.status === 'ACTIVE') || locations[0] || {};

    const newId = uuidv4();
    const profileName = merchant.business_name || stateData.profile_name;
    const profileCount = dbGet("SELECT COUNT(*) as count FROM profiles").count;

    dbRun(
      `INSERT INTO profiles (id, name, access_token, application_id, location_id, is_active) VALUES (?, ?, ?, ?, ?, ?)`,
      [newId, profileName, encrypt(access_token), SQ_CLIENT_ID, firstLoc.id || '', profileCount === 0 ? 1 : 0]
    );

    if (profileCount === 0) {
      squareClient = createSquareClient(getProfileById(newId));
    }

    res.redirect('/?oauth=success&name=' + encodeURIComponent(profileName));
  } catch (err) {
    res.redirect('/?oauth=error&msg=' + encodeURIComponent(err.message));
  }
});

// ── Public endpoints ────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  const p = getActiveProfile();
  res.json({ applicationId: p?.application_id || '', locationId: p?.location_id || '' });
});

app.get('/api/oauth-config', (req, res) => {
  res.json({ enabled: !!(SQ_CLIENT_ID && SQ_CLIENT_SECRET) });
});

// ── Protected API ───────────────────────────────────────────────────────────
app.get('/api/profiles', requireAuth, (req, res) => {
  const profiles = getAllProfiles();
  const activeProfile = profiles.find(p => p.is_active) || profiles[0];
  res.json({
    activeId: activeProfile?.id || null,
    profiles: profiles.map(p => {
      const txCount = dbGet("SELECT COUNT(*) as count FROM transactions WHERE profile_id = ?", [p.id]).count;
      return {
        id: p.id, name: p.name,
        applicationId: p.application_id, locationId: p.location_id,
        accessTokenMasked: maskToken(p.access_token),
        maxAmount: p.max_amount,
        active: p.is_active === 1,
        transactionCount: txCount,
      };
    }),
  });
});

// GET real payments from Square for active location
app.get('/api/profiles/:id/payments', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  const locationId = req.query.location_id || profile.location_id;
  const limit      = Math.min(parseInt(req.query.limit) || 50, 200);
  const cursor     = req.query.cursor || null;
  const begin      = req.query.begin_time || null;
  const end        = req.query.end_time   || null;

  const params = new URLSearchParams({ location_id: locationId, limit: String(limit), sort_order: 'DESC' });
  if (cursor) params.set('cursor', cursor);
  if (begin)  params.set('begin_time', begin);
  if (end)    params.set('end_time', end);

  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/payments?${params}`));

  if (r.tokenExpired) {
    return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true, profileId: r.profileId });
  }
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });

  const payments = (r.body.payments || []).map(p => {
    const card = p.card_details?.card || {};
    const cd   = p.card_details || {};
    return {
      id:            p.id,
      status:        p.status,
      amount:        p.amount_money,
      approvedMoney: p.approved_money || null,
      tip:           p.tip_money || null,
      totalMoney:    p.total_money || null,
      currency:      p.amount_money?.currency,
      note:          p.note || '',
      orderId:       p.order_id || null,
      customerId:    p.customer_id || null,
      receiptUrl:    p.receipt_url || null,
      receiptNumber: p.receipt_number || null,
      locationId:    p.location_id,
      createdAt:     p.created_at,
      updatedAt:     p.updated_at,
      delayUntil:    p.delayed_until || null,
      delayAction:   p.delay_action || null,
      appProduct:    p.application_details?.square_product || null,
      appId:         p.application_details?.application_id || null,
      card: {
        brand:                  card.card_brand || null,
        last4:                  card.last_4 || null,
        expMonth:               card.exp_month || null,
        expYear:                card.exp_year || null,
        fingerprint:            card.fingerprint || null,
        cardId:                 card.id || null,
        enabled:                card.enabled ?? null,
        cardholderName:         card.cardholder_name || null,
        bin:                    card.bin || null,
        cardType:               card.card_type || null,
        prepaidType:            card.prepaid_type || null,
        paymentAccountRef:      card.payment_account_reference || null,
      },
      entryMethod:          cd.entry_method || null,
      cvvStatus:            cd.cvv_status || null,
      avsStatus:            cd.avs_status || null,
      authResultCode:       cd.auth_result_code || null,
      statementDescription: cd.statement_description || null,
      cardStatus:           cd.status || null,
      authorizedAt:         cd.card_payment_timeline?.authorized_at || null,
      capturedAt:           cd.card_payment_timeline?.captured_at || null,
      voidedAt:             cd.card_payment_timeline?.voided_at || null,
      billingName:  [p.billing_address?.first_name, p.billing_address?.last_name].filter(Boolean).join(' ') || null,
      shippingName: [p.shipping_address?.first_name, p.shipping_address?.last_name].filter(Boolean).join(' ') || null,
      buyerEmail:   p.buyer_email_address || null,
      declineCode:   p.card_details?.errors?.[0]?.code || null,
      declineDetail: p.card_details?.errors?.[0]?.detail || null,
      declineCategory: p.card_details?.errors?.[0]?.category || null,
      issuerAlerts:          p.issuer_alerts || p.card_details?.issuer_alerts || [],
      issuerAlertsUpdatedAt: p.issuer_alerts_updated_at || null,
      riskLevel:     p.risk_evaluation?.risk_level || null,
      riskCreatedAt: p.risk_evaluation?.created_at || null,
      refundedMoney: p.refunded_money || null,
      processingFee: p.processing_fee?.[0]?.amount_money || null,
      processingFeeType: p.processing_fee?.[0]?.type || null,
    };
  });

  res.json({ payments, cursor: r.body.cursor || null });
});

// DEBUG: raw payment object
app.get('/api/debug/payment', requireAuth, async (req, res) => {
  const profile = getActiveProfile();
  if (!profile) return res.status(404).json({ error: 'No active profile' });
  const locationId = req.query.location_id || profile.location_id;
  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/payments?location_id=${locationId}&limit=1&sort_order=DESC`));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  res.json(r.body);
});

// GET balance
app.get('/api/profiles/:id/balance', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, '/v2/balance/merchant-balance'));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const fmt = (arr) => (arr || []).map(m => ({ amount: (Number(m.amount) / 100).toFixed(2), currency: m.currency }));
  res.json({ available: fmt(r.body.balance?.available), pending: fmt(r.body.balance?.pending) });
});

// GET bank accounts
app.get('/api/profiles/:id/bank-accounts', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, '/v2/bank-accounts'));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const accounts = (r.body.bank_accounts || []).map(a => ({
    id: a.id, accountType: a.account_type, accountNumberSuffix: a.account_number_suffix,
    routingNumber: a.routing_number, bankName: a.bank_name,
    holderName: a.holder_name || a.account_holder_name || null,
    status: a.status, creditable: a.creditable, debitable: a.debitable,
    merchantId: a.merchant_id || null, locationId: a.location_id || null,
  }));
  res.json({ accounts });
});

// GET merchant info
app.get('/api/profiles/:id/merchant', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, '/v2/merchants/me'));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json(r.body.merchant);
});

// GET transactions from DB
app.get('/api/profiles/:id/transactions', requireAuth, (req, res) => {
  const txs = dbAll(
    "SELECT * FROM transactions WHERE profile_id = ? ORDER BY created_at DESC LIMIT 50",
    [req.params.id]
  );
  res.json({ transactions: txs });
});

// Activate profile
app.post('/api/profiles/:id/activate', requireAuth, (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  dbRun("UPDATE profiles SET is_active = 0");
  dbRun("UPDATE profiles SET is_active = 1 WHERE id = ?", [profile.id]);
  squareClient = createSquareClient(profile);
  res.json({ success: true, name: profile.name });
});

// Create / Edit profile
app.post('/api/profiles', requireAuth, (req, res) => {
  const { id, name, accessToken, applicationId, locationId, maxAmount } = req.body;
  if (!name || !applicationId || !locationId) return res.status(400).json({ error: 'name, applicationId and locationId are required' });

  if (id) {
    const p = getProfileById(id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    dbRun(
      `UPDATE profiles SET name = ?, application_id = ?, location_id = ?, max_amount = ?, updated_at = datetime('now') WHERE id = ?`,
      [name, applicationId, locationId, maxAmount ? parseFloat(maxAmount) : null, id]
    );
    if (accessToken) {
      dbRun("UPDATE profiles SET access_token = ? WHERE id = ?", [encrypt(accessToken), id]);
    }
    if (p.is_active) squareClient = createSquareClient(getProfileById(id));
  } else {
    if (!accessToken) return res.status(400).json({ error: 'accessToken is required' });
    const newId = uuidv4();
    const profileCount = dbGet("SELECT COUNT(*) as count FROM profiles").count;
    dbRun(
      `INSERT INTO profiles (id, name, access_token, application_id, location_id, max_amount, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [newId, name, encrypt(accessToken), applicationId, locationId, maxAmount ? parseFloat(maxAmount) : null, profileCount === 0 ? 1 : 0]
    );
  }

  res.json({ success: true });
});

// Delete profile
app.delete('/api/profiles/:id', requireAuth, (req, res) => {
  const count = dbGet("SELECT COUNT(*) as count FROM profiles").count;
  if (count <= 1) return res.status(400).json({ error: 'Cannot delete last profile' });

  const wasActive = getProfileById(req.params.id)?.is_active;
  dbRun("DELETE FROM profiles WHERE id = ?", [req.params.id]);

  if (wasActive) {
    const first = dbGet("SELECT * FROM profiles LIMIT 1");
    if (first) {
      dbRun("UPDATE profiles SET is_active = 1 WHERE id = ?", [first.id]);
      squareClient = createSquareClient(first);
    }
  }

  res.json({ success: true });
});

// GET locations
app.get('/api/profiles/:id/locations', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, '/v2/locations'));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });

  // Get transaction totals from DB
  const totals = {};
  const txRows = dbAll(
    "SELECT location_id, type, SUM(amount) as total, COUNT(*) as count FROM transactions WHERE profile_id = ? AND status != 'FAILED' GROUP BY location_id, type",
    [profile.id]
  );
  for (const row of txRows) {
    const locId = row.location_id || profile.location_id;
    if (!totals[locId]) totals[locId] = { charged: 0, links: 0, count: 0 };
    totals[locId].count += row.count;
    if (row.type === 'charge') totals[locId].charged += row.total;
    if (row.type === 'link') totals[locId].links += row.total;
  }

  res.json({
    locations: (r.body.locations || []).map(l => ({
      id: l.id, name: l.name, business_name: l.business_name || '',
      status: l.status, description: l.description || '',
      phone_number: l.phone_number || '', business_email: l.business_email || '',
      website_url: l.website_url || '', instagram_username: l.instagram_username || '',
      twitter_username: l.twitter_username || '', facebook_url: l.facebook_url || '',
      address: l.address ? [l.address.address_line_1, l.address.locality, l.address.administrative_district_level_1].filter(Boolean).join(', ') : null,
      address_line_1: l.address?.address_line_1 || '', city: l.address?.locality || '',
      state: l.address?.administrative_district_level_1 || '', postal_code: l.address?.postal_code || '',
      currency: l.currency, country: l.country, timezone: l.timezone, type: l.type,
      created_at: l.created_at || null, isActive: l.id === profile.location_id,
      canProcessPayments: Array.isArray(l.capabilities) && l.capabilities.includes('CREDIT_CARD_PROCESSING'),
      capabilities: l.capabilities || [],
      totals: totals[l.id] || { charged: 0, links: 0, count: 0 },
    })),
  });
});

// Update location
app.put('/api/profiles/:id/locations/:locId', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  const { name, business_name, description, address_line_1, city, state, postal_code, country,
          phone_number, business_email, website_url, timezone,
          instagram_username, twitter_username, facebook_url } = req.body;

  if (!name) return res.status(400).json({ error: 'Name is required' });

  const locationBody = {
    location: {
      name,
      business_name:      business_name      || undefined,
      description:        description        || undefined,
      phone_number:       phone_number       || undefined,
      business_email:     business_email     || undefined,
      website_url:        website_url        || undefined,
      timezone:           timezone           || undefined,
      instagram_username: instagram_username || undefined,
      twitter_username:   twitter_username   || undefined,
      facebook_url:       facebook_url       || undefined,
      ...(address_line_1 ? {
        address: {
          address_line_1,
          locality: city || undefined,
          administrative_district_level_1: state || undefined,
          postal_code: postal_code || undefined,
          country: country || 'US',
        }
      } : {}),
    }
  };

  const r = await safeSquareCall(profile, (token) => squareRequest('PUT', token, `/v2/locations/${req.params.locId}`, locationBody));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ success: true, location: r.body.location });
});

// Create location
app.post('/api/profiles/:id/locations', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { name, address_line_1, city, state, postal_code, timezone, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const r = await safeSquareCall(profile, (token) =>
    squarePost(token, '/v2/locations', {
      location: { name, description, timezone: timezone || 'America/New_York',
        ...(address_line_1 ? { address: { address_line_1, locality: city, administrative_district_level_1: state, postal_code, country: 'US' } } : {})
      }
    })
  );
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ success: true, location: r.body.location });
});

// Report
app.get('/api/profiles/:id/report', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const period = req.query.period || 'month';
  const now = new Date();
  let beginTime;
  if      (period === 'today')  beginTime = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  else if (period === 'week')   beginTime = new Date(now - 7 * 24 * 60 * 60 * 1000);
  else if (period === 'month')  beginTime = new Date(now.getFullYear(), now.getMonth(), 1);
  else if (period === 'year')   beginTime = new Date(now.getFullYear(), 0, 1);
  else if (period === 'custom' && req.query.begin) beginTime = new Date(req.query.begin);
  else beginTime = new Date(now.getFullYear(), now.getMonth(), 1);
  const endTime = req.query.end ? new Date(req.query.end) : now;

  const locResult = await safeSquareCall(profile, (token) => squareGet(token, '/v2/locations'));
  if (locResult.tokenExpired) return res.status(401).json({ error: locResult.body.errors[0].detail, tokenExpired: true });
  if (locResult.status !== 200) return res.status(locResult.status).json({ error: locResult.body?.errors?.[0]?.detail || 'Failed to fetch locations' });
  const locations = locResult.body.locations || [];
  const accessToken = getDecryptedToken(profile);

  const reportByLocation = [];
  for (const loc of locations) {
    if (loc.status !== 'ACTIVE') { reportByLocation.push({ locationId: loc.id, locationName: loc.name, status: loc.status }); continue; }
    let allPayments = [], cursor = null;
    do {
      const params = new URLSearchParams({ location_id: loc.id, begin_time: beginTime.toISOString(), end_time: endTime.toISOString(), limit: '100', sort_order: 'DESC' });
      if (cursor) params.set('cursor', cursor);
      const r = await squareGet(accessToken, `/v2/payments?${params}`);
      if (r.status === 401) {
        return res.status(401).json({ error: `Токен для "${profile.name}" истёк. Обновите в настройках.`, tokenExpired: true });
      }
      if (r.status !== 200) break;
      allPayments = allPayments.concat(r.body.payments || []);
      cursor = r.body.cursor || null;
      if (allPayments.length >= 500) break;
    } while (cursor);

    let totalAmount = 0, totalFees = 0, totalRefunds = 0, countOk = 0, countFailed = 0;
    for (const p of allPayments) {
      if (p.status === 'COMPLETED') { totalAmount += Number(p.amount_money?.amount || 0); totalFees += Number(p.processing_fee?.[0]?.amount_money?.amount || 0); countOk++; }
      else if (['FAILED','CANCELED'].includes(p.status)) countFailed++;
      if (p.refunded_money) totalRefunds += Number(p.refunded_money?.amount || 0);
    }
    const fmt = v => (v / 100).toFixed(2);
    reportByLocation.push({ locationId: loc.id, locationName: loc.name, status: loc.status, currency: loc.currency || 'USD', totalAmount: fmt(totalAmount), totalFees: fmt(totalFees), totalRefunds: fmt(totalRefunds), net: fmt(totalAmount - totalFees - totalRefunds), countOk, countFailed, totalPayments: allPayments.length });
  }
  res.json({ period, beginTime: beginTime.toISOString(), endTime: endTime.toISOString(), locations: reportByLocation });
});

// Charge
app.post('/api/charge', requireAuth, async (req, res) => {
  const { sourceId, amount, currency, note, buyerEmail, verificationToken } = req.body;
  if (!sourceId || !amount) return res.status(400).json({ error: 'sourceId and amount required' });
  const profile = getActiveProfile();
  if (!profile) return res.status(400).json({ error: 'No active profile' });
  if (profile.max_amount && parseFloat(amount) > profile.max_amount) return res.status(400).json({ success: false, errors: [{ detail: `Amount exceeds limit of $${profile.max_amount.toFixed(2)}` }] });
  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const client = createSquareClient(profile);
    const response = await client.paymentsApi.createPayment({
      sourceId, idempotencyKey: uuidv4(),
      amountMoney: { amount: BigInt(amountCents), currency: currency || 'USD' },
      locationId: profile.location_id, note: note || '',
      buyerEmailAddress: buyerEmail || undefined,
      verificationToken: verificationToken || undefined,
    });
    const payment = response.result.payment;
    addTransaction(profile.id, { id: payment.id, type: 'charge', amount: parseFloat(amount), currency: currency || 'USD', note: note || '', buyerEmail: buyerEmail || '', status: payment.status, receiptUrl: payment.receiptUrl || '', createdAt: new Date().toISOString() });
    res.json({ success: true, paymentId: payment.id, status: payment.status, amount: { amount: payment.amountMoney?.amount?.toString(), currency: payment.amountMoney?.currency }, receiptUrl: payment.receiptUrl });
  } catch (err) {
    // Check if it's an auth error
    if (err.statusCode === 401) {
      return res.status(401).json({ success: false, tokenExpired: true, errors: [{ detail: `Токен для "${profile.name}" истёк. Обновите в настройках.` }] });
    }
    addTransaction(profile.id, { id: 'err-' + uuidv4().slice(0,8), type: 'charge', amount: parseFloat(amount), currency: currency||'USD', note: note||'', buyerEmail: buyerEmail||'', status: 'FAILED', error: (err.errors||[{detail:err.message}]).map(e=>e.detail).join('; '), createdAt: new Date().toISOString() });
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

// Payment Link
app.post('/api/payment-link', requireAuth, async (req, res) => {
  const { amount, currency, title, description, locationId } = req.body;
  if (!amount) return res.status(400).json({ error: 'amount required' });
  const profile = getActiveProfile();
  if (!profile) return res.status(400).json({ error: 'No active profile' });
  if (profile.max_amount && parseFloat(amount) > profile.max_amount) return res.status(400).json({ success: false, errors: [{ detail: `Amount exceeds limit of $${profile.max_amount.toFixed(2)}` }] });
  const usedLocationId = locationId || profile.location_id;
  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const client = createSquareClient(profile);
    const response = await client.checkoutApi.createPaymentLink({
      idempotencyKey: uuidv4(),
      quickPay: { name: title || 'Payment', priceMoney: { amount: BigInt(amountCents), currency: currency || 'USD' }, locationId: usedLocationId },
      description: description || '',
    });
    const link = response.result.paymentLink;
    addTransaction(profile.id, { id: link.id, type: 'link', amount: parseFloat(amount), currency: currency||'USD', note: title||'', locationId: usedLocationId, status: 'LINK_CREATED', url: link.url, createdAt: new Date().toISOString() });
    res.json({ success: true, url: link.url, linkId: link.id });
  } catch (err) {
    if (err.statusCode === 401) {
      return res.status(401).json({ success: false, tokenExpired: true, errors: [{ detail: `Токен для "${profile.name}" истёк. Обновите в настройках.` }] });
    }
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

// Customers
app.get('/api/profiles/:id/customers', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const cursor = req.query.cursor || null;
  const query = req.query.query || '';
  try {
    let customers = [], newCursor = null;
    const accessToken = getDecryptedToken(profile);
    if (query) {
      const body = { query: { filter: { text_filter: { fuzzy: query } } }, limit: 50 };
      if (cursor) body.cursor = cursor;
      const r = await squarePost(accessToken, '/v2/customers/search', body);
      if (r.status === 401) return res.status(401).json({ error: `Токен для "${profile.name}" истёк. Обновите в настройках.`, tokenExpired: true });
      if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
      customers = r.body.customers || [];
      newCursor = r.body.cursor || null;
    } else {
      let apiPath = '/v2/customers?limit=100&sort_field=CREATED_AT&sort_order=DESC';
      if (cursor) apiPath += `&cursor=${encodeURIComponent(cursor)}`;
      const r = await squareGet(accessToken, apiPath);
      if (r.status === 401) return res.status(401).json({ error: `Токен для "${profile.name}" истёк. Обновите в настройках.`, tokenExpired: true });
      if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
      customers = r.body.customers || [];
      newCursor = r.body.cursor || null;
    }
    res.json({ customers: customers.map(c => ({
      id: c.id, givenName: c.given_name || '', familyName: c.family_name || '',
      email: c.email_address || '', phone: c.phone_number || '', createdAt: c.created_at,
      source: c.creation_source || '', note: c.note || '', segmentIds: c.segment_ids || [],
    })), cursor: newCursor });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Single customer
app.get('/api/profiles/:id/customers/:cid', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/customers/${req.params.cid}`));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const c = r.body.customer;
  res.json({ id: c.id, givenName: c.given_name || '', familyName: c.family_name || '',
    email: c.email_address || '', phone: c.phone_number || '', createdAt: c.created_at,
    updatedAt: c.updated_at, source: c.creation_source || '', note: c.note || '',
    segmentIds: c.segment_ids || [],
    address: c.address ? [c.address.address_line_1, c.address.locality, c.address.administrative_district_level_1].filter(Boolean).join(', ') : '',
    birthday: c.birthday || '', referenceId: c.reference_id || '',
  });
});

// Customer segments
app.get('/api/profiles/:id/customer-segments', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, '/v2/customers/segments?limit=50'));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ segments: (r.body.segments || []).map(s => ({ id: s.id, name: s.name })) });
});

// Customer payments
app.get('/api/profiles/:id/customers/:cid/payments', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const accessToken = getDecryptedToken(profile);
  try {
    const locRes = await squareGet(accessToken, '/v2/locations');
    if (locRes.status === 401) return res.status(401).json({ error: `Токен для "${profile.name}" истёк.`, tokenExpired: true });
    const locationIds = (locRes.body?.locations || []).filter(l => l.status === 'ACTIVE').map(l => l.id);
    const body = { location_ids: locationIds,
      query: { filter: { customer_filter: { customer_ids: [req.params.cid] } }, sort: { sort_field: 'CREATED_AT', sort_order: 'DESC' } },
      limit: 50 };
    const r = await squarePost(accessToken, '/v2/orders/search', body);
    if (r.status === 401) return res.status(401).json({ error: `Токен для "${profile.name}" истёк.`, tokenExpired: true });
    if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
    const orders = r.body.orders || [];
    res.json({ payments: orders.map(o => ({
      orderId: o.id, state: o.state,
      total: ((o.total_money?.amount || 0) / 100).toFixed(2),
      currency: o.total_money?.currency || 'USD', createdAt: o.created_at,
      lineItems: (o.line_items || []).map(i => ({ name: i.name, qty: i.quantity, price: ((i.base_price_money?.amount || 0) / 100).toFixed(2) })),
      paymentId: o.tenders?.[0]?.payment_id || null,
    }))});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Square Terminal running on port ${PORT}`));
