require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');
let HttpsProxyAgent, SocksProxyAgent;
try { HttpsProxyAgent = require('https-proxy-agent').HttpsProxyAgent; } catch (_) {}
try { SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent; } catch (_) {}
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

// Add proxy_url column if missing
try { db.exec("ALTER TABLE profiles ADD COLUMN proxy_url TEXT DEFAULT ''"); } catch (_) {}

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
function getProxyAgent(proxyUrl) {
  if (!proxyUrl) return null;
  try {
    if (proxyUrl.startsWith('socks')) {
      if (!SocksProxyAgent) { console.warn('socks-proxy-agent not installed'); return null; }
      return new SocksProxyAgent(proxyUrl);
    }
    // HTTP/HTTPS proxy
    if (!HttpsProxyAgent) { console.warn('https-proxy-agent not installed'); return null; }
    return new HttpsProxyAgent(proxyUrl);
  } catch (e) { console.error('Proxy agent error:', e.message); return null; }
}

function squareRequest(method, accessToken, apiPath, body, proxyUrl) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const agent = getProxyAgent(proxyUrl !== undefined ? proxyUrl : _currentProxy);
    const req = https.request({
      hostname: 'connect.squareup.com',
      path: apiPath, method,
      ...(agent ? { agent } : {}),
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

const squareGet  = (t, p)    => squareRequest('GET',  t, p, null, _currentProxy);
const squarePost = (t, p, b) => squareRequest('POST', t, p, b, _currentProxy);

// ── Square Token Validation Wrapper ─────────────────────────────────────────
// Wraps Square API calls to detect expired/invalid tokens and return clear errors
// currentProxy is set per-call for squareGet/squarePost to pick up
let _currentProxy = '';
async function safeSquareCall(profile, apiCall) {
  try {
    _currentProxy = profile.proxy_url || '';
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
        proxyUrl: p.proxy_url || '',
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

// GET payouts
app.get('/api/profiles/:id/payouts', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const cursor = req.query.cursor || '';
  const qs = `location_id=${profile.location_id}&limit=${limit}${cursor ? '&cursor=' + cursor : ''}`;
  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/payouts?${qs}`));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const payouts = (r.body.payouts || []).map(p => ({
    id: p.id,
    status: p.status,
    amount: (Number(p.amount_money?.amount || 0) / 100).toFixed(2),
    currency: p.amount_money?.currency || 'USD',
    createdAt: p.created_at,
    updatedAt: p.updated_at,
    arrivalDate: p.arrival_date || null,
    type: p.type,
    destinationType: p.destination?.type || null,
    destinationId: p.destination?.id || null,
    endToEndId: p.end_to_end_id || null,
  }));
  res.json({ payouts, cursor: r.body.cursor || null });
});

// GET payout entries (breakdown of a single payout)
app.get('/api/profiles/:id/payouts/:payoutId/entries', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  const payoutId = req.params.payoutId;
  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/payouts/${payoutId}/payout-entries?limit=100`));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const entries = (r.body.payout_entries || []).map(e => ({
    id: e.id,
    type: e.type,
    grossAmount: (Number(e.gross_amount_money?.amount || 0) / 100).toFixed(2),
    netAmount: (Number(e.net_amount_money?.amount || 0) / 100).toFixed(2),
    feeAmount: (Number(e.fee_amount_money?.amount || 0) / 100).toFixed(2),
    currency: e.gross_amount_money?.currency || e.net_amount_money?.currency || 'USD',
    effectiveAt: e.effective_at || null,
    paymentId: e.type_charge_details?.payment_id || e.type_refund_details?.payment_id || null,
    refundId: e.type_refund_details?.refund_id || null,
    feeType: e.type_fee_details?.type || null,
  }));
  // Summarize by type
  const summary = { charges: 0, chargeCount: 0, refunds: 0, refundCount: 0, fees: 0, feeCount: 0, adjustments: 0, adjustmentCount: 0, other: 0, otherCount: 0, totalFees: 0, totalNet: 0 };
  for (const e of entries) {
    const amt = parseFloat(e.grossAmount);
    summary.totalFees += parseFloat(e.feeAmount);
    summary.totalNet += parseFloat(e.netAmount);
    if (e.type === 'CHARGE') { summary.charges += amt; summary.chargeCount++; }
    else if (e.type === 'REFUND') { summary.refunds += amt; summary.refundCount++; }
    else if (e.type === 'FEE' || e.type === 'SQUARE_CAPITAL_PAYMENT' || e.type === 'SQUARE_CAPITAL_REVERSED_PAYMENT') { summary.fees += amt; summary.feeCount++; }
    else if (e.type === 'ADJUSTMENT' || e.type === 'BALANCE_ADJUSTMENT') { summary.adjustments += amt; summary.adjustmentCount++; }
    else { summary.other += amt; summary.otherCount++; }
  }
  res.json({ entries, summary });
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

// Check IP (through proxy if configured, or direct)
app.get('/api/profiles/:id/check-ip', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const proxyUrl = profile.proxy_url || '';
  const agent = getProxyAgent(proxyUrl);
  try {
    const result = await new Promise((resolve, reject) => {
      const r = https.request({
        hostname: 'api.ipify.org',
        path: '/?format=json',
        method: 'GET',
        ...(agent ? { agent } : {}),
        timeout: 10000,
      }, response => {
        let data = '';
        response.on('data', c => data += c);
        response.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch { resolve({ ip: data.trim() }); }
        });
      });
      r.on('error', reject);
      r.on('timeout', () => { r.destroy(); reject(new Error('Timeout')); });
      r.end();
    });
    res.json({ ip: result.ip, proxy: !!proxyUrl, proxyUrl: proxyUrl ? proxyUrl.replace(/\/\/([^:]+):([^@]+)@/, '//$1:***@') : null });
  } catch (e) {
    res.json({ error: e.message, proxy: !!proxyUrl, proxyUrl: proxyUrl ? proxyUrl.replace(/\/\/([^:]+):([^@]+)@/, '//$1:***@') : null });
  }
});

// Health check — gather account status from multiple APIs
app.get('/api/profiles/:id/health', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const accessToken = getDecryptedToken(profile);
  _currentProxy = profile.proxy_url || '';

  const results = {};

  // 1. Merchant info
  try {
    const r = await squareGet(accessToken, '/v2/merchants/me');
    if (r.status === 200) {
      const m = r.body.merchant;
      results.merchant = { status: m.status, country: m.country, currency: m.currency, businessName: m.business_name, createdAt: m.created_at, mainLocationId: m.main_location_id };
    } else {
      results.merchant = { error: r.body?.errors?.[0]?.detail || `HTTP ${r.status}` };
    }
  } catch (e) { results.merchant = { error: e.message }; }

  // 2. Location details + capabilities
  try {
    const r = await squareGet(accessToken, '/v2/locations');
    if (r.status === 200) {
      results.locations = (r.body.locations || []).map(l => ({
        id: l.id, name: l.name, status: l.status,
        capabilities: l.capabilities || [],
        address: [l.address?.address_line_1, l.address?.locality, l.address?.administrative_district_level_1, l.address?.postal_code].filter(Boolean).join(', '),
        mcc: l.mcc || null,
        type: l.type || null,
        currency: l.currency || 'USD',
      }));
    } else {
      results.locations = { error: r.body?.errors?.[0]?.detail || `HTTP ${r.status}` };
    }
  } catch (e) { results.locations = { error: e.message }; }

  // 3. Bank accounts
  try {
    const r = await squareGet(accessToken, '/v2/bank-accounts');
    if (r.status === 200) {
      results.bankAccounts = (r.body.bank_accounts || []).map(a => ({
        bankName: a.bank_name, last4: a.account_number_suffix, status: a.status,
        creditable: a.creditable, debitable: a.debitable, holderName: a.holder_name || a.account_holder_name || null,
      }));
    } else {
      results.bankAccounts = { error: r.body?.errors?.[0]?.detail || `HTTP ${r.status}` };
    }
  } catch (e) { results.bankAccounts = { error: e.message }; }

  // 4. Disputes (open)
  try {
    const r = await squareGet(accessToken, '/v2/disputes?states=INQUIRY_EVIDENCE_REQUIRED,EVIDENCE_REQUIRED,PROCESSING&limit=10');
    if (r.status === 200) {
      results.disputes = { count: (r.body.disputes || []).length, items: (r.body.disputes || []).slice(0, 5).map(d => ({ id: d.id, state: d.state, amount: d.amount_money, reason: d.reason, createdAt: d.created_at })) };
    } else {
      results.disputes = { count: 0, error: r.body?.errors?.[0]?.detail };
    }
  } catch (e) { results.disputes = { count: 0, error: e.message }; }

  // 5. Live tests — actually try create operations to see what's blocked
  const liveTests = {};

  // Test: Create Order
  try {
    const r = await squarePost(accessToken, '/v2/orders', {
      order: { location_id: profile.location_id, line_items: [{ name: 'Health Check Test', quantity: '1', base_price_money: { amount: 1, currency: 'USD' } }] },
      idempotency_key: 'health-test-order-' + Date.now(),
    });
    if (r.status === 200) {
      liveTests.createOrder = { status: 'ok', orderId: r.body.order.id };
    } else {
      liveTests.createOrder = { status: 'error', detail: r.body?.errors?.[0]?.detail || `HTTP ${r.status}` };
    }
  } catch (e) { liveTests.createOrder = { status: 'error', detail: e.message }; }

  // Test: Create Invoice (requires order)
  if (liveTests.createOrder?.orderId) {
    try {
      const r = await squarePost(accessToken, '/v2/invoices', {
        invoice: {
          location_id: profile.location_id,
          order_id: liveTests.createOrder.orderId,
          delivery_method: 'SHARE_MANUALLY',
          payment_requests: [{ request_type: 'BALANCE', due_date: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10) }],
          accepted_payment_methods: { card: true, square_gift_card: false, bank_account: false, buy_now_pay_later: false, cash_app_pay: false },
        },
        idempotency_key: 'health-test-inv-' + Date.now(),
      });
      if (r.status === 200) {
        liveTests.createInvoice = { status: 'ok', invoiceId: r.body.invoice.id, version: r.body.invoice.version };
        // Clean up — delete the draft invoice
        try { await squareRequest('DELETE', accessToken, `/v2/invoices/${r.body.invoice.id}?version=${r.body.invoice.version}`, null); } catch (_) {}
      } else {
        liveTests.createInvoice = { status: 'error', detail: r.body?.errors?.[0]?.detail || `HTTP ${r.status}` };
      }
    } catch (e) { liveTests.createInvoice = { status: 'error', detail: e.message }; }
  } else {
    liveTests.createInvoice = { status: 'skip', detail: 'Order creation failed' };
  }

  // Test: Charge Payment (with fake nonce — will fail with specific error)
  try {
    const r = await squarePost(accessToken, '/v2/payments', {
      source_id: 'cnon:card-nonce-ok',
      amount_money: { amount: 1, currency: 'USD' },
      location_id: profile.location_id,
      idempotency_key: 'health-test-pay-' + Date.now(),
    });
    if (r.status === 200) {
      liveTests.chargePayment = { status: 'ok', detail: 'Payment would succeed' };
      // Refund immediately if somehow it went through
      if (r.body.payment?.id) {
        try { await squarePost(accessToken, '/v2/refunds', { payment_id: r.body.payment.id, amount_money: { amount: 1, currency: 'USD' }, idempotency_key: 'health-refund-' + Date.now() }); } catch (_) {}
      }
    } else {
      const detail = r.body?.errors?.[0]?.detail || `HTTP ${r.status}`;
      const code = r.body?.errors?.[0]?.code || '';
      // "not enabled to take payments" = account blocked
      // "INVALID_CARD_DATA" or "VERIFY_CVV/AVS" = permission ok, card just fake
      const isPermOk = code === 'INVALID_CARD_DATA' || code === 'VERIFY_CVV_FAILURE' || code === 'VERIFY_AVS_FAILURE' || code === 'BAD_REQUEST';
      if (detail.includes('not been enabled')) {
        liveTests.chargePayment = { status: 'blocked', detail };
      } else if (r.status === 400 || isPermOk) {
        liveTests.chargePayment = { status: 'ok', detail: 'Can process payments (test nonce rejected as expected)' };
      } else {
        liveTests.chargePayment = { status: 'error', detail };
      }
    }
  } catch (e) { liveTests.chargePayment = { status: 'error', detail: e.message }; }

  results.liveTests = liveTests;

  res.json(results);
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
  const { id, name, accessToken, applicationId, locationId, maxAmount, proxyUrl } = req.body;
  if (!name || !applicationId || !locationId) return res.status(400).json({ error: 'name, applicationId and locationId are required' });

  if (id) {
    const p = getProfileById(id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    dbRun(
      `UPDATE profiles SET name = ?, application_id = ?, location_id = ?, max_amount = ?, proxy_url = ?, updated_at = datetime('now') WHERE id = ?`,
      [name, applicationId, locationId, maxAmount ? parseFloat(maxAmount) : null, proxyUrl || '', id]
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
      `INSERT INTO profiles (id, name, access_token, application_id, location_id, max_amount, proxy_url, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [newId, name, encrypt(accessToken), applicationId, locationId, maxAmount ? parseFloat(maxAmount) : null, proxyUrl || '', profileCount === 0 ? 1 : 0]
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
  _currentProxy = profile.proxy_url || '';

  // Helper to paginate Square API calls
  async function fetchAllPages(token, path, key, maxItems = 500) {
    let all = [], cursor = null;
    do {
      const sep = path.includes('?') ? '&' : '?';
      const url = cursor ? `${path}${sep}cursor=${cursor}` : path;
      const r = await squareGet(token, url);
      if (r.status === 401) throw { tokenExpired: true, detail: `Токен для "${profile.name}" истёк. Обновите в настройках.` };
      if (r.status !== 200) break;
      all = all.concat(r.body[key] || []);
      cursor = r.body.cursor || null;
      if (all.length >= maxItems) break;
    } while (cursor);
    return all;
  }

  try {
    const reportByLocation = [];
    for (const loc of locations) {
      if (loc.status !== 'ACTIVE') { reportByLocation.push({ locationId: loc.id, locationName: loc.name, status: loc.status }); continue; }

      // Fetch payments for this location + period
      const payParams = `location_id=${loc.id}&begin_time=${beginTime.toISOString()}&end_time=${endTime.toISOString()}&limit=100&sort_order=DESC`;
      const allPayments = await fetchAllPages(accessToken, `/v2/payments?${payParams}`, 'payments');

      let totalAmount = 0, totalTips = 0, totalFees = 0, totalRefunds = 0, countOk = 0, countFailed = 0, countRefunded = 0;
      const paymentMethods = {};
      for (const p of allPayments) {
        if (p.status === 'COMPLETED') {
          totalAmount += Number(p.amount_money?.amount || 0);
          totalTips += Number(p.tip_money?.amount || 0);
          // Sum ALL processing fees (not just [0])
          for (const fee of (p.processing_fee || [])) totalFees += Number(fee.amount_money?.amount || 0);
          countOk++;
          // Payment method breakdown
          const method = p.source_type || 'OTHER';
          paymentMethods[method] = (paymentMethods[method] || 0) + 1;
        }
        else if (['FAILED','CANCELED'].includes(p.status)) countFailed++;
        if (p.refunded_money) {
          totalRefunds += Number(p.refunded_money.amount || 0);
          countRefunded++;
        }
      }
      const fmt = v => (v / 100).toFixed(2);
      const avgTransaction = countOk > 0 ? totalAmount / countOk : 0;
      const refundRate = countOk > 0 ? ((countRefunded / countOk) * 100).toFixed(1) : '0.0';

      reportByLocation.push({
        locationId: loc.id, locationName: loc.name, status: loc.status,
        currency: loc.currency || 'USD',
        totalAmount: fmt(totalAmount),
        totalTips: fmt(totalTips),
        totalFees: fmt(totalFees),
        totalRefunds: fmt(totalRefunds),
        net: fmt(totalAmount - totalFees - totalRefunds),
        countOk, countFailed, countRefunded,
        totalPayments: allPayments.length,
        avgTransaction: fmt(avgTransaction),
        refundRate,
        paymentMethods,
      });
    }

    // Fetch refunds separately (gives more detail than payment.refunded_money)
    const refundParams = `begin_time=${beginTime.toISOString()}&end_time=${endTime.toISOString()}&limit=100&sort_order=DESC`;
    const allRefunds = await fetchAllPages(accessToken, `/v2/refunds?${refundParams}`, 'refunds');
    const refundBreakdown = { total: 0, count: allRefunds.length, reasons: {} };
    for (const r of allRefunds) {
      refundBreakdown.total += Number(r.amount_money?.amount || 0);
      const reason = r.reason || 'No reason';
      refundBreakdown.reasons[reason] = (refundBreakdown.reasons[reason] || 0) + 1;
    }
    refundBreakdown.total = (refundBreakdown.total / 100).toFixed(2);

    // Fetch disputes (chargebacks)
    let disputes = [];
    try {
      const dispResult = await squareGet(accessToken, `/v2/disputes?states=INQUIRY_EVIDENCE_REQUIRED,INQUIRY_PROCESSING,INQUIRY_CLOSED,EVIDENCE_REQUIRED,PROCESSING,WON,LOST&limit=50`);
      if (dispResult.status === 200) disputes = dispResult.body.disputes || [];
    } catch (_) {}
    const disputeBreakdown = { total: 0, count: disputes.length, won: 0, lost: 0, pending: 0, totalLost: 0 };
    for (const d of disputes) {
      const amt = Number(d.disputed_payment?.amount_money?.amount || d.amount_money?.amount || 0);
      disputeBreakdown.total += amt;
      if (d.state === 'WON' || d.state === 'INQUIRY_CLOSED') disputeBreakdown.won++;
      else if (d.state === 'LOST') { disputeBreakdown.lost++; disputeBreakdown.totalLost += amt; }
      else disputeBreakdown.pending++;
    }
    disputeBreakdown.total = (disputeBreakdown.total / 100).toFixed(2);
    disputeBreakdown.totalLost = (disputeBreakdown.totalLost / 100).toFixed(2);

    // Fetch payouts total (all time — for balance calculation)
    let payoutTotal = 0, payoutCount = 0;
    try {
      const payoutParams = `location_id=${profile.location_id}&limit=100`;
      const allPayouts = await fetchAllPages(accessToken, `/v2/payouts?${payoutParams}`, 'payouts', 200);
      for (const p of allPayouts) {
        if (p.status === 'PAID' || p.status === 'SENT') {
          payoutTotal += Number(p.amount_money?.amount || 0);
          payoutCount++;
        }
      }
    } catch (_) {}

    // Calculate estimated balance: gross - fees - refunds - disputes_lost - payouts
    const activeLocs = reportByLocation.filter(l => l.status === 'ACTIVE');
    const grossCents = activeLocs.reduce((s, l) => s + Math.round(parseFloat(l.totalAmount) * 100), 0);
    const feesCents = activeLocs.reduce((s, l) => s + Math.round(parseFloat(l.totalFees) * 100), 0);
    const refundsCents = activeLocs.reduce((s, l) => s + Math.round(parseFloat(l.totalRefunds) * 100), 0);
    const disputeLostCents = Math.round(parseFloat(disputeBreakdown.totalLost) * 100);
    const estimatedBalance = ((grossCents - feesCents - refundsCents - disputeLostCents - payoutTotal) / 100).toFixed(2);

    res.json({
      period, beginTime: beginTime.toISOString(), endTime: endTime.toISOString(),
      locations: reportByLocation,
      refunds: refundBreakdown,
      disputes: disputeBreakdown,
      payouts: { total: (payoutTotal / 100).toFixed(2), count: payoutCount },
      estimatedBalance,
    });
  } catch (err) {
    if (err.tokenExpired) return res.status(401).json({ error: err.detail, tokenExpired: true });
    throw err;
  }
});

// ── Invoices ──────────────────────────────────────────────────────────────────

// LIST invoices (with optional status filter)
app.get('/api/profiles/:id/invoices', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const cursor = req.query.cursor || '';
  const qs = `location_id=${profile.location_id}&limit=${limit}${cursor ? '&cursor=' + cursor : ''}`;
  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/invoices?${qs}`));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const statusFilter = req.query.status || '';
  let invoices = (r.body.invoices || []).map(inv => ({
    id: inv.id, version: inv.version, status: inv.status,
    invoiceNumber: inv.invoice_number || null,
    title: inv.title || null,
    description: inv.description || null,
    publicUrl: inv.public_url || null,
    createdAt: inv.created_at,
    updatedAt: inv.updated_at,
    scheduledAt: inv.scheduled_at || null,
    totalMoney: inv.payment_requests?.[0]?.computed_amount_money || inv.payment_requests?.[0]?.fixed_amount_requested_money || null,
    nextPaymentAmount: inv.next_payment_amount_money || null,
    dueDate: inv.payment_requests?.[0]?.due_date || null,
    deliveryMethod: inv.delivery_method || null,
    orderId: inv.order_id || null,
    customerName: null,
    customerId: inv.primary_recipient?.customer_id || null,
    acceptedMethods: inv.accepted_payment_methods || {},
    paymentRequests: (inv.payment_requests || []).map(pr => ({
      requestType: pr.request_type, dueDate: pr.due_date,
      amount: pr.computed_amount_money || pr.fixed_amount_requested_money || null,
      tippingEnabled: pr.tipping_enabled || false,
      automaticPaymentSource: pr.automatic_payment_source || 'NONE',
    })),
  }));
  if (statusFilter) invoices = invoices.filter(i => i.status === statusFilter);
  res.json({ invoices, cursor: r.body.cursor || null });
});

// SEARCH invoices (by status, customer, dates)
app.post('/api/profiles/:id/invoices/search', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { statuses, customerId, startDate, endDate } = req.body;
  const query = { filter: { location_ids: [profile.location_id] }, limit: 50 };
  if (statuses?.length) query.filter.status = statuses;
  if (customerId) query.filter.customer_ids = [customerId];
  if (startDate || endDate) {
    query.filter.date_range = {};
    if (startDate) query.filter.date_range.start_at = startDate;
    if (endDate) query.filter.date_range.end_at = endDate;
  }
  const r = await safeSquareCall(profile, (token) => squarePost(token, '/v2/invoices/search', { query }));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  const invoices = (r.body.invoices || []).map(inv => ({
    id: inv.id, version: inv.version, status: inv.status,
    invoiceNumber: inv.invoice_number || null,
    title: inv.title || null,
    publicUrl: inv.public_url || null,
    createdAt: inv.created_at,
    totalMoney: inv.payment_requests?.[0]?.computed_amount_money || inv.payment_requests?.[0]?.fixed_amount_requested_money || null,
    dueDate: inv.payment_requests?.[0]?.due_date || null,
    customerId: inv.primary_recipient?.customer_id || null,
  }));
  res.json({ invoices });
});

// GET single invoice detail
app.get('/api/profiles/:id/invoices/:invoiceId', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const r = await safeSquareCall(profile, (token) => squareGet(token, `/v2/invoices/${req.params.invoiceId}`));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ invoice: r.body.invoice });
});

// CREATE invoice (creates order + draft invoice)
app.post('/api/profiles/:id/invoices', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { title, description, customerId, items, dueDate, deliveryMethod, acceptCard, acceptBankTransfer, acceptCash, invoiceNumber, saleDateStr, tippingEnabled, autoPaySource } = req.body;
  if (!items?.length) return res.status(400).json({ error: 'At least one item is required' });
  if (!customerId) return res.status(400).json({ error: 'Customer is required' });

  const accessToken = getDecryptedToken(profile);
  _currentProxy = profile.proxy_url || '';

  // 1. Create Order
  const lineItems = items.map(item => ({
    name: item.name || 'Item',
    quantity: String(item.quantity || 1),
    base_price_money: { amount: Math.round(parseFloat(item.price) * 100), currency: 'USD' },
  }));
  const orderBody = {
    order: { location_id: profile.location_id, line_items: lineItems },
    idempotency_key: crypto.randomUUID(),
  };
  const orderRes = await squarePost(accessToken, '/v2/orders', orderBody);
  if (orderRes.status !== 200) {
    return res.status(orderRes.status).json({ error: orderRes.body?.errors?.[0]?.detail || 'Failed to create order' });
  }
  const orderId = orderRes.body.order.id;

  // 2. Create Invoice (draft)
  const invoiceBody = {
    invoice: {
      location_id: profile.location_id,
      order_id: orderId,
      primary_recipient: { customer_id: customerId },
      delivery_method: deliveryMethod || 'EMAIL',
      payment_requests: [{
        request_type: 'BALANCE',
        due_date: dueDate || new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
        tipping_enabled: tippingEnabled || false,
        automatic_payment_source: autoPaySource || 'NONE',
      }],
      accepted_payment_methods: {
        card: acceptCard !== false,
        square_gift_card: false,
        bank_account: acceptBankTransfer || false,
        buy_now_pay_later: false,
        cash_app_pay: acceptCash || false,
      },
    },
    idempotency_key: crypto.randomUUID(),
  };
  if (title) invoiceBody.invoice.title = title;
  if (description) invoiceBody.invoice.description = description;
  if (invoiceNumber) invoiceBody.invoice.invoice_number = invoiceNumber;
  if (saleDateStr) invoiceBody.invoice.sale_or_service_date = saleDateStr;

  const invRes = await squarePost(accessToken, '/v2/invoices', invoiceBody);
  if (invRes.status !== 200) {
    return res.status(invRes.status).json({ error: invRes.body?.errors?.[0]?.detail || 'Failed to create invoice' });
  }
  res.json({ invoice: invRes.body.invoice });
});

// PUBLISH invoice (sends to customer)
app.post('/api/profiles/:id/invoices/:invoiceId/publish', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { version } = req.body;
  const r = await safeSquareCall(profile, (token) => squarePost(token, `/v2/invoices/${req.params.invoiceId}/publish`, {
    version: version || 0,
    idempotency_key: crypto.randomUUID(),
  }));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ invoice: r.body.invoice });
});

// CANCEL invoice
app.post('/api/profiles/:id/invoices/:invoiceId/cancel', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { version } = req.body;
  const r = await safeSquareCall(profile, (token) => squarePost(token, `/v2/invoices/${req.params.invoiceId}/cancel`, {
    version: version || 0,
  }));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ invoice: r.body.invoice });
});

// DELETE invoice (draft only)
app.delete('/api/profiles/:id/invoices/:invoiceId', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const version = req.query.version || 0;
  const r = await safeSquareCall(profile, (token) => squareRequest('DELETE', token, `/v2/invoices/${req.params.invoiceId}?version=${version}`, null));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ success: true });
});

// UPDATE invoice
app.put('/api/profiles/:id/invoices/:invoiceId', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { version, title, description, dueDate } = req.body;
  const fields = [];
  const invoice = {};
  if (title !== undefined) { invoice.title = title; fields.push('title'); }
  if (description !== undefined) { invoice.description = description; fields.push('description'); }
  if (dueDate) { invoice.payment_requests = [{ request_type: 'BALANCE', due_date: dueDate }]; fields.push('payment_requests[0].due_date'); }
  const r = await safeSquareCall(profile, (token) => squareRequest('PUT', token, `/v2/invoices/${req.params.invoiceId}`, {
    invoice, fields_to_clear: [], idempotency_key: crypto.randomUUID(),
  }));
  if (r.tokenExpired) return res.status(401).json({ error: r.body.errors[0].detail, tokenExpired: true });
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
  res.json({ invoice: r.body.invoice });
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
  _currentProxy = profile.proxy_url || '';
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

// Create customer
app.post('/api/profiles/:id/customers', requireAuth, async (req, res) => {
  const profile = getProfileById(req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { givenName, familyName, emailAddress, phoneNumber, addressLine1, locality, state, postalCode, country } = req.body;
  if (!givenName && !familyName && !emailAddress) return res.status(400).json({ error: 'At least a name or email is required' });
  const body = { idempotency_key: crypto.randomUUID() };
  if (givenName) body.given_name = givenName;
  if (familyName) body.family_name = familyName;
  if (emailAddress) body.email_address = emailAddress;
  if (phoneNumber) body.phone_number = phoneNumber;
  if (addressLine1 || locality || state || postalCode) {
    body.address = {};
    if (addressLine1) body.address.address_line_1 = addressLine1;
    if (locality) body.address.locality = locality;
    if (state) body.address.administrative_district_level_1 = state;
    if (postalCode) body.address.postal_code = postalCode;
    body.address.country = country || 'US';
  }
  const accessToken = getDecryptedToken(profile);
  _currentProxy = profile.proxy_url || '';
  const r = await squarePost(accessToken, '/v2/customers', body);
  if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Failed to create customer' });
  const c = r.body.customer;
  res.json({ customer: { id: c.id, givenName: c.given_name, familyName: c.family_name, emailAddress: c.email_address, phoneNumber: c.phone_number } });
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
  _currentProxy = profile.proxy_url || '';
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
