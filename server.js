require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const RENDER_API_TOKEN  = process.env.RENDER_API_TOKEN;
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID;
const APP_PASSWORD      = process.env.APP_PASSWORD || 'changeme';
const SESSION_SECRET    = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const BASE_URL          = process.env.BASE_URL || 'https://square-terminal.onrender.com';

// Square OAuth app credentials
const SQ_CLIENT_ID     = process.env.SQ_CLIENT_ID || '';
const SQ_CLIENT_SECRET = process.env.SQ_CLIENT_SECRET || '';
const SQ_OAUTH_SCOPES  = 'PAYMENTS_READ PAYMENTS_WRITE MERCHANT_PROFILE_READ ORDERS_READ ORDERS_WRITE';

// ── Sessions (in-memory) ──────────────────────────────────────────────────────
const sessions = new Map(); // token → { createdAt }

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { createdAt: Date.now() });
  return token;
}

function isValidSession(token) {
  if (!token || !sessions.has(token)) return false;
  const s = sessions.get(token);
  // Sessions expire after 12 hours
  if (Date.now() - s.createdAt > 12 * 60 * 60 * 1000) {
    sessions.delete(token);
    return false;
  }
  return true;
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.session || req.headers['x-session-token'];
  if (isValidSession(token)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Login ─────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password !== APP_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password' });
  }
  const token = createSession();
  res.cookie('session', token, { httpOnly: true, maxAge: 12 * 60 * 60 * 1000, sameSite: 'strict' });
  res.json({ success: true, token });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.session;
  if (token) sessions.delete(token);
  res.clearCookie('session');
  res.json({ success: true });
});

app.get('/api/auth-status', (req, res) => {
  const token = req.cookies?.session || req.headers['x-session-token'];
  res.json({ authenticated: isValidSession(token) });
});

// ── Square OAuth ──────────────────────────────────────────────────────────────
// Pending OAuth states: state → { profileName }
const oauthStates = new Map();

app.get('/auth/square', requireAuth, (req, res) => {
  if (!SQ_CLIENT_ID) return res.status(400).send('SQ_CLIENT_ID not configured');
  const state = crypto.randomBytes(16).toString('hex');
  const profileName = req.query.name || 'New Business';
  oauthStates.set(state, { profileName, createdAt: Date.now() });

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

  const stateData = oauthStates.get(state);
  if (!stateData) return res.redirect('/?oauth=error&msg=invalid_state');
  oauthStates.delete(state);

  // Exchange code for access token
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
          'Square-Version': '2024-01-17',
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

    const { access_token, merchant_id } = result.body;

    // Get merchant info & first location
    const [merchantRes, locRes] = await Promise.all([
      squareGet(access_token, '/v2/merchants/me'),
      squareGet(access_token, '/v2/locations'),
    ]);

    const merchant  = merchantRes.body?.merchant || {};
    const locations = locRes.body?.locations || [];
    const firstLoc  = locations.find(l => l.status === 'ACTIVE') || locations[0] || {};

    // Get Application ID from merchant (needed for Square.js)
    const appId = SQ_CLIENT_ID;

    const newProfile = {
      id: uuidv4(),
      name: merchant.business_name || stateData.profileName,
      accessToken: access_token,
      applicationId: appId,
      locationId: firstLoc.id || '',
      maxAmount: null,
      transactions: [],
    };

    store.profiles.push(newProfile);
    // Auto-activate if first profile
    if (store.profiles.length === 1) {
      store.activeId = newProfile.id;
      squareClient = createClient(newProfile);
    }

    await persistProfiles().catch(() => {});
    res.redirect('/?oauth=success&name=' + encodeURIComponent(newProfile.name));

  } catch (err) {
    res.redirect('/?oauth=error&msg=' + encodeURIComponent(err.message));
  }
});

// ── Profiles storage ──────────────────────────────────────────────────────────
function loadProfiles() {
  if (process.env.PROFILES_JSON) {
    try { return JSON.parse(process.env.PROFILES_JSON); } catch {}
  }
  const defaultProfile = {
    id: uuidv4(),
    name: 'Default',
    accessToken: process.env.SQUARE_ACCESS_TOKEN || '',
    applicationId: process.env.SQUARE_APPLICATION_ID || '',
    locationId: process.env.SQUARE_LOCATION_ID || '',
    maxAmount: null,
    transactions: [],
  };
  return { activeId: defaultProfile.id, profiles: [defaultProfile] };
}

let store = loadProfiles();
store.profiles.forEach(p => {
  if (!p.transactions) p.transactions = [];
  if (p.maxAmount === undefined) p.maxAmount = null;
});

async function persistProfiles() {
  process.env.PROFILES_JSON = JSON.stringify(store);
  if (!RENDER_API_TOKEN || !RENDER_SERVICE_ID) return;

  const envVars = [
    { key: 'PROFILES_JSON',        value: JSON.stringify(store) },
    { key: 'RENDER_API_TOKEN',     value: RENDER_API_TOKEN },
    { key: 'RENDER_SERVICE_ID',    value: RENDER_SERVICE_ID },
    { key: 'APP_PASSWORD',         value: APP_PASSWORD },
    { key: 'SESSION_SECRET',       value: SESSION_SECRET },
    { key: 'BASE_URL',             value: BASE_URL },
    { key: 'SQUARE_ACCESS_TOKEN',  value: process.env.SQUARE_ACCESS_TOKEN  || '' },
    { key: 'SQUARE_APPLICATION_ID',value: process.env.SQUARE_APPLICATION_ID|| '' },
    { key: 'SQUARE_LOCATION_ID',   value: process.env.SQUARE_LOCATION_ID   || '' },
    { key: 'SQ_CLIENT_ID',         value: SQ_CLIENT_ID },
    { key: 'SQ_CLIENT_SECRET',     value: SQ_CLIENT_SECRET },
  ];

  const body = JSON.stringify(envVars);
  await new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.render.com',
      path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${RENDER_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => (res.statusCode < 300 ? resolve() : reject(new Error(data))));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function activeProfile() {
  return store.profiles.find(p => p.id === store.activeId) || store.profiles[0];
}

function createClient(profile) {
  return new Client({ accessToken: profile.accessToken, environment: Environment.Production });
}

let squareClient = createClient(activeProfile());

function maskToken(t) {
  if (!t || t.length < 8) return '••••••••';
  return t.slice(0, 4) + '••••••••' + t.slice(-4);
}

function addTransaction(profileId, tx) {
  const p = store.profiles.find(x => x.id === profileId);
  if (!p) return;
  if (!p.transactions) p.transactions = [];
  p.transactions.unshift(tx);
  if (p.transactions.length > 50) p.transactions = p.transactions.slice(0, 50);
}

// ── Square API helpers ────────────────────────────────────────────────────────
function squareRequest(method, accessToken, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'connect.squareup.com',
      path, method,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Square-Version': '2024-01-17',
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

// ── Public endpoints (no auth needed) ────────────────────────────────────────
app.get('/api/config', (req, res) => {
  const p = activeProfile();
  res.json({ applicationId: p.applicationId, locationId: p.locationId });
});

app.get('/api/oauth-config', (req, res) => {
  res.json({ enabled: !!(SQ_CLIENT_ID && SQ_CLIENT_SECRET) });
});

// ── Protected API ─────────────────────────────────────────────────────────────
app.get('/api/profiles', requireAuth, (req, res) => {
  res.json({
    activeId: store.activeId,
    profiles: store.profiles.map(p => ({
      id: p.id, name: p.name,
      applicationId: p.applicationId, locationId: p.locationId,
      accessTokenMasked: maskToken(p.accessToken),
      maxAmount: p.maxAmount,
      active: p.id === store.activeId,
      transactionCount: (p.transactions || []).length,
    })),
  });
});

// GET bank accounts for a profile
app.get('/api/profiles/:id/bank-accounts', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  try {
    const r = await squareGet(profile.accessToken, '/v2/bank-accounts');
    if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
    const accounts = (r.body.bank_accounts || []).map(a => ({
      id: a.id,
      accountType: a.account_type,
      accountNumberSuffix: a.account_number_suffix,
      routingNumber: a.routing_number,
      bankName: a.bank_name,
      holderName: a.holder_name || a.account_holder_name || null,
      status: a.status,
      creditable: a.creditable,
      debitable: a.debitable,
      merchantId: a.merchant_id || null,
      locationId: a.location_id || null,
    }));
    res.json({ accounts });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/profiles/:id/merchant', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  try {
    const r = await squareGet(profile.accessToken, '/v2/merchants/me');
    if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
    res.json(r.body.merchant);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/profiles/:id/transactions', requireAuth, (req, res) => {
  const p = store.profiles.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  res.json({ transactions: p.transactions || [] });
});

app.post('/api/profiles/:id/activate', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  store.activeId = profile.id;
  squareClient = createClient(profile);
  try { await persistProfiles(); } catch {}
  res.json({ success: true, name: profile.name });
});

app.post('/api/profiles', requireAuth, async (req, res) => {
  const { id, name, accessToken, applicationId, locationId, maxAmount } = req.body;
  if (!name || !applicationId || !locationId) return res.status(400).json({ error: 'name, applicationId and locationId are required' });
  if (id) {
    const p = store.profiles.find(x => x.id === id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    p.name = name; p.applicationId = applicationId; p.locationId = locationId;
    p.maxAmount = maxAmount ? parseFloat(maxAmount) : null;
    if (accessToken) p.accessToken = accessToken;
    if (store.activeId === id) squareClient = createClient(p);
  } else {
    if (!accessToken) return res.status(400).json({ error: 'accessToken is required' });
    store.profiles.push({ id: uuidv4(), name, accessToken, applicationId, locationId, maxAmount: maxAmount ? parseFloat(maxAmount) : null, transactions: [] });
  }
  try { await persistProfiles(); res.json({ success: true }); }
  catch (e) { res.json({ success: true, warning: e.message }); }
});

app.delete('/api/profiles/:id', requireAuth, async (req, res) => {
  if (store.profiles.length <= 1) return res.status(400).json({ error: 'Cannot delete last profile' });
  store.profiles = store.profiles.filter(p => p.id !== req.params.id);
  if (store.activeId === req.params.id) {
    store.activeId = store.profiles[0].id;
    squareClient = createClient(store.profiles[0]);
  }
  try { await persistProfiles(); res.json({ success: true }); }
  catch (e) { res.json({ success: true, warning: e.message }); }
});

app.get('/api/profiles/:id/locations', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  try {
    const r = await squareGet(profile.accessToken, '/v2/locations');
    if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
    const totals = {};
    for (const tx of (profile.transactions || [])) {
      const locId = tx.locationId || profile.locationId;
      if (!totals[locId]) totals[locId] = { charged: 0, links: 0, count: 0 };
      if (tx.status !== 'FAILED') { totals[locId].count++; if (tx.type === 'charge') totals[locId].charged += tx.amount; if (tx.type === 'link') totals[locId].links += tx.amount; }
    }
    res.json({ locations: (r.body.locations || []).map(l => ({ id: l.id, name: l.name, business_name: l.business_name || '', status: l.status, description: l.description || '', phone_number: l.phone_number || '', business_email: l.business_email || '', website_url: l.website_url || '', instagram_username: l.instagram_username || '', twitter_username: l.twitter_username || '', facebook_url: l.facebook_url || '', address: l.address ? [l.address.address_line_1, l.address.locality, l.address.administrative_district_level_1].filter(Boolean).join(', ') : null, address_line_1: l.address?.address_line_1 || '', city: l.address?.locality || '', state: l.address?.administrative_district_level_1 || '', postal_code: l.address?.postal_code || '', currency: l.currency, country: l.country, timezone: l.timezone, type: l.type, created_at: l.created_at || null, isActive: l.id === profile.locationId, canProcessPayments: Array.isArray(l.capabilities) && l.capabilities.includes('CREDIT_CARD_PROCESSING'), capabilities: l.capabilities || [], totals: totals[l.id] || { charged: 0, links: 0, count: 0 } })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profiles/:id/locations/:locId', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
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

  try {
    const r = await squareRequest('PUT', profile.accessToken, `/v2/locations/${req.params.locId}`, locationBody);
    if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
    res.json({ success: true, location: r.body.location });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/profiles/:id/locations', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  const { name, address_line_1, city, state, postal_code, timezone, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  try {
    const r = await squarePost(profile.accessToken, '/v2/locations', { location: { name, description, timezone: timezone || 'America/New_York', ...(address_line_1 ? { address: { address_line_1, locality: city, administrative_district_level_1: state, postal_code, country: 'US' } } : {}) } });
    if (r.status !== 200) return res.status(r.status).json({ error: r.body?.errors?.[0]?.detail || 'Square error' });
    res.json({ success: true, location: r.body.location });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/profiles/:id/report', requireAuth, async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
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
  try {
    const locResult = await squareGet(profile.accessToken, '/v2/locations');
    if (locResult.status !== 200) return res.status(locResult.status).json({ error: locResult.body?.errors?.[0]?.detail || 'Failed to fetch locations' });
    const locations = locResult.body.locations || [];
    const reportByLocation = [];
    for (const loc of locations) {
      if (loc.status !== 'ACTIVE') { reportByLocation.push({ locationId: loc.id, locationName: loc.name, status: loc.status }); continue; }
      let allPayments = [], cursor = null;
      do {
        const params = new URLSearchParams({ location_id: loc.id, begin_time: beginTime.toISOString(), end_time: endTime.toISOString(), limit: '100', sort_order: 'DESC' });
        if (cursor) params.set('cursor', cursor);
        const r = await squareGet(profile.accessToken, `/v2/payments?${params}`);
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/charge', requireAuth, async (req, res) => {
  const { sourceId, amount, currency, note, buyerEmail, verificationToken } = req.body;
  if (!sourceId || !amount) return res.status(400).json({ error: 'sourceId and amount required' });
  const profile = activeProfile();
  if (profile.maxAmount && parseFloat(amount) > profile.maxAmount) return res.status(400).json({ success: false, errors: [{ detail: `Amount exceeds limit of $${profile.maxAmount.toFixed(2)}` }] });
  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const response = await squareClient.paymentsApi.createPayment({ sourceId, idempotencyKey: uuidv4(), amountMoney: { amount: BigInt(amountCents), currency: currency || 'USD' }, locationId: profile.locationId, note: note || '', buyerEmailAddress: buyerEmail || undefined, verificationToken: verificationToken || undefined });
    const payment = response.result.payment;
    addTransaction(profile.id, { id: payment.id, type: 'charge', amount: parseFloat(amount), currency: currency || 'USD', note: note || '', buyerEmail: buyerEmail || '', status: payment.status, receiptUrl: payment.receiptUrl || '', createdAt: new Date().toISOString() });
    try { await persistProfiles(); } catch {}
    res.json({ success: true, paymentId: payment.id, status: payment.status, amount: { amount: payment.amountMoney?.amount?.toString(), currency: payment.amountMoney?.currency }, receiptUrl: payment.receiptUrl });
  } catch (err) {
    addTransaction(profile.id, { id: 'err-' + uuidv4().slice(0,8), type: 'charge', amount: parseFloat(amount), currency: currency||'USD', note: note||'', buyerEmail: buyerEmail||'', status: 'FAILED', error: (err.errors||[{detail:err.message}]).map(e=>e.detail).join('; '), createdAt: new Date().toISOString() });
    try { await persistProfiles(); } catch {}
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

app.post('/api/payment-link', requireAuth, async (req, res) => {
  const { amount, currency, title, description, locationId } = req.body;
  if (!amount) return res.status(400).json({ error: 'amount required' });
  const profile = activeProfile();
  if (profile.maxAmount && parseFloat(amount) > profile.maxAmount) return res.status(400).json({ success: false, errors: [{ detail: `Amount exceeds limit of $${profile.maxAmount.toFixed(2)}` }] });
  const usedLocationId = locationId || profile.locationId;
  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const response = await squareClient.checkoutApi.createPaymentLink({ idempotencyKey: uuidv4(), quickPay: { name: title || 'Payment', priceMoney: { amount: BigInt(amountCents), currency: currency || 'USD' }, locationId: usedLocationId }, description: description || '' });
    const link = response.result.paymentLink;
    addTransaction(profile.id, { id: link.id, type: 'link', amount: parseFloat(amount), currency: currency||'USD', note: title||'', locationId: usedLocationId, status: 'LINK_CREATED', url: link.url, createdAt: new Date().toISOString() });
    try { await persistProfiles(); } catch {}
    res.json({ success: true, url: link.url, linkId: link.id });
  } catch (err) {
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Square Terminal running on port ${PORT}`));
