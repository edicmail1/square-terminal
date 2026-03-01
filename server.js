require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');
const https = require('https');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const RENDER_API_TOKEN = process.env.RENDER_API_TOKEN;
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID;

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

// Ensure all profiles have transactions/maxAmount fields (migration)
store.profiles.forEach(p => {
  if (!p.transactions) p.transactions = [];
  if (p.maxAmount === undefined) p.maxAmount = null;
});

async function persistProfiles() {
  process.env.PROFILES_JSON = JSON.stringify(store);
  if (!RENDER_API_TOKEN || !RENDER_SERVICE_ID) return;

  const body = JSON.stringify([
    { key: 'PROFILES_JSON', value: JSON.stringify(store) },
    { key: 'RENDER_API_TOKEN', value: RENDER_API_TOKEN },
    { key: 'RENDER_SERVICE_ID', value: RENDER_SERVICE_ID },
    { key: 'SQUARE_ACCESS_TOKEN', value: process.env.SQUARE_ACCESS_TOKEN || '' },
    { key: 'SQUARE_APPLICATION_ID', value: process.env.SQUARE_APPLICATION_ID || '' },
    { key: 'SQUARE_LOCATION_ID', value: process.env.SQUARE_LOCATION_ID || '' },
  ]);

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
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve();
        else reject(new Error(`Render API ${res.statusCode}: ${data}`));
      });
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

function maskToken(token) {
  if (!token || token.length < 8) return '••••••••';
  return token.slice(0, 4) + '••••••••' + token.slice(-4);
}

function addTransaction(profileId, tx) {
  const profile = store.profiles.find(p => p.id === profileId);
  if (!profile) return;
  if (!profile.transactions) profile.transactions = [];
  profile.transactions.unshift(tx);
  if (profile.transactions.length > 50) profile.transactions = profile.transactions.slice(0, 50);
}

// ── Square API proxy helper ───────────────────────────────────────────────────
function squareRequest(method, accessToken, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'connect.squareup.com',
      path,
      method,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Square-Version': '2024-01-17',
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
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

const squareGet  = (token, path)       => squareRequest('GET',  token, path, null);
const squarePost = (token, path, body) => squareRequest('POST', token, path, body);

// GET merchant info for a profile
app.get('/api/profiles/:id/merchant', async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  if (!profile.accessToken) return res.status(400).json({ error: 'No access token' });

  try {
    const result = await squareGet(profile.accessToken, '/v2/merchants/me');
    if (result.status !== 200) {
      return res.status(result.status).json({ error: result.body?.errors?.[0]?.detail || 'Square API error' });
    }
    res.json(result.body.merchant);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Locations API ─────────────────────────────────────────────────────────────
app.get('/api/profiles/:id/locations', async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  try {
    const result = await squareGet(profile.accessToken, '/v2/locations');
    if (result.status !== 200) {
      return res.status(result.status).json({ error: result.body?.errors?.[0]?.detail || 'Square API error' });
    }

    const locations = result.body.locations || [];

    // Calculate totals from stored transaction history per location
    const totals = {};
    for (const tx of (profile.transactions || [])) {
      const locId = tx.locationId || profile.locationId;
      if (!totals[locId]) totals[locId] = { charged: 0, links: 0, count: 0 };
      if (tx.status !== 'FAILED') {
        totals[locId].count++;
        if (tx.type === 'charge') totals[locId].charged += tx.amount;
        if (tx.type === 'link') totals[locId].links += tx.amount;
      }
    }

    res.json({
      locations: locations.map(l => ({
        id: l.id,
        name: l.name,
        status: l.status,
        address: l.address ? [l.address.address_line_1, l.address.locality, l.address.administrative_district_level_1].filter(Boolean).join(', ') : null,
        currency: l.currency,
        country: l.country,
        timezone: l.timezone,
        type: l.type,
        isActive: l.id === profile.locationId,
        totals: totals[l.id] || { charged: 0, links: 0, count: 0 },
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/profiles/:id/locations', async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  const { name, address_line_1, city, state, postal_code, country, timezone, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Location name is required' });

  const locationBody = {
    location: {
      name,
      description: description || undefined,
      timezone: timezone || 'America/New_York',
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
    const result = await squarePost(profile.accessToken, '/v2/locations', locationBody);
    if (result.status !== 200) {
      return res.status(result.status).json({ error: result.body?.errors?.[0]?.detail || 'Square API error' });
    }
    res.json({ success: true, location: result.body.location });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Config ────────────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  const p = activeProfile();
  res.json({ applicationId: p.applicationId, locationId: p.locationId });
});

// ── Profiles ──────────────────────────────────────────────────────────────────
app.get('/api/profiles', (req, res) => {
  const list = store.profiles.map(p => ({
    id: p.id,
    name: p.name,
    applicationId: p.applicationId,
    locationId: p.locationId,
    accessTokenMasked: maskToken(p.accessToken),
    maxAmount: p.maxAmount,
    active: p.id === store.activeId,
    transactionCount: (p.transactions || []).length,
  }));
  res.json({ activeId: store.activeId, profiles: list });
});

app.get('/api/profiles/:id/transactions', (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Not found' });
  res.json({ transactions: profile.transactions || [] });
});

app.post('/api/profiles/:id/activate', async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  store.activeId = profile.id;
  squareClient = createClient(profile);
  try { await persistProfiles(); } catch {}
  res.json({ success: true, name: profile.name });
});

app.post('/api/profiles', async (req, res) => {
  const { id, name, accessToken, applicationId, locationId, maxAmount } = req.body;
  if (!name || !applicationId || !locationId) {
    return res.status(400).json({ error: 'name, applicationId and locationId are required' });
  }
  if (id) {
    const profile = store.profiles.find(p => p.id === id);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    profile.name = name;
    profile.applicationId = applicationId;
    profile.locationId = locationId;
    profile.maxAmount = maxAmount ? parseFloat(maxAmount) : null;
    if (accessToken) profile.accessToken = accessToken;
    if (store.activeId === id) squareClient = createClient(profile);
  } else {
    if (!accessToken) return res.status(400).json({ error: 'accessToken is required for new profile' });
    store.profiles.push({
      id: uuidv4(), name, accessToken, applicationId, locationId,
      maxAmount: maxAmount ? parseFloat(maxAmount) : null,
      transactions: [],
    });
  }
  try { await persistProfiles(); res.json({ success: true }); }
  catch (err) { res.json({ success: true, warning: err.message }); }
});

app.delete('/api/profiles/:id', async (req, res) => {
  if (store.profiles.length <= 1) return res.status(400).json({ error: 'Cannot delete the last profile' });
  store.profiles = store.profiles.filter(p => p.id !== req.params.id);
  if (store.activeId === req.params.id) {
    store.activeId = store.profiles[0].id;
    squareClient = createClient(store.profiles[0]);
  }
  try { await persistProfiles(); res.json({ success: true }); }
  catch (err) { res.json({ success: true, warning: err.message }); }
});

// ── Charge ────────────────────────────────────────────────────────────────────
app.post('/api/charge', async (req, res) => {
  const { sourceId, amount, currency, note, buyerEmail, verificationToken } = req.body;
  if (!sourceId || !amount) return res.status(400).json({ error: 'sourceId and amount are required' });

  const profile = activeProfile();

  // Enforce max amount limit
  if (profile.maxAmount && parseFloat(amount) > profile.maxAmount) {
    return res.status(400).json({
      success: false,
      errors: [{ detail: `Amount exceeds limit of $${profile.maxAmount.toFixed(2)} for this business` }]
    });
  }

  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const response = await squareClient.paymentsApi.createPayment({
      sourceId,
      idempotencyKey: uuidv4(),
      amountMoney: { amount: BigInt(amountCents), currency: currency || 'USD' },
      locationId: profile.locationId,
      note: note || '',
      buyerEmailAddress: buyerEmail || undefined,
      verificationToken: verificationToken || undefined,
    });
    const payment = response.result.payment;

    // Log transaction
    const tx = {
      id: payment.id,
      type: 'charge',
      amount: parseFloat(amount),
      currency: currency || 'USD',
      note: note || '',
      buyerEmail: buyerEmail || '',
      status: payment.status,
      receiptUrl: payment.receiptUrl || '',
      createdAt: new Date().toISOString(),
    };
    addTransaction(profile.id, tx);
    try { await persistProfiles(); } catch {}

    res.json({
      success: true,
      paymentId: payment.id,
      status: payment.status,
      amount: { amount: payment.amountMoney?.amount?.toString(), currency: payment.amountMoney?.currency },
      receiptUrl: payment.receiptUrl,
    });
  } catch (err) {
    // Log failed transaction
    const tx = {
      id: 'err-' + uuidv4().slice(0, 8),
      type: 'charge',
      amount: parseFloat(amount),
      currency: currency || 'USD',
      note: note || '',
      buyerEmail: buyerEmail || '',
      status: 'FAILED',
      error: (err.errors || [{ detail: err.message }]).map(e => e.detail).join('; '),
      createdAt: new Date().toISOString(),
    };
    addTransaction(profile.id, tx);
    try { await persistProfiles(); } catch {}
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

// ── Payment Link ──────────────────────────────────────────────────────────────
app.post('/api/payment-link', async (req, res) => {
  const { amount, currency, title, description } = req.body;
  if (!amount) return res.status(400).json({ error: 'amount is required' });

  const profile = activeProfile();

  if (profile.maxAmount && parseFloat(amount) > profile.maxAmount) {
    return res.status(400).json({
      success: false,
      errors: [{ detail: `Amount exceeds limit of $${profile.maxAmount.toFixed(2)} for this business` }]
    });
  }

  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const response = await squareClient.checkoutApi.createPaymentLink({
      idempotencyKey: uuidv4(),
      quickPay: {
        name: title || 'Payment',
        priceMoney: { amount: BigInt(amountCents), currency: currency || 'USD' },
        locationId: profile.locationId,
      },
      description: description || '',
    });
    const link = response.result.paymentLink;

    // Log
    addTransaction(profile.id, {
      id: link.id,
      type: 'link',
      amount: parseFloat(amount),
      currency: currency || 'USD',
      note: title || '',
      status: 'LINK_CREATED',
      url: link.url,
      createdAt: new Date().toISOString(),
    });
    try { await persistProfiles(); } catch {}

    res.json({ success: true, url: link.url, linkId: link.id });
  } catch (err) {
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Square Terminal running on port ${PORT}`));
