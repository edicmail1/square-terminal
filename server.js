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

// ── Profiles storage (Render env var PROFILES_JSON) ───────────────────────────
function loadProfiles() {
  if (process.env.PROFILES_JSON) {
    try { return JSON.parse(process.env.PROFILES_JSON); } catch {}
  }
  // Seed from individual env vars on first run
  const defaultProfile = {
    id: uuidv4(),
    name: 'Default',
    accessToken: process.env.SQUARE_ACCESS_TOKEN || '',
    applicationId: process.env.SQUARE_APPLICATION_ID || '',
    locationId: process.env.SQUARE_LOCATION_ID || '',
  };
  return { activeId: defaultProfile.id, profiles: [defaultProfile] };
}

let store = loadProfiles();

async function persistProfiles() {
  // Save in-process
  process.env.PROFILES_JSON = JSON.stringify(store);

  // Persist to Render env vars so it survives redeploys
  if (!RENDER_API_TOKEN || !RENDER_SERVICE_ID) return;

  const body = JSON.stringify([
    { key: 'PROFILES_JSON', value: JSON.stringify(store) }
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
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
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
  return new Client({
    accessToken: profile.accessToken,
    environment: Environment.Production,
  });
}

let squareClient = createClient(activeProfile());

function maskToken(token) {
  if (!token || token.length < 8) return '••••••••';
  return token.slice(0, 4) + '••••••••' + token.slice(-4);
}

// ── Public config ─────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  const p = activeProfile();
  res.json({ applicationId: p.applicationId, locationId: p.locationId });
});

// ── Profiles API ──────────────────────────────────────────────────────────────
app.get('/api/profiles', (req, res) => {
  const list = store.profiles.map(p => ({
    id: p.id,
    name: p.name,
    applicationId: p.applicationId,
    locationId: p.locationId,
    accessTokenMasked: maskToken(p.accessToken),
    active: p.id === store.activeId,
  }));
  res.json({ activeId: store.activeId, profiles: list });
});

app.post('/api/profiles/:id/activate', async (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  store.activeId = profile.id;
  squareClient = createClient(profile);
  try {
    await persistProfiles();
    res.json({ success: true, name: profile.name });
  } catch (err) {
    res.json({ success: true, name: profile.name, warning: 'Saved in memory but failed to persist: ' + err.message });
  }
});

app.post('/api/profiles', async (req, res) => {
  const { id, name, accessToken, applicationId, locationId } = req.body;
  if (!name || !applicationId || !locationId) {
    return res.status(400).json({ error: 'name, applicationId and locationId are required' });
  }

  if (id) {
    const profile = store.profiles.find(p => p.id === id);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    profile.name = name;
    profile.applicationId = applicationId;
    profile.locationId = locationId;
    if (accessToken) profile.accessToken = accessToken;
    if (store.activeId === id) squareClient = createClient(profile);
  } else {
    if (!accessToken) return res.status(400).json({ error: 'accessToken is required for new profile' });
    const newProfile = { id: uuidv4(), name, accessToken, applicationId, locationId };
    store.profiles.push(newProfile);
  }

  try {
    await persistProfiles();
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true, warning: 'Saved in memory but failed to persist: ' + err.message });
  }
});

app.delete('/api/profiles/:id', async (req, res) => {
  if (store.profiles.length <= 1) {
    return res.status(400).json({ error: 'Cannot delete the last profile' });
  }
  store.profiles = store.profiles.filter(p => p.id !== req.params.id);
  if (store.activeId === req.params.id) {
    store.activeId = store.profiles[0].id;
    squareClient = createClient(store.profiles[0]);
  }
  try {
    await persistProfiles();
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true, warning: 'Deleted in memory but failed to persist: ' + err.message });
  }
});

// ── Charge ────────────────────────────────────────────────────────────────────
app.post('/api/charge', async (req, res) => {
  const { sourceId, amount, currency, note, buyerEmail, verificationToken } = req.body;
  if (!sourceId || !amount) return res.status(400).json({ error: 'sourceId and amount are required' });

  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const response = await squareClient.paymentsApi.createPayment({
      sourceId,
      idempotencyKey: uuidv4(),
      amountMoney: { amount: BigInt(amountCents), currency: currency || 'USD' },
      locationId: activeProfile().locationId,
      note: note || '',
      buyerEmailAddress: buyerEmail || undefined,
      verificationToken: verificationToken || undefined,
    });
    const payment = response.result.payment;
    res.json({
      success: true,
      paymentId: payment.id,
      status: payment.status,
      amount: {
        amount: payment.amountMoney?.amount?.toString(),
        currency: payment.amountMoney?.currency,
      },
      receiptUrl: payment.receiptUrl,
    });
  } catch (err) {
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

// ── Payment Link ──────────────────────────────────────────────────────────────
app.post('/api/payment-link', async (req, res) => {
  const { amount, currency, title, description } = req.body;
  if (!amount) return res.status(400).json({ error: 'amount is required' });

  try {
    const amountCents = Math.round(parseFloat(amount) * 100);
    const response = await squareClient.checkoutApi.createPaymentLink({
      idempotencyKey: uuidv4(),
      quickPay: {
        name: title || 'Payment',
        priceMoney: { amount: BigInt(amountCents), currency: currency || 'USD' },
        locationId: activeProfile().locationId,
      },
      description: description || '',
    });
    const link = response.result.paymentLink;
    res.json({ success: true, url: link.url, linkId: link.id });
  } catch (err) {
    res.status(400).json({ success: false, errors: err.errors || [{ detail: err.message }] });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Square Terminal running on port ${PORT}`));
