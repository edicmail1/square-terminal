require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ── Profiles storage ────────────────────────────────────────────────────────
const PROFILES_FILE = path.join(__dirname, 'profiles.json');

function loadProfiles() {
  if (fs.existsSync(PROFILES_FILE)) {
    try { return JSON.parse(fs.readFileSync(PROFILES_FILE, 'utf8')); } catch {}
  }
  // Seed from .env on first run
  const defaultProfile = {
    id: uuidv4(),
    name: 'Default',
    accessToken: process.env.SQUARE_ACCESS_TOKEN || '',
    applicationId: process.env.SQUARE_APPLICATION_ID || '',
    locationId: process.env.SQUARE_LOCATION_ID || '',
  };
  const data = { activeId: defaultProfile.id, profiles: [defaultProfile] };
  saveProfiles(data);
  return data;
}

function saveProfiles(data) {
  fs.writeFileSync(PROFILES_FILE, JSON.stringify(data, null, 2), 'utf8');
}

let store = loadProfiles();

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

// ── Helper ───────────────────────────────────────────────────────────────────
function maskToken(token) {
  if (!token || token.length < 8) return '••••••••';
  return token.slice(0, 4) + '••••••••' + token.slice(-4);
}

// ── Public config (for Square.js init) ───────────────────────────────────────
app.get('/api/config', (req, res) => {
  const p = activeProfile();
  res.json({ applicationId: p.applicationId, locationId: p.locationId });
});

// ── Profiles API ─────────────────────────────────────────────────────────────

// List all profiles (tokens masked)
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

// Activate a profile
app.post('/api/profiles/:id/activate', (req, res) => {
  const profile = store.profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  store.activeId = profile.id;
  squareClient = createClient(profile);
  saveProfiles(store);
  res.json({ success: true, name: profile.name });
});

// Add or update a profile
app.post('/api/profiles', (req, res) => {
  const { id, name, accessToken, applicationId, locationId } = req.body;
  if (!name || !applicationId || !locationId) {
    return res.status(400).json({ error: 'name, applicationId and locationId are required' });
  }

  if (id) {
    // Update existing
    const profile = store.profiles.find(p => p.id === id);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    profile.name = name;
    profile.applicationId = applicationId;
    profile.locationId = locationId;
    if (accessToken) profile.accessToken = accessToken;
    if (store.activeId === id) squareClient = createClient(profile);
  } else {
    // Create new
    if (!accessToken) return res.status(400).json({ error: 'accessToken is required for new profile' });
    const newProfile = { id: uuidv4(), name, accessToken, applicationId, locationId };
    store.profiles.push(newProfile);
  }

  saveProfiles(store);
  res.json({ success: true });
});

// Delete a profile
app.delete('/api/profiles/:id', (req, res) => {
  if (store.profiles.length <= 1) {
    return res.status(400).json({ error: 'Cannot delete the last profile' });
  }
  store.profiles = store.profiles.filter(p => p.id !== req.params.id);
  if (store.activeId === req.params.id) {
    store.activeId = store.profiles[0].id;
    squareClient = createClient(store.profiles[0]);
  }
  saveProfiles(store);
  res.json({ success: true });
});

// ── Charge card ───────────────────────────────────────────────────────────────
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
    const errors = err.errors || [{ detail: err.message }];
    res.status(400).json({ success: false, errors });
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
    const errors = err.errors || [{ detail: err.message }];
    res.status(400).json({ success: false, errors });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Square Terminal running on port ${PORT}`));
