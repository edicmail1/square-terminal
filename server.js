require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Mutable config — can be updated at runtime
let config = {
  accessToken: process.env.SQUARE_ACCESS_TOKEN,
  applicationId: process.env.SQUARE_APPLICATION_ID,
  locationId: process.env.SQUARE_LOCATION_ID,
};

function createClient() {
  return new Client({
    accessToken: config.accessToken,
    environment: Environment.Production,
  });
}

let client = createClient();

// Charge card manually (manual entry)
app.post('/api/charge', async (req, res) => {
  const { sourceId, amount, currency, note, customerName, buyerEmail, verificationToken } = req.body;

  if (!sourceId || !amount) {
    return res.status(400).json({ error: 'sourceId and amount are required' });
  }

  try {
    const amountCents = Math.round(parseFloat(amount) * 100);

    const response = await client.paymentsApi.createPayment({
      sourceId,
      idempotencyKey: uuidv4(),
      amountMoney: {
        amount: BigInt(amountCents),
        currency: currency || 'USD',
      },
      locationId: config.locationId,
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

// Create Payment Link
app.post('/api/payment-link', async (req, res) => {
  const { amount, currency, title, description } = req.body;

  if (!amount) {
    return res.status(400).json({ error: 'amount is required' });
  }

  try {
    const amountCents = Math.round(parseFloat(amount) * 100);

    const response = await client.checkoutApi.createPaymentLink({
      idempotencyKey: uuidv4(),
      quickPay: {
        name: title || 'Payment',
        priceMoney: {
          amount: BigInt(amountCents),
          currency: currency || 'USD',
        },
        locationId: config.locationId,
      },
      description: description || '',
    });

    const link = response.result.paymentLink;
    res.json({
      success: true,
      url: link.url,
      linkId: link.id,
    });
  } catch (err) {
    const errors = err.errors || [{ detail: err.message }];
    res.status(400).json({ success: false, errors });
  }
});

// Expose public config for frontend
app.get('/api/config', (req, res) => {
  res.json({
    applicationId: config.applicationId,
    locationId: config.locationId,
  });
});

// Get current settings (masked token)
app.get('/api/settings', (req, res) => {
  const token = config.accessToken || '';
  const masked = token.length > 8
    ? token.slice(0, 4) + '••••••••' + token.slice(-4)
    : '••••••••';
  res.json({
    accessTokenMasked: masked,
    applicationId: config.applicationId || '',
    locationId: config.locationId || '',
  });
});

// Update settings — saves to .env and reinitializes client
app.post('/api/settings', (req, res) => {
  const { accessToken, applicationId, locationId } = req.body;

  if (accessToken) config.accessToken = accessToken.trim();
  if (applicationId) config.applicationId = applicationId.trim();
  if (locationId) config.locationId = locationId.trim();

  // Reinitialize Square client with new credentials
  client = createClient();

  // Persist to .env file
  const envPath = path.join(__dirname, '.env');
  const envContent = [
    `SQUARE_ACCESS_TOKEN=${config.accessToken}`,
    `SQUARE_APPLICATION_ID=${config.applicationId}`,
    `SQUARE_LOCATION_ID=${config.locationId}`,
    `SQUARE_ENVIRONMENT=production`,
    `PORT=${process.env.PORT || 3000}`,
  ].join('\n') + '\n';

  try {
    fs.writeFileSync(envPath, envContent, 'utf8');
    res.json({ success: true, message: 'Settings saved and applied.' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to save .env: ' + err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Square Terminal running on port ${PORT}`);
});
