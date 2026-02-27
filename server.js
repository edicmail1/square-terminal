require('dotenv').config();
const express = require('express');
const { Client, Environment } = require('square');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const client = new Client({
  accessToken: process.env.SQUARE_ACCESS_TOKEN,
  environment: Environment.Production,
});

// Charge card manually (manual entry)
app.post('/api/charge', async (req, res) => {
  const { sourceId, amount, currency, note, customerName } = req.body;

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
      locationId: process.env.SQUARE_LOCATION_ID,
      note: note || '',
      buyerEmailAddress: undefined,
    });

    const payment = response.result.payment;
    res.json({
      success: true,
      paymentId: payment.id,
      status: payment.status,
      amount: payment.amountMoney,
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
        locationId: process.env.SQUARE_LOCATION_ID,
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
    applicationId: process.env.SQUARE_APPLICATION_ID,
    locationId: process.env.SQUARE_LOCATION_ID,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Square Terminal running on port ${PORT}`);
});
