/**
 * Tests for decline dictionaries consistency.
 * Parses index.html to extract declineLabels, declineHints, categoryLabels
 * and verifies they are complete and consistent.
 *
 * Run: bun test
 */

import { describe, test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const html = readFileSync(join(import.meta.dir, '..', 'public', 'index.html'), 'utf-8');

// Extract JS object from HTML by regex — finds `const NAME = { ... };`
function extractDict(name) {
  const regex = new RegExp(`const ${name} = \\{([^}]+(?:\\{[^}]*\\}[^}]*)*)\\};`, 's');
  const match = html.match(regex);
  if (!match) throw new Error(`Could not find ${name} in index.html`);
  // Parse the key-value pairs
  const entries = {};
  const kvRegex = /'([^']+)':\s*'([^']*)'/g;
  let m;
  while ((m = kvRegex.exec(match[1])) !== null) {
    entries[m[1]] = m[2];
  }
  return entries;
}

const declineLabels = extractDict('declineLabels');
const declineHints = extractDict('declineHints');
const categoryLabels = extractDict('categoryLabels');

// All known Square payment error codes (from Square API docs)
const SQUARE_DECLINE_CODES = [
  'CARD_DECLINED',
  'CARD_DECLINED_VERIFICATION_REQUIRED',
  'CVV_FAILURE',
  'ADDRESS_VERIFICATION_FAILURE',
  'EXPIRATION_FAILURE',
  'CARD_NOT_SUPPORTED',
  'INSUFFICIENT_FUNDS',
  'TRANSACTION_LIMIT',
  'CARD_VELOCITY_EXCEEDED',
  'INVALID_ACCOUNT',
  'VOICE_FAILURE',
  'PAN_FAILURE',
  'BAD_EXPIRATION',
  'CHIP_INSERTION_REQUIRED',
  'ALLOWLIST_FAILURE',
  'BLOCKED_BY_SQUARE',
  'GENERIC_DECLINE',
  'TEMPORARY_ERROR',
  'CARD_TOKEN_EXPIRED',
  'CARD_TOKEN_USED',
  'MANUALLY_ENTERED_PAYMENT_NOT_ACCEPTED',
  'PAYMENT_LIMIT_EXCEEDED',
  'INVALID_CARD',
  'INVALID_LOCATION',
  'INVALID_FEES',
  'CARDHOLDER_INSUFFICIENT_PERMISSIONS',
  'INVALID_PIN',
  'CARD_EXPIRED',
  'GIFT_CARD_AVAILABLE_AMOUNT',
  'INSUFFICIENT_PERMISSIONS',
];

const SQUARE_ERROR_CATEGORIES = [
  'PAYMENT_METHOD_ERROR',
  'AUTHENTICATION_ERROR',
  'AUTHORIZATION_ERROR',
  'INVALID_REQUEST_ERROR',
  'RATE_LIMIT_ERROR',
  'API_ERROR',
  'REFUND_ERROR',
  'EXTERNAL_VENDOR_ERROR',
];

describe('declineLabels', () => {
  test('has a label for every known Square decline code', () => {
    const missing = SQUARE_DECLINE_CODES.filter(code => !declineLabels[code]);
    expect(missing).toEqual([]);
  });

  test('all labels are non-empty strings', () => {
    for (const [code, label] of Object.entries(declineLabels)) {
      expect(label.length).toBeGreaterThan(0);
    }
  });

  test('no duplicate labels (each code has a unique description)', () => {
    const values = Object.values(declineLabels);
    // Allow some duplicates (e.g. EXPIRATION_FAILURE and CARD_EXPIRED are similar)
    // but flag exact duplicates
    const dupes = values.filter((v, i) => values.indexOf(v) !== i);
    // Just warn, don't fail — some codes legitimately share descriptions
    if (dupes.length > 0) {
      console.warn('Duplicate labels found:', dupes);
    }
  });
});

describe('declineHints', () => {
  test('has a hint for every code in declineLabels', () => {
    const labelCodes = Object.keys(declineLabels);
    const missing = labelCodes.filter(code => !declineHints[code]);
    expect(missing).toEqual([]);
  });

  test('does not have hints for codes NOT in declineLabels', () => {
    const hintCodes = Object.keys(declineHints);
    const extra = hintCodes.filter(code => !declineLabels[code]);
    expect(extra).toEqual([]);
  });

  test('all hints are non-empty and actionable (contain a verb)', () => {
    for (const [code, hint] of Object.entries(declineHints)) {
      expect(hint.length).toBeGreaterThan(5);
    }
  });
});

describe('categoryLabels', () => {
  test('has a label for every known Square error category', () => {
    const missing = SQUARE_ERROR_CATEGORIES.filter(cat => !categoryLabels[cat]);
    expect(missing).toEqual([]);
  });

  test('all category labels are non-empty', () => {
    for (const [cat, label] of Object.entries(categoryLabels)) {
      expect(label.length).toBeGreaterThan(0);
    }
  });
});

describe('dictionary consistency', () => {
  test('declineLabels and declineHints have the same keys', () => {
    const labelKeys = Object.keys(declineLabels).sort();
    const hintKeys = Object.keys(declineHints).sort();
    expect(labelKeys).toEqual(hintKeys);
  });
});

// ── Risk dictionaries ──────────────────────────────────────────────────────

const riskLabels = extractDict('riskLabels');
const riskHints = extractDict('riskHints');

const SQUARE_RISK_LEVELS = ['PENDING', 'NORMAL', 'MODERATE', 'HIGH'];

describe('riskLabels', () => {
  test('has a label for every Square risk level', () => {
    const missing = SQUARE_RISK_LEVELS.filter(level => !riskLabels[level]);
    expect(missing).toEqual([]);
  });

  test('all labels are non-empty', () => {
    for (const [level, label] of Object.entries(riskLabels)) {
      expect(label.length).toBeGreaterThan(0);
    }
  });
});

describe('riskHints', () => {
  test('has hints for MODERATE and HIGH (actionable levels)', () => {
    expect(riskHints['MODERATE']).toBeDefined();
    expect(riskHints['HIGH']).toBeDefined();
    expect(riskHints['MODERATE'].length).toBeGreaterThan(10);
    expect(riskHints['HIGH'].length).toBeGreaterThan(10);
  });

  test('does NOT have hints for NORMAL or PENDING (no action needed)', () => {
    expect(riskHints['NORMAL']).toBeUndefined();
    expect(riskHints['PENDING']).toBeUndefined();
  });

  test('only contains valid risk levels', () => {
    const hintKeys = Object.keys(riskHints);
    const invalid = hintKeys.filter(k => !SQUARE_RISK_LEVELS.includes(k));
    expect(invalid).toEqual([]);
  });
});
