import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatTokenCreateResult,
  resolveKeyIdentifiers,
} from '../commands/token-helpers';

// ── Response parsing ─────────────────────────────────────────────────────────
// Regression: the CLI used to read `res.token`, which never existed on the
// worker's response — the secret printed as "undefined" and was lost forever.

test('create output prints the access_token secret', () => {
  const lines = formatTokenCreateResult({
    id: 'tok_abc',
    name: 'my-token',
    access_token: 'SECRET_VALUE',
    rotation_type: 'static',
  });
  const output = lines.join('\n');
  assert.ok(output.includes('SECRET_VALUE'), 'must print the actual secret');
  assert.ok(!output.includes('undefined'), 'must never print undefined');
});

test('static tokens print no refresh token or expiry', () => {
  const output = formatTokenCreateResult({
    id: 'tok_abc',
    name: 't',
    access_token: 'S',
    rotation_type: 'static',
    refresh_token: null,
    access_token_expires_at: null,
  }).join('\n');
  assert.ok(!output.includes('Refresh token'));
  assert.ok(!output.includes('Expires:'));
});

test('rotating tokens print refresh token and expiry', () => {
  const output = formatTokenCreateResult({
    id: 'tok_abc',
    name: 't',
    access_token: 'ACCESS',
    refresh_token: 'REFRESH',
    rotation_type: 'daily',
    access_token_expires_at: '2026-07-13T00:00:00.000Z',
  }).join('\n');
  assert.ok(output.includes('ACCESS'));
  assert.ok(output.includes('REFRESH'));
  assert.ok(output.includes('Expires:'));
});

// ── Key resolution ───────────────────────────────────────────────────────────
// Regression: names were passed through verbatim as allowed_keys, but the
// proxy authorizes by key ID — such tokens could never authorize anything.

const VAULT = [
  { id: 'key_111', name: 'OPENAI_KEY' },
  { id: 'key_222', name: 'ELEVENLABS_KEY' },
  { id: 'key_333', name: 'DUPED' },
  { id: 'key_444', name: 'DUPED' },
];

test('key IDs pass through untouched', () => {
  assert.deepEqual(resolveKeyIdentifiers(['key_999'], VAULT), ['key_999']);
});

test('key names resolve to their IDs', () => {
  assert.deepEqual(
    resolveKeyIdentifiers(['ELEVENLABS_KEY', 'key_111'], VAULT),
    ['key_222', 'key_111']
  );
});

test('unknown key name throws instead of creating a dead token', () => {
  assert.throws(
    () => resolveKeyIdentifiers(['NOPE'], VAULT),
    /No key named "NOPE"/
  );
});

test('ambiguous key name throws', () => {
  assert.throws(
    () => resolveKeyIdentifiers(['DUPED'], VAULT),
    /Multiple keys named "DUPED"/
  );
});
