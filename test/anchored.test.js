// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const qc = require('..');
const { honest, provenByPinnedOperators, iso } = require('./honest');
const { makeChain, client } = require('./chain');

const ROOT = require('path').join(__dirname, '..');

test('an anchored consent, acknowledgement and revocation each verify', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const c = await qc.verify(h.records.consent, h.options.consent);
    assert.equal(c.status, 'valid', JSON.stringify(c.checks.filter((x) => !x.ok)));
    assert.equal(c.patientTrusted, true);
    assert.ok(c.anchoredAt);
    const a = await qc.verify(h.records.acknowledge, h.options.acknowledge);
    assert.equal(a.status, 'valid', JSON.stringify(a.checks.filter((x) => !x.ok)));
    const r = await qc.verify(h.records.revoke, h.options.revoke);
    assert.equal(r.status, 'valid', JSON.stringify(r.checks.filter((x) => !x.ok)));
  } finally {
    restore();
  }
});

test('verify requires the expected patient and rejects a substitute', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    await assert.rejects(qc.verify(h.records.consent, Object.assign({}, h.options.consent, { patientKeyId: undefined })), /expected patient is required/);
    const wrong = await qc.verify(h.records.consent, Object.assign({}, h.options.consent, { patientKeyId: qc.keyId(qc.generateKey()) }));
    assert.notEqual(wrong.status, 'valid');
    assert.ok(wrong.checks.some((x) => x.name === 'expected patient' && !x.ok));
  } finally {
    restore();
  }
});

test('an expected grantee that does not match is reported', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const wrong = await qc.verify(h.records.consent, Object.assign({}, h.options.consent, { granteeKeyId: qc.keyId(qc.generateKey()) }));
    assert.ok(wrong.checks.some((x) => x.name === 'expected grantee' && !x.ok));
    assert.notEqual(wrong.status, 'valid');
  } finally {
    restore();
  }
});

test('status reports an active consent and the correct scope', async () => {
  const h = await honest();
  const st = await qc.status(h.records.consent, Object.assign({ granteeKeyId: h.granteeKeyId, revocations: [], at: h.at }, h.ep));
  assert.equal(st.active, true);
  assert.deepEqual(st.purposes, ['diagnosis', 'treatment']);
  assert.deepEqual(st.categories, ['allergies', 'medications']);
  assert.equal(st.granteeKeyId, h.granteeKeyId);
  assert.equal(st.revokedAt, null);
});

test('once revoked and anchored, the consent is no longer in force', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const later = iso((h.chain.time + 1) * 1000);
    const res = await qc.verify(h.records.consent, Object.assign({}, h.options.consent, { revocations: [h.records.revoke], at: later }));
    assert.equal(res.status, 'invalid');
    assert.ok(res.revokedAt);
    assert.ok(res.checks.some((x) => x.name === 'in force' && !x.ok));
    const st = await qc.status(h.records.consent, Object.assign({ revocations: [h.records.revoke], at: later }, h.ep));
    assert.equal(st.active, false);
    assert.match(st.reasons.join(' '), /revoked/);
  } finally {
    restore();
  }
});

test('a revocation for another consent is ignored', async () => {
  const h = await honest();
  const strangerPatient = qc.generateKey();
  const other = qc.grant({ key: strangerPatient, grantee: qc.describeKey(qc.generateKey()), purposes: ['a'], categories: ['x'], validUntil: iso((h.chain.time + 10 * 86400) * 1000) });
  const strayRevoke = qc.revoke({ key: strangerPatient, consent: other });
  const st = await qc.status(h.records.consent, Object.assign({ revocations: [strayRevoke], at: h.at }, h.ep));
  assert.equal(st.active, true);
  assert.equal(st.revokedAt, null);
});

test('an anchor recorded on another network is refused', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const fake = makeChain(ROOT);
    fake.chainId = 'other';
    fake.genesis = 'other';
    const forged = { network: 'testnet', trustCustomEndpoints: true, clients: [client(fake, 'c'), client(fake, 'd')] };
    const res = await qc.verify(h.records.consent, Object.assign({}, h.options.consent, forged));
    assert.notEqual(res.status, 'valid');
  } finally {
    restore();
  }
});

test('a single endpoint is refused in strict mode and never valid', async () => {
  const h = await honest();
  await assert.rejects(qc.verify(h.records.consent, Object.assign({}, h.options.consent, { clients: [h.ep.clients[0]], trustSingleEndpoint: true })), /strict/);
  const single = await qc.verify(h.records.consent, Object.assign({ strict: false }, h.options.consent, { clients: [h.ep.clients[0]], trustSingleEndpoint: true }));
  assert.notEqual(single.status, 'valid');
});

test('an unanchored consent is confirmed but unproven, and valid only with requireAnchor false', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const open = await qc.verify(h.plain.consent, h.options.consent);
    assert.notEqual(open.status, 'valid');
    assert.ok(open.checks.some((x) => x.name === 'anchor' && !x.ok));
    const relaxed = await qc.verify(h.plain.consent, h.plainOptions.consent);
    assert.equal(relaxed.status, 'valid', JSON.stringify(relaxed.checks.filter((x) => !x.ok)));
  } finally {
    restore();
  }
});

test('an acknowledgement must bind the consent it answers', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const strangerPatient = qc.generateKey();
    const otherConsent = qc.grant({ key: strangerPatient, grantee: qc.describeKey(h.grantee), purposes: ['a'], categories: ['x'], validUntil: iso((h.chain.time + 10 * 86400) * 1000) });
    const res = await qc.verify(h.records.acknowledge, Object.assign({}, h.options.acknowledge, { consent: otherConsent }));
    assert.ok(res.checks.some((x) => x.name === 'consent binding' && !x.ok));
  } finally {
    restore();
  }
});

test('an anchored consent carries a deadline at or before its expiry', async () => {
  const h = await honest();
  const until = Math.floor(Date.parse(h.records.consent.statement.validUntil) / 1000);
  assert.ok(Number.isSafeInteger(h.records.consent.anchor.until));
  assert.ok(h.records.consent.anchor.until <= until);
});
